"""Bounded project AST triage. Application source is parsed, never imported or run.

The supported subset is deliberately explicit: local functions/imports, literal SQL
with positional/named bindings, Django model managers, and SQLAlchemy model queries.
Every emitted signal is a candidate; absence of a signal is not a security proof.
"""
import ast
from dataclasses import dataclass, field, replace
import re


AUTH = "Authorization and tenant isolation"
SQL = "SQL and data query injection"
INPUT = "Command, code, and template injection"
OWNER = {"owner_id": "id", "user_id": "id", "tenant_id": "tenant_id", "account_id": "account_id"}
SOURCE_ATTRS = {"args", "GET", "POST", "json", "query_params", "path_params", "form", "data", "body"}
MAX_DEPTH, MAX_CONTEXTS, MAX_STATES, MAX_NODES = 6, 160, 16, 24000
MAX_SOURCE_BYTES, MAX_TOTAL_BYTES = 1_000_000, 8_000_000
MAX_FILES, MAX_AST_NODES = 1000, 120000


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + "." + node.attr
    return ""


@dataclass(frozen=True)
class Value:
    origins: frozenset = frozenset()
    principal: str = ""
    rows: frozenset = frozenset()
    member: str = ""
    symbol: str = ""
    literal: object = None
    items: tuple = ()
    mapping: tuple = ()
    orm: tuple = ()
    trace: tuple = ()


def combine(values):
    values = list(values)
    return Value(origins=frozenset().union(*(v.origins for v in values)),
                 rows=frozenset().union(*(v.rows for v in values)),
                 trace=tuple(dict.fromkeys(t for v in values for t in v.trace)))


@dataclass
class State:
    env: dict = field(default_factory=dict)
    guards: dict = field(default_factory=dict)
    admin: bool = False
    non_admin: bool = False
    decorator_policy_unknown: bool = False

    def copy(self):
        return State(dict(self.env), dict(self.guards), self.admin, self.non_admin, self.decorator_policy_unknown)


class Project:
    def __init__(self, sources):
        self.sources = sources
        self.modules, self.functions, self.globals, self.models = {}, {}, {}, {}
        self.rows, self.signals, self.gaps, self.tasks = {}, [], [], []
        self.seen, self.stack, self.summary_cache = set(), [], {}
        self.controls, self.analysis_incomplete = {}, False
        self.expanded_functions = set()
        self.contexts = self.nodes = 0
        total_bytes = file_count = ast_nodes = 0
        for path, source in sorted(sources.items()):
            if not path.endswith(".py"):
                continue
            file_count += 1
            if file_count > MAX_FILES:
                self.issue(self.gaps, path, None, 'python-project-resource-gap', 'Python file budget reached', 'Project source-count budget excludes this file; no project suppression is inferred.')
                continue
            size = len(source.encode('utf-8'))
            total_bytes += size
            if size > MAX_SOURCE_BYTES or total_bytes > MAX_TOTAL_BYTES:
                self.analysis_incomplete = True
                self.issue(self.gaps, path, None, "python-project-resource-gap", "Python source budget reached", "Source exceeds the bounded per-file or project byte budget; no project suppression is inferred.")
                continue
            module = path.replace("\\", "/").removesuffix(".py").replace("/", ".")
            if module.endswith(".__init__"):
                module = module[:-9]
            try:
                tree = ast.parse(source, filename=path)
            except (SyntaxError, ValueError, RecursionError) as error:
                self.analysis_incomplete = True
                self.issue(self.gaps, path, None, "python-project-parse-gap", "Python source could not be parsed", str(error))
                continue
            over_budget = False
            for _ in ast.walk(tree):
                ast_nodes += 1
                if ast_nodes > MAX_AST_NODES:
                    over_budget = True
                    break
            if over_budget:
                self.issue(self.gaps, path, None, 'python-project-resource-gap', 'Python AST node budget reached', 'Aggregate AST node budget excludes this module; no project suppression is inferred.')
                continue
            self.modules[module] = (path, tree)
        for module, (path, tree) in self.modules.items():
            env = {}
            for node in tree.body:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        env[alias.asname or alias.name.split(".")[0]] = Value(symbol=alias.name if alias.asname else alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    package = module.split(".")[:-1]
                    if path.replace("\\", "/").endswith("/__init__.py"):
                        package = module.split(".")
                    prefix = ".".join(package[:len(package) - node.level + 1]) if node.level else ""
                    target = ".".join(p for p in (prefix, node.module or "") if p)
                    for alias in node.names:
                        if alias.name == "*":
                            self.issue(self.gaps, path, node, "python-project-import-gap", "Wildcard import is unresolved", "Explicit bindings are required for project call resolution.")
                        else:
                            env[alias.asname or alias.name] = Value(symbol=target + "." + alias.name)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    key = module + "." + node.name
                    env[node.name] = Value(symbol=key)
                    self.functions[key] = (module, path, node)
                elif isinstance(node, ast.ClassDef):
                    env[node.name] = Value(symbol=module + "." + node.name)
            self.globals[module] = env
        # Resolve model declarations only from explicit framework bases; method names alone are insufficient.
        for module, (path, tree) in self.modules.items():
            env = self.globals[module]
            bases = set()
            for node in tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    target = self.symbol(node.value.func, State(env))
                    if target in {"sqlalchemy.orm.declarative_base", "sqlalchemy.ext.declarative.declarative_base"}:
                        bases.update(t.id for t in node.targets if isinstance(t, ast.Name))
                    if target == "flask_sqlalchemy.SQLAlchemy":
                        bases.update(t.id + ".Model" for t in node.targets if isinstance(t, ast.Name))
                if isinstance(node, ast.ClassDef):
                    names = {self.symbol(b, State(env)) for b in node.bases}
                    raw = {dotted(b) for b in node.bases}
                    kind = "django" if "django.db.models.Model" in names else "sqlalchemy" if (names & {"sqlalchemy.orm.DeclarativeBase"} or raw & bases) else ""
                    if kind:
                        fields = {dotted(t).split(".")[-1] for s in node.body if isinstance(s, (ast.Assign, ast.AnnAssign)) for t in (s.targets if isinstance(s, ast.Assign) else [s.target])}
                        self.models[module + "." + node.name] = (kind, fields & OWNER.keys())
                    if 'sqlalchemy.orm.DeclarativeBase' in names or raw & bases:
                        bases.add(node.name)

    def loc(self, path, node):
        return (path, getattr(node, "lineno", None), getattr(node, "col_offset", -1) + 1 if node is not None else None)

    def issue(self, collection, path, node, rule, title, detail, value=None, **extra):
        if collection is self.gaps:
            self.analysis_incomplete = True
        key = (id(collection), path, getattr(node, "lineno", None), getattr(node, "col_offset", None), rule, detail)
        if key in self.seen:
            return
        self.seen.add(key)
        trace = [{"path": p, "line": l, "column": c} for p, l, c in (value.trace if value else ())]
        item = dict(path=path, line=getattr(node, "lineno", None), column=getattr(node, "col_offset", -1) + 1 if node else None,
                    rule=rule, title=title, family='Source analysis coverage' if collection is self.gaps else AUTH if "authorization" in rule or "boundary" in rule or 'object-policy' in rule else SQL if "sql" in rule else INPUT,
                    method="Bounded Python project AST flow", detail=detail, trace=trace,
                    evidence={"operation": dict(zip(("path", "line", "column"), self.loc(path, node)))}, **extra)
        if collection is self.signals:
            item["proof_state"] = "candidate"
        collection.append(item)

    def symbol(self, node, state):
        if isinstance(node, ast.Name):
            return state.env.get(node.id, Value(symbol=node.id)).symbol
        if isinstance(node, ast.Attribute):
            base = self.symbol(node.value, state)
            return base + "." + node.attr if base else ""
        return ""

    def record(self, path, node, value, fields=(), scoped=(), kind="SQL", schema_verified=False):
        key = self.loc(path, node) + (tuple(self.stack),)
        self.rows[key] = dict(path=path, node=node, fields=set(fields) or set(scoped), scoped=set(scoped), kind=kind, input=value, schema_verified=schema_verified)
        return replace(value, rows=frozenset({key}), member="", principal="", trace=value.trace + (self.loc(path, node),))

    def boundary(self, path, node, value, state, action):
        if state.non_admin and action in {'delete', 'update', 'mutation', 'save', 'add'}:
            self.issue(self.signals, path, node, 'python-project-admin-authorization', 'Review an admin-excluding guard before a write', 'A trusted admin test excludes admins while a non-admin path reaches a write. Establish the actual privileged-operation policy; the observed inversion is a candidate, not proof this operation requires admin.', value,
                       boundary_kind=action, admin_policy_verified=False, non_admin_path_observed=True)
        for key in value.rows:
            row = self.rows.get(key)
            if not row:
                continue
            fields = row["fields"]
            checked = row["scoped"] | set(state.guards.get(key, ()))
            # If both user and tenant are declared, both must match their exact trusted identities.
            safe = bool(fields) and fields <= checked
            self.observe_control(row['path'], row['node'], 'python-object-authorization', safe)
            if safe:
                continue
            if not fields and row['schema_verified'] or state.decorator_policy_unknown:
                self.issue(self.tasks, path, node, 'python-project-object-policy', 'Verify object access policy and supplied decorators',
                           'A request-selected object reaches this boundary. Its declared schema has no ownership fields, or a supplied decorator has unresolved policy. Inspect publication, roles and decorator effects before judging authorization.', value)
                continue
            detail = f"Request-selected {row['kind']} object reaches {action}; "
            detail += "declared ownership/tenant fields lack a dominating exact identity check." if fields else "ownership, tenant and publication policy are unknown."
            enriched = replace(value, trace=value.trace + (self.loc(path, node),))
            self.issue(self.signals, path, node, "python-project-object-authorization", "Review object authorization at " + action, detail, enriched,
                       ownership_schema_observed=row['schema_verified'], operation=action,
                       missing_fields=sorted(fields - checked), boundary_kind=action,
                       admin_guard_observed=state.admin,
                       evidence_lines={"input": min((x[1] for x in row['input'].origins), default=None), "lookup": row['node'].lineno, "boundary": node.lineno})
            if not fields:
                self.issue(self.tasks, path, node, "python-project-authorization-policy", "Establish object access policy", "Confirm whether this object is public, user-owned, tenant-owned, or admin-only before judging exploitability.", enriched)

    def sql(self, path, node, query, parameters, state):
        raw = query.literal
        if not isinstance(raw, str):
            if query.origins:
                self.observe_control(path, node, 'python-sql-composition', False)
                self.issue(self.signals, path, node, "python-project-sql-injection", "Request data reaches a possible SQL query boundary", "Query text carries request origin. Verify the receiver is a database interpreter, effective controls and query structure; method spelling alone is not database proof.", replace(query, trace=query.trace + (self.loc(path, node),)))
            elif query.symbol == '@fixed-sql-shape':
                self.observe_control(path, node, 'python-sql-composition', True)
            return Value()
        self.observe_control(path, node, 'python-sql-composition', not query.origins)
        if not re.match(r"\s*(SELECT|UPDATE|DELETE)\b", raw, re.I):
            return Value()
        # Parse only flat conjunctions. Joins are accepted, but each alias has its own bounds.
        operation = re.match(r"\s*(\w+)", raw)[1].upper()
        table_matches = list(re.finditer(r"\b(?:FROM|JOIN|UPDATE)\s+([\w]+)(?:\s+(?:AS\s+)?(?!WHERE\b|JOIN\b|ON\b|SET\b|LEFT\b|RIGHT\b|INNER\b)([\w]+))?", raw, re.I))
        tables = {m[2] or m[1]: m[1] for m in table_matches}
        where = re.search(r"\bWHERE\s+(.+?)(?:\b(?:ORDER\s+BY|LIMIT|RETURNING)\b|$)", raw, re.I | re.S)
        if not where:
            return Value()
        text = where[1].strip().rstrip(";")
        predicate_text = re.sub(r"%\([A-Za-z_]\w*\)s", "?", text)
        simple = not re.search(r"\b(?:OR|NOT|EXISTS|SELECT)\b|[()'\"]|--|/\*", predicate_text, re.I)
        if not simple:
            self.issue(self.gaps, path, node, 'python-project-sql-gap', 'Complex SQL predicate requires review', 'Only flat equality conjunctions establish ownership bounds; subqueries, disjunctions, expressions and comments remain open.')
        positional = iter(parameters.items)
        # Number positional placeholders across the whole SQL string, including UPDATE SET values.
        bindings = {}
        for match in re.finditer(r"\?|%s|(?<!:):([A-Za-z_]\w*)|%\(([A-Za-z_]\w*)\)s", raw):
            name = match[1] or match[2]
            bindings[match.start()] = dict(parameters.mapping).get(name, Value()) if name else next(positional, Value())
        requested, scoped = {}, {}
        for match in re.finditer(r"(?:(\w+)\.)?(\w+)\s*=\s*(\?|%s|(?<!:):[A-Za-z_]\w*|%\([A-Za-z_]\w*\)s)(?=\s*(?:AND\b|;|$))", text, re.I):
            alias, name = match[1], match[2].lower()
            if not alias and len(tables) == 1:
                alias = next(iter(tables))
            if alias not in tables:
                continue
            offset = where.start(1) + match.start(3)
            value = bindings.get(offset, Value())
            if name in {"id", "pk"} and value.origins:
                requested[alias] = value
            if simple and name in OWNER and value.principal == OWNER[name] and not value.origins:
                scoped.setdefault(alias, set()).add(name)
        # Schema declarations are gathered independently of execution order.
        schema = self.schemas
        result = Value()
        for alias, identity in requested.items():
            fields = schema.get(tables[alias].lower(), set())
            row = self.record(path, node, identity, fields, scoped.get(alias, ()), "SQL", tables[alias].lower() in schema)
            result = combine([result, row])
        if operation != "SELECT":
            self.boundary(path, node, result, state, operation.lower())
            return Value()
        return result

    def orm_read(self, path, node, receiver, name, args, keywords, state):
        # orm=(framework, model, predicates); only explicit model/session roots create it.
        if not receiver.orm:
            return None
        kind, model, predicates = receiver.orm
        predicates = list(predicates)
        if name in {"filter_by", "filter", "get", "get_or_404", "exclude"}:
            if kind == "django" and name in {"filter", "get"} or kind in {"sqlalchemy", 'unverified-orm'} and name == "filter_by":
                predicates.extend((k, v) for k, v in keywords.items())
            elif kind in {"sqlalchemy", 'unverified-orm'} and name == "filter":
                for expr, value in args:
                    if isinstance(expr, ast.Compare) and len(expr.ops) == 1 and isinstance(expr.ops[0], ast.Eq):
                        left = self.expr(expr.left, state, path)
                        right = self.expr(expr.comparators[0], state, path)
                        if left.symbol.startswith(model + "."):
                            predicates.append((left.symbol.removeprefix(model + "."), right))
            elif kind in {"sqlalchemy", "unverified-orm"} and name in {"get", "get_or_404"} and args:
                predicates.append(("id", args[0][1]))
            else:
                self.issue(self.gaps, path, node, "python-project-orm-gap", "Unsupported ORM predicate", "Exclusion, positional Django lookups and complex ORM predicates require manual review.")
        if name in {"filter", "filter_by", "exclude", "all", "order_by"}:
            return replace(receiver, orm=(kind, model, tuple(predicates)))
        if name in {"get", "get_or_404", "first", "first_or_404", "one", "one_or_none", "update", "delete"}:
            identities = [v for k, v in predicates if k in {"id", "pk", "id__exact", "pk__exact"} and v.origins]
            if not identities:
                return Value(orm=(kind, model, tuple(predicates)))
            fields = self.models[model][1]
            bounds = {k.removesuffix("__exact") for k, v in predicates if k.removesuffix("__exact") in OWNER and v.principal == OWNER[k.removesuffix("__exact")] and not v.origins}
            row = self.record(path, node, combine(identities), fields, bounds, kind, bool(fields) and kind != 'unverified-orm')
            if name in {"update", "delete"}:
                self.boundary(path, node, row, state, name)
                return Value()
            return row
        self.issue(self.gaps, path, node, "python-project-orm-gap", "Unsupported ORM operation", "This model operation is outside the supported manager/query subset.")
        return Value()

    def expr(self, node, state, path):
        if node is None:
            return Value()
        self.nodes += 1
        if self.nodes > MAX_NODES:
            self.issue(self.gaps, path, node, "python-project-complexity-gap", "Expression budget reached", "Project expression analysis stopped at its explicit node budget.")
            return Value()
        if isinstance(node, ast.Name):
            value = state.env.get(node.id, Value(symbol=node.id))
            return replace(value, principal='object') if value.symbol in {'flask_login.current_user', 'current_user'} else value
        if isinstance(node, ast.Constant):
            return Value(literal=node.value)
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value, state, path)
            symbol = base.symbol + "." + node.attr if base.symbol else ""
            if base.symbol in {"request", "flask.request", "starlette.requests.Request", "fastapi.Request"} and node.attr in SOURCE_ATTRS:
                location = self.loc(path, node)
                return Value(origins=frozenset({location}), trace=(location,))
            if symbol in {"request.user", "flask.request.user", "flask_login.current_user", "current_user"}:
                return Value(principal="object", symbol=symbol)
            if symbol == 'flask.g.user':
                return Value(principal='object', symbol=symbol)
            if base.principal == "object" and node.attr in {"id", "pk", "tenant_id", "account_id", "is_admin", "is_superuser"}:
                return Value(principal="id" if node.attr == "pk" else node.attr, symbol=symbol)
            if symbol in {"current_user.id", "current_user.pk", "current_user.tenant_id", "current_user.account_id", "current_user.is_admin", "current_user.is_superuser"}:
                return Value(principal="id" if node.attr == "pk" else node.attr, symbol=symbol)
            if base.rows and node.attr in OWNER:
                for key in base.rows:
                    self.rows[key]['fields'].add(node.attr)
                return replace(base, member=node.attr, principal="", symbol="")
            if base.symbol in self.models and node.attr in {"objects", "query"}:
                kind = self.models[base.symbol][0]
                if node.attr == ("objects" if kind == "django" else "query"):
                    return Value(orm=(kind, base.symbol, ()))
            if base.symbol == '@flask-db' and node.attr == 'session':
                return Value(symbol='@session')
            if node.attr == 'session' and base.symbol and not base.origins:
                self.issue(self.tasks, path, node, 'python-project-session-provenance', 'Verify database session receiver', 'A session-shaped receiver from an external binding is summarized provisionally; supplied model/library definitions and policy are unavailable.')
                return Value(symbol='@potential-session')
            if node.attr == 'query' and isinstance(node.value, ast.Name) and base.symbol and not base.origins:
                self.models.setdefault(base.symbol, ('unverified-orm', set()))
                self.issue(self.tasks, path, node, 'python-project-orm-provenance', 'Verify ORM query receiver', 'This query/filter shape has no supplied model declaration. Candidates and observed bounds remain conditional on library identity and access policy.')
                return Value(orm=('unverified-orm', base.symbol, ()))
            return replace(base, symbol=symbol, principal="", member="")
        if isinstance(node, ast.Subscript):
            base, index = self.expr(node.value, state, path), self.expr(node.slice, state, path)
            principal_fields = {'id': 'id', 'pk': 'id', 'user_id': 'id', 'tenant_id': 'tenant_id', 'account_id': 'account_id'}
            if (base.principal == 'object' or base.symbol == 'flask.session') and index.literal in principal_fields:
                return Value(principal=principal_fields[index.literal])
            if base.mapping:
                return dict(base.mapping).get(index.literal, combine([base, index]))
            if base.rows and index.literal in OWNER:
                for key in base.rows:
                    self.rows[key]['fields'].add(index.literal)
                return replace(base, member=index.literal, principal="", symbol="")
            return replace(base, principal="", member="", symbol="")
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            values = tuple(self.expr(e, state, path) for e in node.elts)
            return replace(combine(values), items=values)
        if isinstance(node, ast.Dict):
            pairs = tuple((self.expr(k, state, path).literal, self.expr(v, state, path)) for k, v in zip(node.keys, node.values))
            return replace(combine(v for _, v in pairs), mapping=pairs)
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value, state, path)
            self.assign(node.target, value, state)
            return value
        if isinstance(node, ast.Call):
            target = self.symbol(node.func, state)
            receiver = self.expr(node.func.value, state, path) if isinstance(node.func, ast.Attribute) else Value()
            args = [(a, self.expr(a, state, path)) for a in node.args]
            keywords = {k.arg: self.expr(k.value, state, path) for k in node.keywords if k.arg}
            if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
                self.issue(self.gaps, path, node, 'python-project-argument-gap', 'Expanded call arguments require review', 'Starred arguments are not a reliable exact parameter binding in this bounded analyzer.')
                return combine([v for _, v in args] + [self.expr(k.value, state, path) for k in node.keywords])
            value = combine([v for _, v in args] + list(keywords.values()) + [receiver])
            if target in self.functions:
                return self.call(target, args, keywords, state, path, node)
            name = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if receiver.symbol == 'flask.session' and name == 'get' and len(args) == 1 and not keywords:
                field = args[0][1].literal
                if field in {'user_id', 'id', 'tenant_id', 'account_id'}:
                    return Value(principal='id' if field == 'user_id' else field)
            if receiver.rows and name == 'get' and len(args) == 1 and not keywords and args[0][1].literal in OWNER:
                for key in receiver.rows:
                    self.rows[key]['fields'].add(args[0][1].literal)
                return replace(receiver, member=args[0][1].literal, principal='', symbol='')
            if name == 'get' and receiver.mapping and 1 <= len(args) <= 2 and not keywords:
                choices = [v for _, v in receiver.mapping] + ([args[1][1]] if len(args) == 2 else [Value(literal=None)])
                if all(isinstance(v.literal, str) and not v.origins and not v.rows for v in choices):
                    return Value(symbol='@fixed-string-choices')
            if target in {"sqlite3.connect", "sqlite3.Connection", "psycopg.connect", "psycopg2.connect"}:
                return Value(symbol="@sql")
            if target == 'flask_sqlalchemy.SQLAlchemy':
                return Value(symbol='@flask-db')
            if target == 'sqlalchemy.text' and len(args) == 1 and not keywords:
                return replace(args[0][1], principal='', member='', trace=args[0][1].trace + (self.loc(path, node),))
            if receiver.symbol == "@sql" and name == "cursor":
                return Value(symbol="@sql")
            if name == 'cursor' and not args and not keywords:
                self.issue(self.tasks, path, node, 'python-project-sql-provenance', 'Verify cursor library identity', 'A DB-API-shaped cursor is summarized provisionally; no database identity or runtime reachability is established.')
                return Value(symbol='@potential-sql')
            if name == "execute":
                query = args[0][1] if args else keywords.get("query", keywords.get("sql", Value()))
                parameters = args[1][1] if len(args) > 1 else keywords.get("parameters", keywords.get("params", Value()))
                if receiver.symbol in {"@sql", '@potential-sql', '@session', '@potential-session'} or query.origins or query.symbol == '@fixed-sql-shape' or isinstance(query.literal, str) and re.match(r"\s*(SELECT|UPDATE|DELETE)\b", query.literal, re.I):
                    result = self.sql(path, node, query, parameters, state)
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        state.env[node.func.value.id] = replace(receiver, rows=result.rows, trace=result.trace)
                    return result
            if name in {"fetchone", "fetchall"} and receiver.rows:
                return receiver
            if target in {"sqlalchemy.orm.Session", "sqlalchemy.orm.sessionmaker"}:
                return Value(symbol="@session")
            if receiver.symbol in {"@session", '@potential-session'} and name in {"query", "get"} and args and args[0][1].symbol:
                model = args[0][1].symbol
                if model not in self.models:
                    self.models[model] = ('unverified-orm', set())
                    self.issue(self.tasks, path, node, 'python-project-orm-provenance', 'Verify session model binding', 'No model definition was supplied for the session query/get argument; object and tenant policy remain conditional.')
                query = Value(orm=(self.models[model][0], model, ()))
                return self.orm_read(path, node, query, "get", args[1:], {}, state) if name == "get" else query
            if receiver.orm:
                result = self.orm_read(path, node, receiver, name, args, keywords, state)
                if result is not None:
                    return result
            if receiver.rows and name in {"save", "delete"}:
                self.boundary(path, node, receiver, state, name)
                return Value()
            if receiver.symbol in {"@session", '@potential-session'} and name in {"delete", "add"} and args:
                self.boundary(path, node, args[0][1], state, name)
                return Value()
            if target in {"eval", "exec", "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_output", "subprocess.check_call", "subprocess.Popen"}:
                shell = keywords.get("shell", Value()).literal
                first = args[0][1] if args else Value()
                literal_control = isinstance(first.literal, (str, bytes)) and not first.origins
                legacy = 'python-dynamic-code' if target in {'eval', 'exec'} else 'python-shell'
                self.observe_control(path, node, legacy, literal_control)
                if value.origins and target.startswith("subprocess.") and shell is not True:
                    self.issue(self.tasks, path, node, "python-project-interpreter-options", "Review request-controlled process arguments", "shell is not proven true; inspect argument and executable selection without assuming shell injection.", value)
                elif value.origins:
                    self.issue(self.signals, path, node, "python-project-interpreter-input", "Request data reaches an interpreter", "A bounded local call chain carries request origin to a code/shell boundary; verify sanitization and reachability.", replace(value, trace=value.trace + (self.loc(path, node),)))
                return replace(value, principal='', member='', symbol='')
            if name in {"send", "send_json", "reply"} and value.rows:
                self.boundary(path, node, value, state, "response")
            transfers = {"str", "int", "float", "dict", "list", "tuple", "json.dumps", "flask.jsonify", "jsonify"}
            if target in transfers or name in {"get", "format", "join", "strip", "encode", "decode"} and receiver.origins:
                return replace(value, principal="", member="", symbol="")
            if value.origins or value.rows:
                self.issue(self.gaps, path, node, "python-project-unresolved-call", "Request/object flow crosses an unresolved call", f"No supported local summary or library transfer is available for {target or dotted(node.func) or 'dynamic call'}.", value)
                # Preserve candidate flow but never infer a principal, guard or sanitizer from an unknown call.
                for key in value.rows:
                    state.guards.pop(key, None)
                    if key in self.rows:
                        self.rows[key]['scoped'] = set()
            if any(v.symbol in self.functions for _, v in args) or any(v.symbol in self.functions for v in keywords.values()):
                self.issue(self.gaps, path, node, 'python-project-callback-gap', 'Function passed into unresolved registration or dispatch', 'A supplied local function is passed to an unsupported caller/registration API. Its possible input contexts are unknown; project controls cannot suppress per-file signals.')
            return replace(value, principal="", member="", symbol="")
        if isinstance(node, ast.Await):
            return self.expr(node.value, state, path)
        values = [self.expr(child, state, path) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        value = combine(values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and not value.origins:
            if values and all(isinstance(v.literal, str) or v.symbol in {'@fixed-string-choices', '@fixed-sql-shape'} for v in values):
                return Value(literal=''.join(v.literal for v in values)) if all(isinstance(v.literal, str) for v in values) else Value(symbol='@fixed-sql-shape')
        return replace(value, rows=frozenset() if isinstance(node, (ast.Compare, ast.BoolOp)) else value.rows)

    def assign(self, target, value, state):
        if isinstance(target, ast.Name):
            state.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for i, part in enumerate(target.elts):
                self.assign(part, value.items[i] if i < len(value.items) else Value(), state)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # Assigning ownership on a selected object invalidates an earlier guard for that object.
            base = self.expr(target.value, state, self.stack[-1][2][0] if self.stack else '')
            field = target.attr if isinstance(target, ast.Attribute) else target.slice.value if isinstance(target.slice, ast.Constant) else None
            if base.rows:
                self.boundary(self.stack[-1][2][0] if self.stack else '', target, base, state, 'mutation')
            if field in OWNER or field is None:
                for key in base.rows:
                    state.guards.pop(key, None)
                    self.rows[key]['scoped'] = set()

    def observe_control(self, path, node, rule, safe):
        key = self.loc(path, node) + (rule,)
        self.controls[key] = self.controls.get(key, True) and safe

    def proof(self, test, truth, state, path):
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.proof(test.operand, not truth, state, path)
        if isinstance(test, ast.BoolOp):
            reliable = isinstance(test.op, ast.And) and truth or isinstance(test.op, ast.Or) and not truth
            if reliable:
                for part in test.values:
                    self.proof(part, truth, state, path)
            return
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op = test.ops[0]
            equal = isinstance(op, ast.Eq) and truth or isinstance(op, ast.NotEq) and not truth
            if equal:
                left, right = self.expr(test.left, state, path), self.expr(test.comparators[0], state, path)
                for owned, principal in ((left, right), (right, left)):
                    if owned.member in OWNER and principal.principal == OWNER[owned.member] and not principal.origins:
                        for key in owned.rows:
                            state.guards[key] = frozenset(set(state.guards.get(key, ())) | {owned.member})
            return
        value = self.expr(test, state, path)
        if truth and value.principal in {"is_admin", "is_superuser"} and not value.origins:
            state.admin = True
            state.non_admin = False
        elif not truth and value.principal in {"is_admin", "is_superuser"} and not value.origins:
            state.non_admin = True
            state.admin = False

    def has_decorator_admin_check(self, key):
        """A visible role denial changes the policy question, never proves object access."""
        module, _path, function = self.functions[key]
        if len(function.body) != 2 or not isinstance(function.body[0], ast.FunctionDef) or len(function.args.args) != 1 or function.args.posonlyargs or function.args.kwonlyargs:
            return False
        wrapper, returned = function.body
        parameter = function.args.args[0].arg
        if (not isinstance(returned, ast.Return) or not isinstance(returned.value, ast.Name) or returned.value.id != wrapper.name
                or len(wrapper.body) != 2 or not isinstance(wrapper.body[1], ast.Return)
                or not isinstance(wrapper.body[1].value, ast.Call) or dotted(wrapper.body[1].value.func) != parameter):
            return False
        state = State(dict(self.globals[module]))
        # Shadowed names and unknown wrappers cannot establish a trusted role source.
        for p in function.args.args + wrapper.args.posonlyargs + wrapper.args.args + wrapper.args.kwonlyargs + [a for a in (wrapper.args.vararg, wrapper.args.kwarg) if a]:
            state.env[p.arg] = Value()
        if any(self.symbol(d.func if isinstance(d, ast.Call) else d, state) != 'functools.wraps' for d in wrapper.decorator_list):
            return False
        for node in wrapper.body[:1]:
            if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare) or len(node.test.ops) != 1 or not isinstance(node.test.ops[0], ast.NotEq):
                continue
            test = node.test
            if not isinstance(test.comparators[0], ast.Constant) or test.comparators[0].value != 'admin':
                continue
            role = test.left
            trusted = (isinstance(role, ast.Call) and self.symbol(role.func, state) == 'flask.session.get'
                       and len(role.args) == 1 and not role.keywords and isinstance(role.args[0], ast.Constant) and role.args[0].value == 'role')
            trusted |= (isinstance(role, ast.Subscript) and self.symbol(role.value, state) == 'flask.session'
                        and isinstance(role.slice, ast.Constant) and role.slice.value == 'role')
            denied = any(isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and self.symbol(s.value.func, state) == 'flask.abort'
                         and s.value.args and isinstance(s.value.args[0], ast.Constant) and s.value.args[0].value in {401, 403, 404} for s in node.body)
            if trusted and denied:
                return True
        return False

    def block(self, statements, states, path, route=False):
        returns = []
        for node in statements:
            live = []
            for state in states:
                if self.nodes > MAX_NODES:
                    break
                if isinstance(node, ast.Assign):
                    value = self.expr(node.value, state, path)
                    for target in node.targets:
                        self.assign(target, value, state)
                    live.append(state)
                elif isinstance(node, ast.AnnAssign):
                    self.assign(node.target, self.expr(node.value, state, path), state)
                    live.append(state)
                elif isinstance(node, ast.AugAssign):
                    self.assign(node.target, combine([self.expr(node.target, state, path), self.expr(node.value, state, path)]), state)
                    live.append(state)
                elif isinstance(node, ast.Return):
                    value = self.expr(node.value, state, path)
                    if route:
                        self.boundary(path, node, value, state, "disclosure")
                    returns.append((value, state))
                elif isinstance(node, ast.Raise):
                    self.expr(node.exc, state, path)
                elif isinstance(node, ast.If):
                    self.expr(node.test, state, path)
                    yes, no = state.copy(), state.copy()
                    self.proof(node.test, True, yes, path)
                    self.proof(node.test, False, no, path)
                    a, ar = self.block(node.body, [yes], path, route)
                    b, br = self.block(node.orelse, [no], path, route)
                    live.extend(a + b)
                    returns.extend(ar + br)
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    self.issue(self.gaps, path, node, 'python-project-with-gap', 'Context manager exception policy requires review', 'Context expressions and as-bindings are analyzed; __enter__/__exit__ side effects and exception suppression do not establish authorization guards.')
                    branch = state.copy()
                    for item in node.items:
                        value = self.expr(item.context_expr, branch, path)
                        if item.optional_vars:
                            self.assign(item.optional_vars, value, branch)
                    more, rr = self.block(node.body, [branch], path, route)
                    returns.extend(rr)
                    for exit_state in more:
                        exit_state.guards, exit_state.admin, exit_state.non_admin = {}, False, False
                    live.extend(more)
                elif isinstance(node, ast.Expr):
                    self.expr(node.value, state, path)
                    target = self.symbol(node.value.func, state) if isinstance(node.value, ast.Call) else ""
                    if target not in {"abort", "flask.abort", "sys.exit"}:
                        live.append(state)
                elif isinstance(node, ast.Assert):
                    self.expr(node.test, state, path)
                    self.issue(self.gaps, path, node, "python-project-assert-gap", "Assertion is not an authorization guard", "Python optimization can remove assertions; no authorization proof is inferred.")
                    live.append(state)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Nested definitions have lexical bindings, not global name substitution.
                    key = path + ":" + str(node.lineno) + ":" + node.name
                    module = self.stack[-1][0] if self.stack else next((m for m, (p, _) in self.modules.items() if p == path), "")
                    self.functions[key] = (module, path, node)
                    state.env[node.name] = Value(symbol=key)
                    self.globals[key] = dict(state.env)
                    live.append(state)
                elif isinstance(node, (ast.Import, ast.ImportFrom, ast.ClassDef, ast.Pass)):
                    live.append(state)
                else:
                    self.issue(self.gaps, path, node, "python-project-control-gap", "Unsupported control flow", f"{type(node).__name__} is outside the bounded branch subset; guards are not inferred through it.")
                    uncertain = state.copy()
                    uncertain.guards, uncertain.admin, uncertain.non_admin = {}, False, False
                    # Visit possible bodies for candidates, while retaining the zero-iteration/exception path.
                    for attr in ("body", "orelse", "finalbody"):
                        body = getattr(node, attr, [])
                        if body:
                            more, rr = self.block(body, [uncertain.copy()], path, route)
                            live.extend(more)
                            returns.extend(rr)
                    live.append(uncertain)
            states = live
            if len(states) > MAX_STATES:
                self.issue(self.gaps, path, node, "python-project-complexity-gap", "Branch state budget reached", "Remaining paths are merged conservatively; authorization guards are discarded.")
                names = set().union(*(s.env.keys() for s in states))
                states = [State({name: combine(s.env.get(name, Value()) for s in states) for name in names})]
        return states, returns

    def call(self, target, args, keywords, caller, caller_path, node):
        module, path, definition = self.functions[target]
        if any(item[1] == target for item in self.stack):
            self.issue(self.gaps, caller_path, node, "python-project-cycle-gap", "Recursive call summary stopped", "The active call cycle exceeds this analyzer's nonrecursive summary subset.")
            return combine([v for _, v in args] + list(keywords.values()))
        if len(self.stack) >= MAX_DEPTH or self.contexts >= MAX_CONTEXTS:
            self.issue(self.gaps, caller_path, node, "python-project-complexity-gap", "Call context budget reached", "Depth/context budget stopped interprocedural expansion.")
            return combine([v for _, v in args] + list(keywords.values()))
        self.contexts += 1
        self.expanded_functions.add(target)
        env = dict(self.globals.get(target, self.globals.get(module, {})))
        parameters = definition.args.posonlyargs + definition.args.args
        defaults = {p.arg: d for p, d in zip(parameters[-len(definition.args.defaults):], definition.args.defaults)} if definition.args.defaults else {}
        for i, parameter in enumerate(parameters):
            env[parameter.arg] = args[i][1] if i < len(args) else keywords.get(parameter.arg, self.expr(defaults.get(parameter.arg), State(env), path))
        for parameter, default in zip(definition.args.kwonlyargs, definition.args.kw_defaults):
            env[parameter.arg] = keywords.get(parameter.arg, self.expr(default, State(env), path))
        if definition.args.vararg:
            env[definition.args.vararg.arg] = replace(combine(v for _, v in args[len(parameters):]), items=tuple(v for _, v in args[len(parameters):]))
        if definition.args.kwarg:
            extra = tuple((k, v) for k, v in keywords.items() if k not in {p.arg for p in parameters + definition.args.kwonlyargs})
            env[definition.args.kwarg.arg] = replace(combine(v for _, v in extra), mapping=extra)
        call_location = self.loc(caller_path, node)
        env = {k: replace(v, trace=v.trace + (call_location,)) if v.origins or v.rows else v for k, v in env.items()}
        state = State(env, dict(caller.guards), caller.admin, caller.non_admin, caller.decorator_policy_unknown)
        self.stack.append((module, target, call_location))
        live, returns = self.block(definition.body, [state], path)
        self.stack.pop()
        exits = [s for _, s in returns] + live
        if exits:
            keys = set.intersection(*(set(s.guards) for s in exits))
            caller.guards = {k: frozenset.intersection(*(s.guards[k] for s in exits)) for k in keys}
            caller.admin = all(s.admin for s in exits)
            caller.non_admin = all(s.non_admin for s in exits)
        else:
            # A guard helper that raises/aborts on every analyzed path never returns.
            # Keep caller analysis conservative rather than inventing a successful guard.
            caller.guards, caller.admin, caller.non_admin = {}, False, False
        result = combine(v for v, _ in returns)
        # Exact return identity survives only if every normal return agrees, including no implicit None.
        if returns and not live:
            principals = {v.principal for v, _ in returns}
            members = {v.member for v, _ in returns}
            symbols = {v.symbol for v, _ in returns}
            result = replace(result, principal=next(iter(principals)) if len(principals) == 1 else "",
                             member=next(iter(members)) if len(members) == 1 else "", symbol=next(iter(symbols)) if len(symbols) == 1 else "")
            if len(returns) == 1:
                result = replace(result, literal=returns[0][0].literal, items=returns[0][0].items, mapping=returns[0][0].mapping, orm=returns[0][0].orm)
        self.summary_cache[(target, call_location, self.contexts)] = result
        return result

    def run(self):
        self.schemas = {}
        for module, (path, tree) in self.modules.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    match = re.fullmatch(r"\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.*)\)\s*;?\s*", node.value, re.I | re.S)
                    if match:
                        names = {x.strip().split()[0].strip('"`[]').lower() for x in match[2].split(",") if x.strip()}
                        self.schemas[match[1].lower()] = names & OWNER.keys()
        for module, (path, tree) in self.modules.items():
            states, _ = self.block([n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))], [State(dict(self.globals[module]))], path)
            if states:
                # Join global bindings, keeping exact symbols only when all paths agree.
                env = dict(self.globals[module])
                for name in set().union(*(s.env.keys() for s in states)):
                    values = [s.env.get(name, Value()) for s in states]
                    env[name] = values[0] if all(v == values[0] for v in values) else combine(values)
                self.globals[module] = env
        for key, (module, path, node) in list(self.functions.items()):
            decorators = [dotted(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list]
            route = any(d.endswith((".route", ".get", ".post", ".put", ".patch", ".delete")) for d in decorators)
            request_parameters = [p for p in node.args.posonlyargs + node.args.args + node.args.kwonlyargs if p.arg == 'request']
            if not route and request_parameters:
                route = True
                self.issue(self.tasks, path, node, 'python-project-entrypoint-policy', 'Verify request handler dispatch', 'An explicit request parameter is analyzed as a possible handler; confirm actual framework registration and authentication middleware.')
            if not route:
                bindings = State(dict(self.globals.get(module, {})))
                source_references = any(self.symbol(n, bindings) == 'flask.request' for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute)))
                if source_references:
                    route = True
                    self.issue(self.tasks, path, node, 'python-project-entrypoint-policy', 'Verify request-consuming function dispatch', 'An explicitly resolved request object occurs in this supplied function. Its body is analyzed as a possible request entrypoint; actual registration and caller types remain unverified.')
            if not route:
                continue
            env = dict(self.globals[module])
            for p in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                if p.arg == "request":
                    env[p.arg] = Value(symbol="request")
                else:
                    location = self.loc(path, p)
                    env[p.arg] = Value(origins=frozenset({location}), trace=(location,))
            state = State(env)
            resolved = [self.symbol(d.func if isinstance(d, ast.Call) else d, state) for d in node.decorator_list
                        if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                                and d.func.attr in {'route', 'get', 'post', 'put', 'patch', 'delete'})]
            state.decorator_policy_unknown = any(d in self.functions and self.has_decorator_admin_check(d) for d in resolved)
            self.expanded_functions.add(key)
            self.stack.append((module, key, self.loc(path, node)))
            live, returns = self.block(node.body, [state], path, route=True)
            self.stack.pop()
            if re.search(r"(?:^|[/._])admin(?:[/._]|$)", " ".join(str(d.args[0].value) for d in node.decorator_list if isinstance(d, ast.Call) and d.args and isinstance(d.args[0], ast.Constant)), re.I):
                exits = live + [s for _, s in returns]
                self.issue(self.tasks, path, node, "python-project-admin-boundary", "Verify admin route policy", "Route spelling alone does not establish an admin requirement. Compare observed trusted admin guards with actual privileged operations and framework policy; denial returns can appear as unguarded exits.",
                           admin_guard_observed=any(s.admin for s in exits), guarded_exit_count=sum(s.admin for s in exits), normal_exit_count=len(exits))
        # A safe supported caller does not close the contexts of an undispatched
        # function that references the same supplied helper (including import aliases).
        for key, (module, path, node) in list(self.functions.items()):
            if key in self.expanded_functions:
                continue
            bindings = State(dict(self.globals.get(key, self.globals.get(module, {}))))
            referenced = {self.symbol(n, bindings) for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute))}
            if referenced & self.expanded_functions:
                self.issue(self.gaps, path, node, 'python-project-unexpanded-caller-gap', 'Supplied helper has an unexpanded possible caller', 'An unsupported entrypoint or undispatched function references a helper analyzed elsewhere. Unknown caller contexts prevent suppressing per-file signals.')
        return self.signals, self.gaps, self.tasks


def inspect_project(sources, *, controls_out=None):
    """Return (candidate signals, explicit coverage gaps, verification tasks).

    sources maps repository-relative Python paths to inert source text. Bounded
    contexts preserve call-site order and exact object identity; they do not prove
    framework dispatch, authentication middleware, SQL semantics or access policy.
    """
    project = Project(sources)
    try:
        result = project.run()
    except (RecursionError, MemoryError):
        project.issue(project.gaps, '<project>', None, 'python-project-resource-gap', 'Python AST recursion/resource limit reached', 'Project analysis stopped; no control suppression is inferred.')
        result = project.signals, project.gaps, project.tasks
    if controls_out is not None and not project.analysis_incomplete:
        for (path, line, column, rule), safe in sorted(project.controls.items()):
            if safe:
                controls_out.append(dict(path=path, line=line, column=column, rules=[rule], status='recognized-control'))
    return result
