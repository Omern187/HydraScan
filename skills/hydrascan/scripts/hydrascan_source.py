"""Bounded, intraprocedural source triage; signals remain unverified candidates."""
import ast
import re
from html.parser import HTMLParser

INPUT = "Command, code, and template injection"
FILES = "Files, paths and archives"
SQL = "SQL and data query injection"
PARSER = "Parsers and serialization"
TRANSPORT = "Cryptography and transport"
CONTENT = "XSS and content injection"
SSRF = "SSRF and outbound trust"
AUTH = "Authorization and tenant isolation"


def name_of(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name_of(node.value) + "." + node.attr
    return ""


def inspect_python(text):
    """Keep bindings local to a function and follow simple assignments in source order.

    No whole-program reachability, interprocedural taint, branch proof or framework policy inference.
    """
    tree = ast.parse(text)
    signals, tasks, seen = [], [], set()
    owned_tables, lookups = {}, {}
    ownership = {'owner', 'owner_id', 'user_id', 'tenant_id', 'account_id'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and name_of(node.func).endswith('.execute') and node.args and isinstance(node.args[0], ast.Constant):
            schema = node.args[0].value
            match = re.fullmatch(r'\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.*)\)\s*;?\s*', schema, re.I | re.S) if isinstance(schema, str) else None
            if match:
                columns = {item.strip().split()[0].strip('"`[]').lower() for item in match[2].split(',') if item.strip()}
                owned_tables[match[1].lower()] = columns & ownership

    def emit(node, rule, title, family, detail):
        key = (node.lineno, node.col_offset, rule)
        if key not in seen:
            signals.append({"line": node.lineno, "column": node.col_offset + 1, "rule": rule, "title": title, "family": family,
                            "method": "Python AST and local assignment flow", "detail": detail})
            seen.add(key)

    def binding(node, env):
        if isinstance(node, ast.NamedExpr):
            return binding(node.value, env)
        name = name_of(node)
        first, dot, rest = name.partition(".")
        return env.get(first, {}).get("call", first) + (dot + rest if dot else "")

    def facts(node, env):
        if node is None:
            return {}
        if isinstance(node, ast.Name):
            return dict(env.get(node.id, {"dynamic": True, "call": node.id}))
        if isinstance(node, ast.Constant):
            return {"dynamic": False, "call": "", "literal": node.value,
                    "text_parts": [node.value] if isinstance(node.value, str) else []}
        if isinstance(node, ast.NamedExpr):
            return facts(node.value, env)
        if isinstance(node, ast.Attribute):
            base = facts(node.value, env)
            result = {**base, "call": binding(node, env), 'owner_access': set()}
            root = name_of(node).split('.')[0]
            external = root not in env or env[root].get('parameter') or env[root].get('request_source')
            source_fields = {'path', 'args', 'GET', 'POST', 'query_params', 'path_params', 'json', 'form', 'values', 'cookies', 'headers', 'files', 'data', 'body', 'view_args'}
            if (external and name_of(node) == 'self.path' or node.attr in source_fields
                    and (external and name_of(node).startswith('request.') or binding(node.value, env) == 'flask.request')):
                result.update(dynamic=True, request_input=True, html_input=True, input_line=node.lineno)
            if (external and name_of(node) == 'request.user' or root not in env and name_of(node) in {'current_user.id', 'current_user.pk', 'current_user.tenant_id'}
                    or binding(node, env) == 'flask.g.user'
                    or base.get('principal') and node.attr in {'id', 'pk', 'tenant_id', 'account_id'}):
                result['principal'] = True
            else:
                result['principal'] = False
            if node.attr.lower() in ownership and base.get('direct_objects'):
                result['owner_access'] = {(location, node.attr.lower()) for location in base['direct_objects']}
                result['direct_objects'] = set()
            return result
        if isinstance(node, ast.Subscript):
            base = facts(node.value, env)
            index = facts(node.slice, env)
            result = {**base, 'call': '', 'owner_access': set(), 'direct_objects': set(), 'principal': bool(
                (base.get('principal') or binding(node.value, env) == 'flask.session')
                and index.get('literal') in {'id', 'pk', 'user_id', 'tenant_id', 'account_id'})}
            if index.get('literal') in ownership and base.get('direct_objects'):
                result['owner_access'] = {(location, index['literal']) for location in base['direct_objects']}
            return result
        if isinstance(node, ast.Call):
            target = binding(node.func, env)
            values = [facts(value, env) for value in node.args] + [facts(value.value, env) for value in node.keywords]
            receiver = facts(node.func.value, env) if isinstance(node.func, ast.Attribute) else {}
            flow = combine_flow(values + [receiver])
            if target in {'flask.request.get_data', 'flask.request.get_json'}:
                flow.update(request_input=True, html_input=True, input_line=node.lineno)
            if target in {'urllib.parse.urlparse', 'urllib.parse.urlsplit'} and node.args:
                return {**flow, 'dynamic': True, 'call': '', 'parsed_url': name_of(node.args[0])}
            if target in {'int', 'builtins.int', 'werkzeug.utils.secure_filename'}:
                return {**flow, 'dynamic': False, 'call': '', 'path_safe_segment': True}
            if target in {'markupsafe.escape', 'html.escape'} and len(node.args) == 1 and not node.keywords:
                return {**flow, 'dynamic': True, 'call': '', 'html_input': False, 'html_escaped': True}
            if target in {'flask.render_template', 'flask.render_template_string'}:
                # Template-source and explicit Markup checks run at their own
                # sinks. Rendering data is not raw HTML concatenation evidence.
                return {**flow, 'dynamic': True, 'call': '', 'html_input': False,
                        'html_escaped': True, 'text_parts': []}
            if target == 'flask.session.get' and len(node.args) == 1 and not node.keywords and values[0].get('literal') in {'user_id', 'id', 'tenant_id', 'account_id'}:
                return {'dynamic': True, 'call': '', 'principal': True}
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'get' and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'Authorization':
                flow['auth_token'] = True
            if name_of(node.func).lower().endswith(('sessions.get', 'session_users.get')) and flow.get('auth_token'):
                flow['principal'] = True
            lookup = query_lookup(node, env)
            if lookup:
                location = (node.lineno, node.col_offset)
                lookups[location] = lookup
                flow['objects'] = flow['direct_objects'] = {location}
                flow['owner_access'] = set()
            elif target.endswith('.fetchone'):
                flow['direct_objects'] = set(receiver.get('direct_objects', set()))
            elif target == 'dict' and len(values) == 1 and not node.keywords:
                flow['direct_objects'] = set(values[0].get('direct_objects', set()))
            elif isinstance(node.func, ast.Attribute) and node.func.attr == 'get' and len(node.args) == 1 and not node.keywords:
                field = values[0].get('literal')
                if field in ownership and receiver.get('direct_objects'):
                    flow['owner_access'] = {(location, field) for location in receiver['direct_objects']}
            if target == "tarfile.open":
                return {"dynamic": False, "call": "", "tar": True}
            if target == 'zipfile.ZipFile':
                return {"dynamic": False, "call": "", "zip": True}
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'namelist', 'infolist'} and receiver.get('zip'):
                return {'dynamic': True, 'call': '', 'archive_member': True}
            if target in {'flask.Flask', 'flask.Blueprint'}:
                return {'dynamic': False, 'call': '', 'flask_app': True}
            if target in {"pathlib.Path", "Path", "os.path.join"} or target.endswith((".joinpath", ".resolve", ".absolute")):
                base = facts(node.func.value, env) if isinstance(node.func, ast.Attribute) else {}
                if target in {'pathlib.Path', 'Path'} and len(values) == 1 and values[0].get('path'):
                    base = values[0]
                root_value = values[0] if target == 'os.path.join' and values else base
                return {**base, **flow, "dynamic": any(value.get("dynamic") for value in values) or base.get("dynamic", False),
                        "path": True, "normalized": target.endswith(".resolve"), "call": "",
                        "path_root": base.get('path_root') or (ast.dump(node.args[0]) if target == 'os.path.join' and node.args else None),
                        "root_version": base.get('root_version') if target != 'os.path.join' else root_value.get('bound_at'),
                        "root_input": base.get('root_input', False) or (target == 'os.path.join' and root_value.get('request_input', False)),
                        "path_segment_dynamic": base.get("path_segment_dynamic", False) or any(value.get("dynamic") for value in values)}
            if target in {"requests.Session", "httpx.Client", "httpx.AsyncClient"}:
                return {"dynamic": False, "call": target.rsplit(".", 1)[0], 'tls_client': True}
            if target.endswith((".format", ".join")):
                receiver = facts(node.func.value, env) if isinstance(node.func, ast.Attribute) else {}
                return {**combine_flow(values + [receiver]), "dynamic": receiver.get("dynamic", False) or any(value.get("dynamic") for value in values), "composed": True, "call": ""}
            # Safe literal conversion is not evidence for string/query/path containment.
            return {**flow, "dynamic": True, "call": ""}
        children = [facts(child, env) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        path_base = facts(node.left, env) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) else {}
        flow = combine_flow(children)
        if isinstance(node, ast.Compare) or isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            flow['objects'] = set()  # A boolean result is not the fetched record.
        return {**flow, "dynamic": any(child.get("dynamic") for child in children), "call": "",
                "elements": children if isinstance(node, (ast.Tuple, ast.List, ast.Set)) else None,
                "mapping": {facts(key, env).get('literal'): facts(value, env) for key, value in zip(node.keys, node.values)
                            if key is not None and isinstance(facts(key, env).get('literal'), (str, int, bool))} if isinstance(node, ast.Dict) else None,
                "composed": isinstance(node, (ast.JoinedStr, ast.BinOp)),
                "path": isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div),
                "path_root": ast.dump(node.left) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) else None,
                "root_version": path_base.get('bound_at'), "root_input": path_base.get('request_input', False),
                "path_segment_dynamic": path_base.get('path_segment_dynamic', False) or facts(node.right, env).get("dynamic") if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) else False}

    def combine_flow(values):
        result = {key: any(value.get(key) for value in values) for key in ('request_input', 'auth_token', 'html_input', 'archive_member')}
        result['html_escaped'] = any(value.get('html_escaped') for value in values) and all(not value.get('dynamic') or value.get('html_escaped') for value in values)
        result['text_parts'] = [part for value in values for part in value.get('text_parts', [])][:128]
        # Containing a principal is not the same as being that exact principal.
        result['principal'] = False
        for key in ('objects', 'tampered_objects'):
            result[key] = set().union(*(value.get(key, set()) for value in values))
        result['owner_access'] = set()
        lines = [value['input_line'] for value in values if value.get('input_line')]
        if lines:
            result['input_line'] = min(lines)
        return result

    def query_lookup(node, env):
        if not binding(node.func, env).endswith('.execute'):
            return None
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        query_node = node.args[0] if node.args else keywords.get('query', keywords.get('sql'))
        raw = facts(query_node, env).get('literal')
        if not isinstance(raw, str):
            return None
        match = re.match(r'\s*SELECT\b.*?\bFROM\s+(\w+)\b.*?\bWHERE\b(.*)', raw, re.I | re.S)
        if not match:
            return None
        where = match[2]
        params_node = node.args[1] if len(node.args) > 1 else keywords.get('parameters', keywords.get('params'))
        params = facts(params_node, env).get('elements') or []
        id_match = re.search(r'\b(?:id|pk)\s*=\s*\?', where, re.I)
        if not id_match:
            return None
        position = where[:id_match.end()].count('?') - 1
        if position >= len(params) or not params[position].get('request_input'):
            return None
        fields = owned_tables.get(match[1].lower(), ownership)
        if not fields:
            return None  # Publication policy is reviewed by the project analyzer.
        scoped = False
        # Accept only a flat conjunction with a bound principal; OR and nested
        # predicate expressions require review rather than a guessed guarantee.
        simple = not re.search(r'\b(?:OR|NOT)\b|[()\'\"]|--|/\*', where, re.I)
        shared = re.fullmatch(r'\s*(?:id|pk)\s*=\s*\?\s+AND\s*\(\s*(?:owner|owner_id|user_id|tenant_id|account_id)\s*=\s*\?\s+OR\s+is_public\s*=\s*1\s*\)\s*;?\s*', where, re.I)
        if simple or shared:
            delimiter = r'(?:OR\b)' if shared else r'(?:AND\b|$|;)'
            for owner in re.finditer(r'\b(' + '|'.join(sorted(fields)) + r')\s*=\s*\?(?=\s*' + delimiter + ')', where, re.I):
                bound = where[:owner.end()].count('?') - 1
                scoped |= bound < len(params) and bool(params[bound].get('principal')) and not params[bound].get('request_input')
        return {'node': node, 'table': match[1].lower(), 'fields': fields, 'scoped': scoped, 'declared_owner': match[1].lower() in owned_tables,
                'input_line': params[position].get('input_line')}

    def object_guard(test, env, operator):
        if isinstance(test, ast.BoolOp) and (isinstance(operator(), ast.NotEq) and isinstance(test.op, ast.Or)
                                             or isinstance(operator(), ast.Eq) and isinstance(test.op, ast.And)):
            return set().union(*(object_guard(part, env, operator) for part in test.values))
        if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], operator):
            return set()
        left, right = facts(test.left, env), facts(test.comparators[0], env)
        owners = left.get('owner_access', set()) if right.get('principal') and not right.get('request_input') else right.get('owner_access', set()) if left.get('principal') and not left.get('request_input') else set()
        tampered = left.get('tampered_objects', set()) | right.get('tampered_objects', set())
        return {('object', location) for location, field in owners if location not in tampered and field in lookups.get(location, {}).get('fields', set())}

    def disclosure(expression, env, guarded, authenticated):
        if not authenticated:
            return
        flow = facts(expression, env)
        for location in flow.get('objects', set()):
            lookup = lookups[location]
            if lookup['scoped'] or ('object', location) in guarded and location not in flow.get('tampered_objects', set()):
                continue
            emit(lookup['node'], 'python-object-authorization', 'Request-selected owned record reaches a return without a visible object guard', AUTH,
                 'Request-derived ID selects a record and its result reaches a return. Establish route exposure, middleware/database policy, record sensitivity, sharing intent and actual cross-identity effect before confirmation.')
            item = next(item for item in signals if (item['line'], item['column'] - 1) == location and item['rule'] == 'python-object-authorization')
            item['evidence_lines'] = {'input': lookup['input_line'], 'lookup': location[0], 'disclosure': expression.lineno}
            item['table'] = lookup['table']
            item['ownership_schema_observed'] = lookup['declared_owner']
            if not lookup['declared_owner']:
                item['title'] = 'Request-selected record reaches a return; object access policy requires review'

    def terminates(statements, env):
        return any(isinstance(item, (ast.Return, ast.Raise)) or isinstance(item, ast.Expr) and isinstance(item.value, ast.Call)
                   and binding(item.value.func, env) == 'flask.abort' and item.value.args
                   and isinstance(item.value.args[0], ast.Constant) and isinstance(item.value.args[0].value, int)
                   and 400 <= item.value.args[0].value <= 599
                   for item in statements)

    def parameters(arguments):
        return arguments.posonlyargs + arguments.args + arguments.kwonlyargs + [x for x in (arguments.vararg, arguments.kwarg) if x]

    def local_bindings(statements):
        names, outer = set(), set()

        class Locals(ast.NodeVisitor):
            def visit_Name(self, node):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    names.add(node.id)

            def visit_FunctionDef(self, node):
                names.add(node.name)

            visit_AsyncFunctionDef = visit_ClassDef = visit_FunctionDef

            def visit_Lambda(self, node):
                pass

            def visit_Import(self, node):
                names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)

            def visit_ImportFrom(self, node):
                names.update(alias.asname or alias.name for alias in node.names)

            def visit_Global(self, node):
                outer.update(node.names)

            visit_Nonlocal = visit_Global

            def visit_ExceptHandler(self, node):
                if node.name:
                    names.add(node.name)
                self.generic_visit(node)

            def visit_ListComp(self, node):
                # Comprehension targets have their own scope. Named-expression
                # targets in expressions can still bind the enclosing function.
                for generator in node.generators:
                    self.visit(generator.iter)
                    for condition in generator.ifs:
                        self.visit(condition)
                for value in [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]:
                    self.visit(value)

            visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

        visitor = Locals()
        for statement in statements:
            visitor.visit(statement)
        return names - outer

    def scoped_calls(node, env):
        if isinstance(node, ast.Lambda):
            for default in node.args.defaults + [x for x in node.args.kw_defaults if x]:
                yield from scoped_calls(default, env)
            local = dict(env)
            for parameter in parameters(node.args):
                local[parameter.arg] = {"dynamic": True, "call": ""}
            yield from scoped_calls(node.body, local)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            local = dict(env)
            for generator in node.generators:
                yield from scoped_calls(generator.iter, local)
                bind(generator.target, {"dynamic": True, "call": ""}, local)
                for condition in generator.ifs:
                    yield from scoped_calls(condition, local)
            for value in [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]:
                yield from scoped_calls(value, local)
            return
        if isinstance(node, ast.NamedExpr):
            yield from scoped_calls(node.value, env)
            bind(node.target, facts(node.value, env), env)
            return
        # Python captures the callable before evaluating argument expressions.
        callee = binding(node.func, env) if isinstance(node, ast.Call) else None
        for child in ast.iter_child_nodes(node):
            yield from scoped_calls(child, env)
        if isinstance(node, ast.Call):
            yield node, env, callee

    def check_calls(expression, env, guarded, authenticated):
        for node, env, target in scoped_calls(expression, env):
            if name_of(node.func).endswith(('.wfile.write', '.send_json', '.reply')):
                disclosure(node, env, guarded, authenticated)
            keywords = {item.arg: item.value for item in node.keywords if item.arg}
            literal = lambda key, value: isinstance(keywords.get(key), ast.Constant) and keywords[key].value is value
            if target in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                emit(node, "python-dynamic-code", "Dynamic code evaluation", INPUT, "Follow the argument into the resolved evaluator, including local aliases.")
            elif target in {"os.system", "os.popen"} or (target.startswith("subprocess.") and literal("shell", True)):
                emit(node, "python-shell", "Shell interpreter invocation", INPUT, "Establish whether caller-controlled input reaches the shell.")
            elif target in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "yaml.unsafe_load", 'marshal.load', 'marshal.loads', 'jsonpickle.decode'}:
                emit(node, "python-deserialization", "Deserialization requiring trusted input", PARSER, "Verify the provenance of serialized data before accepting this signal.")
            elif target == "yaml.load":
                loader = keywords.get("Loader", node.args[1] if len(node.args) > 1 else None)
                if binding(loader, env) not in {"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader"}:
                    emit(node, "python-yaml-loader", "YAML loader needs configuration review", PARSER, "Resolve the selected loader and callers; a loader's local name is insufficient.")
            elif target == "ssl._create_unverified_context" or (target.startswith(("requests.", "httpx.")) and literal("verify", False)):
                emit(node, "python-tls-verification", "TLS peer verification disabled", TRANSPORT, "Identify affected transport and protected data.")
            elif target in {'lxml.etree.XMLParser', 'lxml.etree.ETCompatXMLParser'} and literal('resolve_entities', True):
                emit(node, 'python-xml-external-entities', 'XML parser explicitly resolves external entities', PARSER,
                     'Establish whether untrusted XML reaches this exact parser; no_network alone does not block local file entities. Runtime defaults and resolvers require review.')
            elif target in {'jwt.decode', 'jwt.api_jwt.decode'}:
                options = facts(keywords.get('options'), env).get('mapping') or {}
                if options.get('verify_signature', {}).get('literal') is False:
                    emit(node, 'python-jwt-unverified', 'JWT signature verification explicitly disabled', TRANSPORT,
                         'Determine whether decoded claims are trusted for identity or permission decisions, or whether the same token was already verified.')
            elif target in {'hashlib.md5', 'hashlib.sha1'} and env.get('@context', {}).get('security_purpose'):
                emit(node, 'python-weak-crypto', 'Weak hash used in a security-named operation', TRANSPORT,
                     'Establish password/signature use; MD5 and SHA-1 are unsuitable for password storage. Nonsecurity checksums may be intentional.')
            elif target in {'random.choice', 'random.choices', 'random.randint', 'random.randrange', 'random.random', 'random.getrandbits', 'random.randbytes'} and env.get('@context', {}).get('security_purpose'):
                emit(node, 'python-weak-random', 'Noncryptographic randomness in a security-named operation', TRANSPORT,
                     'Determine whether output protects a token, session or challenge. Prefer secrets for security material; simulation use is legitimate.')
            elif isinstance(node.func, ast.Attribute) and node.func.attr == 'run' and facts(node.func.value, env).get('flask_app') and literal('debug', True):
                emit(node, 'python-debug-exposure', 'Flask development debugger enabled', TRANSPORT,
                     'Check deployed exposure and entrypoint; the interactive debugger can execute Python and belongs in development only.')
            elif target in {'flask.redirect', 'django.shortcuts.redirect', 'starlette.responses.RedirectResponse', 'fastapi.responses.RedirectResponse'}:
                location = node.args[0] if node.args else keywords.get('location', keywords.get('url', keywords.get('to')))
                if location is not None and facts(location, env).get('dynamic'):
                    emit(node, 'python-open-redirect', 'Variable destination reaches an HTTP redirect', SSRF,
                         'Review exact permitted origins and URL normalization, including scheme-relative URLs and backslashes. Variable redirects may be intentional.')
            elif target == 'markupsafe.Markup' and node.args and facts(node.args[0], env).get('dynamic') and not facts(node.args[0], env).get('html_escaped'):
                emit(node, 'html-rendering', 'Variable content explicitly marked as trusted HTML', CONTENT,
                     'Verify the rendering context and data origin; marking text safe disables template escaping, but a caller may already sanitize it.')
            elif target in {'setattr', 'builtins.setattr'} and len(node.args) == 3 and binding(node.args[0], env) == 'flask_login.current_user' and facts(node.args[1], env).get('request_input'):
                emit(node, 'python-mass-assignment', 'Request-selected attributes assigned to the authenticated user', AUTH,
                     'Establish an explicit writable-field policy and model behavior; caller-selected fields can reach privilege or ownership attributes. Middleware and local allowlists still require review.')
            if target in {'flask.render_template_string', 'jinja2.Template', 'jinja2.Environment.from_string'} or target.endswith('.from_string') and target.startswith('jinja2.'):
                template = node.args[0] if node.args else keywords.get('source', keywords.get('template'))
                if template is not None and facts(template, env).get('dynamic'):
                    emit(node, 'python-template-input', 'Variable template source reaches a template interpreter', INPUT,
                         'Distinguish template source from escaped rendering data; establish reachable input and template capabilities.')

            query_node = node.args[0] if node.args else next((keywords[key] for key in ('query', 'sql', 'statement') if key in keywords), None)
            if target.endswith((".execute", ".executemany", ".executescript", ".raw")) and query_node is not None:
                query = facts(query_node, env)
                if query.get("dynamic") and query.get("composed"):
                    emit(node, "python-sql-composition", "Composed input reaches a query interpreter", SQL, "Query text is assembled before execution; separately inspect bound values, identifiers and permitted SQL builders.")
                raw = query.get("literal")
                if authenticated and isinstance(raw, str) and re.search(r"\bSELECT\b.*\bWHERE\b.*\b(?:id|pk)\s*=", raw, re.I | re.S):
                    where = raw.upper().split("WHERE", 1)[1]
                    if not re.search(r"\b(?:OWNER|USER_ID|TENANT_ID|ACCOUNT_ID)\b", where):
                        tasks.append({"line": node.lineno, "column": node.col_offset + 1, "family": AUTH, "rule": "object-ownership-review",
                                      "question": "Authenticated object lookup is keyed by identifier. Verify owner/tenant enforcement in this route, middleware and database policy; public/shared records may be intentional."})
            if target.endswith(".extractall") and isinstance(node.func, ast.Attribute):
                receiver = facts(node.func.value, env)
                selected = facts(keywords.get("filter"), env) if keywords.get("filter") else {}
                if receiver.get("tar") and selected.get("literal") != "data":
                    emit(node, "python-archive-extraction", "Archive extraction needs path/link containment review", FILES, "The locally recognized TAR receiver lacks an explicit data filter; inspect runtime defaults and all output/link boundaries.")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes", "open", "write_text", "write_bytes", "unlink", "rmdir"}:
                receiver = facts(node.func.value, env)
                checked = (name_of(node.func.value), receiver.get("path_root"), receiver.get('root_version')) in guarded and receiver.get("normalized") and not receiver.get('root_input')
                if receiver.get("path") and receiver.get("path_segment_dynamic") and not checked:
                    emit(node, "python-path-input", "Composed input reaches a file operation", FILES, "Check canonical path containment, caller-controlled bases, links and overwrite permissions; source triage is not a filesystem sandbox.")
            file_calls = {'open', 'builtins.open', 'os.remove', 'os.unlink', 'os.rmdir', 'os.rename', 'os.replace',
                          'shutil.copy', 'shutil.copyfile', 'shutil.move', 'shutil.rmtree', 'flask.send_file'}
            upload_save = isinstance(node.func, ast.Attribute) and node.func.attr == 'save' and facts(node.func.value, env).get('request_input')
            if target in file_calls or upload_save:
                paths = list(node.args[:2] if target in {'os.rename', 'os.replace', 'shutil.copy', 'shutil.copyfile', 'shutil.move'} else node.args[:1])
                if not paths:
                    paths = [keywords[key] for key in ('file', 'filename', 'path', 'path_or_file', 'dst') if key in keywords]
                for argument in paths:
                    path = facts(argument, env)
                    checked = (name_of(argument), path.get('path_root'), path.get('root_version')) in guarded and path.get('normalized') and not path.get('root_input')
                    if not path.get('dynamic') or checked:
                        continue
                    emit(node, "python-path-input", "Composed input reaches a file operation", FILES, "Verify canonical containment and the exact allowed root before the operation.")
                    if path.get('archive_member'):
                        emit(node, 'python-archive-extraction', 'Archive member name reaches a file operation without containment', FILES,
                             'Manual extraction must validate canonical output paths and links; archive member names are not trusted filesystem paths.')
            if target.startswith(("requests.", "httpx.", "urllib.request.", "aiohttp.")) and target.endswith((".get", ".post", ".put", ".patch", ".delete", ".head", ".options", ".request", ".urlopen")):
                position = 1 if target.endswith('.request') else 0
                url = node.args[position] if len(node.args) > position else keywords.get("url")
                checked = url is not None and (name_of(url), 'allowed-url') in guarded and literal('allow_redirects', False)
                if url is not None and facts(url, env).get("dynamic") and not checked:
                    emit(node, "python-outbound-input", "Variable URL reaches an outbound client", SSRF, "Inspect allowed hosts, resolved addresses and redirects on this exact call; variable URLs can be legitimate.")

    def bind(target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = {**value, 'bound_at': (target.lineno, target.col_offset)}
        elif isinstance(target, (ast.Tuple, ast.List)):
            elements = value.get('elements') or []
            for index, element in enumerate(target.elts):
                bind(element, elements[index] if len(elements) == len(target.elts) else {**combine_flow([value]), "dynamic": True, "call": ""}, env)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id in env and env[target.value.id].get('mapping'):
                env[target.value.id] = {**env[target.value.id], 'mapping': None}
            field = facts(target.slice, env).get('literal') if isinstance(target, ast.Subscript) else target.attr.lower()
            if field in ownership:
                objects = facts(target.value, env).get('direct_objects', set())
                for current in env.values():
                    if current.get('objects', set()) & objects:
                        current['tampered_objects'] = current.get('tampered_objects', set()) | objects

    def merge(env, alternatives):
        for name in set().union(*(scope.keys() for scope in alternatives)):
            values = [scope.get(name, {"dynamic": True, "call": ""}) for scope in alternatives]
            value = {**combine_flow(values), **{key: any(item.get(key) for item in values) for key in ('dynamic', 'composed', 'path', 'path_segment_dynamic', 'tar', 'zip', 'flask_app', 'tls_client')}}
            value['principal'] = all(item.get('principal') for item in values)
            value['direct_objects'] = set.intersection(*(set(item.get('direct_objects', set())) for item in values))
            value['normalized'] = all(item.get('normalized') for item in values)
            for key in ('literal', 'path_root', 'root_version', 'bound_at', 'root_input', 'parsed_url', 'elements', 'mapping', 'html_response', 'security_purpose'):
                if all(key in item and item[key] == values[0].get(key) for item in values):
                    value[key] = values[0][key]
            calls = [item.get('call', '') for item in values]
            dangerous = [item for item in calls if item in {'eval', 'exec', 'builtins.eval', 'builtins.exec'} or item.startswith(('pickle.', 'subprocess.', 'requests.', 'httpx.'))]
            value['call'] = dangerous[0] if dangerous else (calls[0] if all(item == calls[0] for item in calls) else '')
            env[name] = value

    def body(statements, env, guarded=None, authenticated=False, function_env=None):
        guarded = set() if guarded is None else set(guarded)
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    env[alias.asname or alias.name.split('.')[0]] = {"dynamic": False, "call": alias.name if alias.asname else alias.name.split('.')[0]}
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    imported = '.' * statement.level + statement.module + "." + alias.name
                    env[alias.asname or alias.name] = {"dynamic": False, "call": imported, 'request_source': imported == 'flask.request'}
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for expression in statement.decorator_list + statement.args.defaults + [x for x in statement.args.kw_defaults if x]:
                    check_calls(expression, env, guarded, authenticated)
                env[statement.name] = {"dynamic": False, "call": ""}
                # A method's unqualified names bypass its class namespace.
                local = dict(function_env if function_env is not None else env)
                for name in local_bindings(statement.body):
                    local[name] = {'dynamic': True, 'call': ''}
                for argument in parameters(statement.args):
                    local[argument.arg] = {"dynamic": True, "call": "", 'parameter': True}
                    if any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in {'route', 'get', 'post', 'put', 'patch', 'delete'}
                           and d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str)
                           and f'<int:{argument.arg}>' in d.args[0].value for d in statement.decorator_list):
                        local[argument.arg].update(dynamic=False, request_input=True, input_line=argument.lineno)
                local['@context'] = {'security_purpose': bool(re.search(r'(?i)password|passwd|secret|token|nonce|csrf|otp|reset', statement.name)),
                                     'html_response': any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                                                          and d.func.attr in {'route', 'get', 'post', 'put', 'patch', 'delete'}
                                                          and facts(d.func.value, env).get('flask_app') for d in statement.decorator_list)}
                # Include schema-independent authentication context, never infer an authorization defect.
                auth = any(isinstance(item, ast.Constant) and item.value == 'Authorization'
                           or isinstance(item, ast.Attribute) and name_of(item) in {'request.user', 'request.session'}
                           or isinstance(item, ast.Name) and item.id == 'current_user' for item in ast.walk(statement))
                auth |= any(binding(item.func if isinstance(item, ast.Call) else item, env).endswith('login_required') for item in statement.decorator_list)
                auth |= any(isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute) and item.func.attr in {'route', 'get', 'post', 'put', 'patch', 'delete'} for item in statement.decorator_list)
                body(statement.body, local, authenticated=auth)
            elif isinstance(statement, ast.ClassDef):
                for expression in statement.decorator_list + statement.bases + [item.value for item in statement.keywords]:
                    check_calls(expression, env, guarded, authenticated)
                body(statement.body, dict(env), function_env=dict(env))
                env[statement.name] = {"dynamic": False, "call": ""}
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                if isinstance(statement, ast.AnnAssign) and statement.value is None:
                    bind(statement.target, {'dynamic': True, 'call': ''}, env)
                if statement.value is not None:
                    check_calls(statement.value, env, guarded, authenticated)
                    value = facts(statement.value, env)
                    for target in statement.targets if isinstance(statement, ast.Assign) else [statement.target]:
                        check_calls(target, env, guarded, authenticated)
                        if isinstance(target, ast.Attribute) and target.attr == 'verify' and facts(target.value, env).get('tls_client') and value.get('literal') is False:
                            emit(target, 'python-tls-verification', 'TLS client peer verification disabled', TRANSPORT, 'Identify affected requests and protected data; unrelated attributes are not TLS policy.')
                        bind(target, value, env)
                        guarded = {item for item in guarded if item[0] != name_of(target) and item[1] != ast.dump(target)}
            elif isinstance(statement, ast.AugAssign):
                check_calls(statement.target, env, guarded, authenticated)
                check_calls(statement.value, env, guarded, authenticated)
                old, value = facts(statement.target, env), facts(statement.value, env)
                bind(statement.target, {**combine_flow([old, value]), "dynamic": old.get('dynamic') or value.get('dynamic'), 'composed': True, 'call': ''}, env)
                guarded = {item for item in guarded if item[0] != name_of(statement.target) and item[1] != ast.dump(statement.target)}
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                local = env
                for item in statement.items:
                    check_calls(item.context_expr, local, guarded, authenticated)
                    if item.optional_vars:
                        bind(item.optional_vars, facts(item.context_expr, local), local)
                body(statement.body, local, guarded, authenticated)
            elif isinstance(statement, ast.If):
                check_calls(statement.test, env, guarded, authenticated)
                left, right = dict(env), dict(env)
                body(statement.body, left, guarded | object_guard(statement.test, env, ast.Eq), authenticated)
                body(statement.orelse, right, guarded, authenticated)
                merge(env, [left, right])
                if terminates(statement.body, env):
                    guarded |= object_guard(statement.test, env, ast.NotEq)
                    test = statement.test
                    if (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and isinstance(test.operand, ast.Call)
                            and isinstance(test.operand.func, ast.Attribute) and test.operand.func.attr == 'is_relative_to'
                            and len(test.operand.args) == 1 and not test.operand.keywords):
                        root = facts(test.operand.args[0], env)
                        if not root.get('request_input'):
                            guarded.add((name_of(test.operand.func.value), ast.dump(test.operand.args[0]), root.get('bound_at')))
                    # Only a terminating rejection of BOTH scheme and fixed host,
                    # followed by redirects disabled, closes this exact URL call.
                    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
                        schemes, hosts = set(), set()
                        for part in test.values:
                            if not isinstance(part, ast.Compare) or len(part.ops) != 1 or not isinstance(part.left, ast.Attribute):
                                continue
                            parsed = facts(part.left.value, env).get('parsed_url')
                            if not parsed:
                                continue
                            choice = facts(part.comparators[0], env)
                            if part.left.attr == 'scheme' and isinstance(part.ops[0], ast.NotEq) and choice.get('literal') == 'https':
                                schemes.add(parsed)
                            allowed = choice.get('elements') or []
                            if part.left.attr == 'hostname' and isinstance(part.ops[0], ast.NotIn) and allowed and all(isinstance(v.get('literal'), str) and v['literal'] for v in allowed):
                                hosts.add(parsed)
                        guarded |= {(name, 'allowed-url') for name in schemes & hosts}
                # A narrow guard suppresses only a normalized path checked in this local block.
                test = statement.test
                if (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn)
                        and isinstance(test.comparators[0], ast.Attribute) and test.comparators[0].attr == 'parents'
                        and any(isinstance(item, (ast.Return, ast.Raise)) for item in statement.body)):
                    root = facts(test.left, env)
                    if not root.get('request_input'):
                        guarded.add((name_of(test.comparators[0].value), ast.dump(test.left), root.get('bound_at')))
            elif isinstance(statement, ast.Try):
                local = dict(env)
                body(statement.body, local, guarded, authenticated)
                alternatives = [local]
                for handler in statement.handlers:
                    alternative = dict(env)
                    body(handler.body, alternative, guarded, authenticated)
                    alternatives.append(alternative)
                body(statement.orelse, local, guarded, authenticated)
                merge(env, alternatives)
                body(statement.finalbody, env, guarded, authenticated)
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                check_calls(statement.iter if hasattr(statement, 'iter') else statement.test, env, guarded, authenticated)
                local = dict(env)
                if hasattr(statement, 'target'):
                    iterator = facts(statement.iter, env)
                    bind(statement.target, {**combine_flow([iterator]), "dynamic": True, "call": ""}, local)
                body(statement.body, local, guarded, authenticated)
                body(statement.orelse, dict(env), guarded, authenticated)
                merge(env, [env.copy(), local])
            else:
                check_calls(statement, env, guarded, authenticated)
                if isinstance(statement, ast.Return) and statement.value is not None:
                    disclosure(statement.value, env, guarded, authenticated)
                    value = facts(statement.value, env)
                    parts = ''.join(value.get('text_parts', []))
                    unsafe_context = bool(re.search(r'(?i)<(?:script|style)\b|\bon\w+\s*=|=', parts))
                    if env.get('@context', {}).get('html_response') and '<' in parts and value.get('request_input') and (value.get('html_input') or unsafe_context):
                        emit(statement.value, 'html-rendering', 'Request content reaches a Flask HTML response', CONTENT,
                             'Verify content type and browser context. HTML escaping protects text nodes but does not establish safety in script, style or URL attributes.')
    body(tree.body, {})
    candidate_positions = {(item['line'], item['column']) for item in signals if item['rule'] == 'python-object-authorization'}
    tasks = [item for item in tasks if (item['line'], item['column']) not in candidate_positions]
    return signals, tasks


def mask_javascript(text):
    """Preserve offsets/newlines while masking comments and quoted text.

    This lexer is deliberately not a full JS/TS parser. Template interpolation and regex
    literals need host review; extracted inline scripts are scanned independently.
    """
    masked = list(text)
    literals = []
    index = 0
    while index < len(text):
        start = index
        if text.startswith('//', index):
            end = re.search(r'[\r\n\u2028\u2029]', text[index:])
            index = len(text) if end is None else index + end.start()
        elif text.startswith('/*', index):
            end = text.find('*/', index + 2)
            index = len(text) if end < 0 else end + 2
        elif text[index] in "\"'`":
            quote = text[index]
            index += 1
            while index < len(text):
                if text[index] == '\\':
                    index += 2
                elif text[index] == quote:
                    index += 1
                    break
                elif quote != '`' and text[index] in '\r\n\u2028\u2029':
                    # Ordinary JS strings cannot span a raw line terminator. This
                    # also prevents JSX text apostrophes masking subsequent lines.
                    break
                else:
                    index += 1
            literals.append((start, min(index, len(text)), text[start:min(index, len(text))]))
        else:
            index += 1
            continue
        for position in range(start, min(index, len(text))):
            if text[position] not in '\r\n\u2028\u2029':
                masked[position] = ' '
    return ''.join(masked), literals


def script_regions(text):
    """Extract executable script content, excluding HTML comments and inert types."""
    regions = []
    starts = [0] + [match.end() for match in re.finditer('\n', text)]

    class Scripts(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.start = None
            self.executable = False
            self.templates = 0

        def position(self):
            line, column = self.getpos()
            return starts[line - 1] + column

        def handle_starttag(self, tag, attrs):
            if tag == 'template':
                self.templates += 1
            if tag == 'script':
                selected = dict(attrs).get('type', '').strip().lower().split(';')[0]
                self.executable = not self.templates and selected in {'', 'module', 'text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript'}
                self.start = self.position() + len(self.get_starttag_text())

        def handle_endtag(self, tag):
            if tag == 'template':
                self.templates = max(0, self.templates - 1)
            if tag == 'script' and self.start is not None:
                if self.executable:
                    regions.append((self.start, text[self.start:self.position()]))
                self.start = None

    Scripts().feed(text)
    return regions


def inspect_javascript(text, html=False):
    regions = []
    if html:
        regions.extend(script_regions(text))
    else:
        regions.append((0, text))
        _, literals = mask_javascript(text)
        for start, end, literal in literals:
            regions.extend((start + 1 + position, content) for position, content in script_regions(literal[1:-1]))
    signals, seen = [], set()
    for offset, source in regions:
        masked, literals = mask_javascript(source)

        def emit(position, rule, title, family, detail):
            line = len(re.findall(r'\r\n|[\r\n\u2028\u2029]', text[:offset + position])) + 1
            if (line, rule) not in seen:
                seen.add((line, rule))
                signals.append({"line": line, "rule": rule, "title": title, "family": family,
                                "method": "JavaScript lexical source triage", "detail": detail})

        patterns = [
            (r'\b(?:eval|new\s+Function)\s*\(', 'js-dynamic-code', 'Dynamic JavaScript evaluation', INPUT),
            (r'\b(?:child_process\s*\.\s*exec|execSync)\s*\(', 'js-shell', 'Shell execution needs input tracing', INPUT),
            (r'\brejectUnauthorized\s*:\s*false\b', 'js-tls-verification', 'TLS peer verification disabled', TRANSPORT),
        ]
        for pattern, rule, title, family in patterns:
            for match in re.finditer(pattern, masked):
                emit(match.start(), rule, title, family, 'Inspect caller input, runtime controls and actual consequence.')
        for match in re.finditer(r'(?:\.(?:innerHTML|outerHTML)\s*=|\.insertAdjacentHTML\s*\(|\bdangerouslySetInnerHTML\b)', masked):
            remainder = source[match.end():]
            # Only a single literal RHS assignment is excluded. Concatenation remains a signal.
            constant = re.match(r'''\s*(["'])(?:\\.|(?!\1).)*?\1\s*(?:;|$)''', remainder, re.S) if '=' in match.group() else None
            if not constant:
                emit(match.start(), 'html-rendering', 'HTML rendering sink', CONTENT, 'Determine render context, data origin and effective sanitization.')
        for match in re.finditer(r'\b(?:fetch|axios\.(?:get|post|request))\s*\(([^,;\n]+)', masked):
            argument = match.group(1).strip()
            raw_argument = source[match.start(1):match.end(1)]
            constant_url = re.fullmatch(r'''\s*(["'])(?:\\.|(?!\1).)*\1\s*\)?\s*''', raw_argument, re.S)
            if not argument or constant_url:
                continue
            # Exact local URL-object guard pattern. This never clears a coverage family.
            variable = re.fullmatch(r'([A-Za-z_$][\w$]*)\s*\)?', argument)
            # Guards in a previous sibling block cannot suppress this call.
            prefix = re.split(r'[{}]', masked[:match.start()])[-1]
            guarded = False
            if variable:
                name = re.escape(variable.group(1))
                guard = re.search(r'if\s*\([^;{}]*\b' + name + r'\.origin\s*!==[^;{}]*\)\s*return\b[^;]*\b403\b[^;]*;', prefix)
                end = masked.find(';', match.start())
                end = len(masked) if end < 0 else end
                options = masked[match.start():end]
                redirect = re.search(r'\bredirect\s*:', options)
                no_redirects = bool(redirect and re.match(r'''\s*(["'])error\1''', source[match.start() + redirect.end():end]))
                reassigned = guard and re.search(r'\b' + name + r'(?:\.[\w$]+)?\s*=(?!=)', prefix[guard.end():])
                conjunction = guard and '&&' in guard.group()
                guarded = bool(guard and no_redirects and not reassigned and not conjunction)
            if not guarded:
                emit(match.start(), 'js-outbound-input', 'Variable URL reaches an outbound client', SSRF, 'Check exact allowed origins, DNS/address handling and redirects. A variable URL alone is not SSRF proof.')
    return signals
