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

    def emit(node, rule, title, family, detail):
        key = (node.lineno, rule)
        if key not in seen:
            signals.append({"line": node.lineno, "rule": rule, "title": title, "family": family,
                            "method": "Python AST and local assignment flow", "detail": detail})
            seen.add(key)

    def binding(node, env):
        if isinstance(node, ast.NamedExpr):
            return binding(node.value, env)
        name = name_of(node)
        first, dot, rest = name.partition(".")
        return env.get(first, {}).get("call", first) + (dot + rest if dot else "")

    def facts(node, env):
        if isinstance(node, ast.Name):
            return dict(env.get(node.id, {"dynamic": True, "call": node.id}))
        if isinstance(node, ast.Constant):
            return {"dynamic": False, "call": "", "literal": node.value}
        if isinstance(node, ast.NamedExpr):
            return facts(node.value, env)
        if isinstance(node, ast.Attribute):
            return {**facts(node.value, env), "call": binding(node, env)}
        if isinstance(node, ast.Call):
            target = binding(node.func, env)
            values = [facts(value, env) for value in node.args] + [facts(value.value, env) for value in node.keywords]
            if target == "tarfile.open":
                return {"dynamic": False, "call": "", "tar": True}
            if target in {"pathlib.Path", "Path", "os.path.join"} or target.endswith((".joinpath", ".resolve", ".absolute")):
                base = facts(node.func.value, env) if isinstance(node.func, ast.Attribute) else {}
                return {**base, "dynamic": any(value.get("dynamic") for value in values) or base.get("dynamic", False),
                        "path": True, "normalized": target.endswith(".resolve"), "call": "",
                        "path_segment_dynamic": base.get("path_segment_dynamic", False) or any(value.get("dynamic") for value in values)}
            if target in {"requests.Session", "httpx.Client", "httpx.AsyncClient"}:
                return {"dynamic": False, "call": target.rsplit(".", 1)[0]}
            if target.endswith((".format", ".join")):
                receiver = facts(node.func.value, env) if isinstance(node.func, ast.Attribute) else {}
                return {"dynamic": receiver.get("dynamic", False) or any(value.get("dynamic") for value in values), "composed": True, "call": ""}
            # Safe literal conversion is not evidence for string/query/path containment.
            return {"dynamic": True, "call": ""}
        children = [facts(child, env) for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        path_base = facts(node.left, env) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) else {}
        return {"dynamic": any(child.get("dynamic") for child in children), "call": "",
                "composed": isinstance(node, (ast.JoinedStr, ast.BinOp)),
                "path": isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div),
                "path_root": ast.dump(node.left) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) else None,
                "path_segment_dynamic": path_base.get('path_segment_dynamic', False) or facts(node.right, env).get("dynamic") if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) else False}

    def parameters(arguments):
        return arguments.posonlyargs + arguments.args + arguments.kwonlyargs + [x for x in (arguments.vararg, arguments.kwarg) if x]

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
        # Argument/function expressions may introduce a named expression used by this call.
        for child in ast.iter_child_nodes(node):
            yield from scoped_calls(child, env)
        if isinstance(node, ast.Call):
            yield node, env

    def check_calls(expression, env, guarded, authenticated):
        for node, env in scoped_calls(expression, env):
            target = binding(node.func, env)
            keywords = {item.arg: item.value for item in node.keywords if item.arg}
            literal = lambda key, value: isinstance(keywords.get(key), ast.Constant) and keywords[key].value is value
            if target in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                emit(node, "python-dynamic-code", "Dynamic code evaluation", INPUT, "Follow the argument into the resolved evaluator, including local aliases.")
            elif target in {"os.system", "os.popen"} or (target.startswith("subprocess.") and literal("shell", True)):
                emit(node, "python-shell", "Shell interpreter invocation", INPUT, "Establish whether caller-controlled input reaches the shell.")
            elif target in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "yaml.unsafe_load"}:
                emit(node, "python-deserialization", "Deserialization requiring trusted input", PARSER, "Verify the provenance of serialized data before accepting this signal.")
            elif target == "yaml.load":
                loader = keywords.get("Loader", node.args[1] if len(node.args) > 1 else None)
                if binding(loader, env) not in {"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader"}:
                    emit(node, "python-yaml-loader", "YAML loader needs configuration review", PARSER, "Resolve the selected loader and callers; a loader's local name is insufficient.")
            elif target == "ssl._create_unverified_context" or (target.startswith(("requests.", "httpx.")) and literal("verify", False)):
                emit(node, "python-tls-verification", "TLS peer verification disabled", TRANSPORT, "Identify affected transport and protected data.")

            query_node = node.args[0] if node.args else next((keywords[key] for key in ('query', 'sql', 'statement') if key in keywords), None)
            if target.endswith((".execute", ".executemany", ".executescript", ".raw")) and query_node is not None:
                query = facts(query_node, env)
                if query.get("dynamic") and query.get("composed"):
                    emit(node, "python-sql-composition", "Composed input reaches a query interpreter", SQL, "Query text is assembled before execution; separately inspect bound values, identifiers and permitted SQL builders.")
                raw = query.get("literal")
                if authenticated and isinstance(raw, str) and re.search(r"\bSELECT\b.*\bWHERE\b.*\b(?:id|pk)\s*=", raw, re.I | re.S):
                    where = raw.upper().split("WHERE", 1)[1]
                    if not re.search(r"\b(?:OWNER|USER_ID|TENANT_ID|ACCOUNT_ID)\b", where):
                        tasks.append({"line": node.lineno, "family": AUTH, "rule": "object-ownership-review",
                                      "question": "Authenticated object lookup is keyed by identifier. Verify owner/tenant enforcement in this route, middleware and database policy; public/shared records may be intentional."})
            if target.endswith(".extractall") and isinstance(node.func, ast.Attribute):
                receiver = facts(node.func.value, env)
                selected = facts(keywords.get("filter"), env) if keywords.get("filter") else {}
                if receiver.get("tar") and selected.get("literal") != "data":
                    emit(node, "python-archive-extraction", "Archive extraction needs path/link containment review", FILES, "The locally recognized TAR receiver lacks an explicit data filter; inspect runtime defaults and all output/link boundaries.")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes", "open", "write_text", "write_bytes"}:
                receiver = facts(node.func.value, env)
                checked = (name_of(node.func.value), receiver.get("path_root")) in guarded and receiver.get("normalized")
                if receiver.get("path") and receiver.get("path_segment_dynamic") and not checked:
                    emit(node, "python-path-input", "Composed input reaches a file operation", FILES, "Check canonical path containment, caller-controlled bases, links and overwrite permissions; source triage is not a filesystem sandbox.")
            if target in {"open", "builtins.open"} and node.args:
                path = facts(node.args[0], env)
                checked = (name_of(node.args[0]), path.get("path_root")) in guarded and path.get("normalized")
                if path.get("path") and path.get("path_segment_dynamic") and not checked:
                    emit(node, "python-path-input", "Composed input reaches a file operation", FILES, "Verify canonical containment and the exact allowed root before the operation.")
            if target.startswith(("requests.", "httpx.", "urllib.request.")) and target.endswith((".get", ".post", ".request", ".urlopen")):
                position = 1 if target.endswith('.request') else 0
                url = node.args[position] if len(node.args) > position else keywords.get("url")
                if url is not None and facts(url, env).get("dynamic"):
                    emit(node, "python-outbound-input", "Variable URL reaches an outbound client", SSRF, "Inspect allowed hosts, resolved addresses and redirects on this exact call; variable URLs can be legitimate.")

    def bind(target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                bind(element, {"dynamic": True, "call": ""}, env)

    def merge(env, alternatives):
        for name in set().union(*(scope.keys() for scope in alternatives)):
            values = [scope.get(name, {"dynamic": True, "call": ""}) for scope in alternatives]
            value = {key: any(item.get(key) for item in values) for key in ('dynamic', 'composed', 'path', 'path_segment_dynamic', 'tar')}
            value['normalized'] = all(item.get('normalized') for item in values)
            for key in ('literal', 'path_root'):
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
                    env[alias.asname or alias.name] = {"dynamic": False, "call": '.' * statement.level + statement.module + "." + alias.name}
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for expression in statement.decorator_list + statement.args.defaults + [x for x in statement.args.kw_defaults if x]:
                    check_calls(expression, env, guarded, authenticated)
                env[statement.name] = {"dynamic": False, "call": ""}
                # A method's unqualified names bypass its class namespace.
                local = dict(function_env if function_env is not None else env)
                for argument in parameters(statement.args):
                    local[argument.arg] = {"dynamic": True, "call": ""}
                # Include schema-independent authentication context, never infer an authorization defect.
                auth = any(isinstance(item, ast.Constant) and item.value == 'Authorization'
                           or isinstance(item, ast.Attribute) and name_of(item) in {'request.user', 'request.session'}
                           or isinstance(item, ast.Name) and item.id == 'current_user' for item in ast.walk(statement))
                auth |= any(binding(item.func if isinstance(item, ast.Call) else item, env).endswith('login_required') for item in statement.decorator_list)
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
                        bind(target, value, env)
                        guarded = {item for item in guarded if item[0] != name_of(target)}
            elif isinstance(statement, ast.AugAssign):
                check_calls(statement.target, env, guarded, authenticated)
                check_calls(statement.value, env, guarded, authenticated)
                old, value = facts(statement.target, env), facts(statement.value, env)
                bind(statement.target, {"dynamic": old.get('dynamic') or value.get('dynamic'), 'composed': True, 'call': ''}, env)
                guarded = {item for item in guarded if item[0] != name_of(statement.target)}
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
                body(statement.body, left, guarded, authenticated)
                body(statement.orelse, right, guarded, authenticated)
                merge(env, [left, right])
                # A narrow guard suppresses only a normalized path checked in this local block.
                test = statement.test
                if (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn)
                        and isinstance(test.comparators[0], ast.Attribute) and test.comparators[0].attr == 'parents'
                        and any(isinstance(item, (ast.Return, ast.Raise)) for item in statement.body)):
                    guarded.add((name_of(test.comparators[0].value), ast.dump(test.left)))
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
                    bind(statement.target, {"dynamic": True, "call": ""}, local)
                body(statement.body, local, guarded, authenticated)
                body(statement.orelse, dict(env), guarded, authenticated)
                merge(env, [env.copy(), local])
            else:
                check_calls(statement, env, guarded, authenticated)
    body(tree.body, {})
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
