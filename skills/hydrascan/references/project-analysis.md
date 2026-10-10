# Bounded project source analysis

Use this reference when interpreting cross-file candidates, SQL/ORM ownership controls or JavaScript AST availability. Source strings are parsed, never imported or executed as application modules. Native results remain `candidate` or `review-task`; the host reviewers establish actual reachability, policy and consequences.

## Python flow and authorization

`scripts/hydrascan_python_flow.py` follows selected local functions and explicit local imports using call-site argument bindings. Request origins, exact principals and selected object identities propagate through bounded call contexts. Review the `trace`, sink location, operation and `missing_fields`; a helper reached by safe and unsafe callers cannot be cleared by the safe caller alone.

Recognized data forms include literal SQL queries with positional or named bindings, flat equality conjunctions, simple table aliases/joins, declared ownership schemas, Django model managers and selected Flask-SQLAlchemy/SQLAlchemy model/session query forms. `sqlalchemy.text` preserves query-text flow; possible external session and model receivers carry provenance questions rather than assumed runtime identity. Read, response, update, save and delete boundaries require the exact declared owner/tenant controls on the same object. When user and tenant fields are both declared, satisfying one does not satisfy both. Control suppression is limited to the exact sink and observed call contexts; incomplete project analysis withholds suppression.

Dynamic query structure can produce injection candidates. Bound request values are distinguished from query text. Complex predicates, subqueries, disjunctions, comments, exclusions, unsupported ORM operations and unknown policy produce coverage gaps or review tasks. A query using a method named `execute` still needs receiver and database validation by the reviewer. Model or schema ownership observations prioritize review; they do not establish private data or absent external policy.

Admin route names trigger policy review. An observed trusted admin-excluding branch into a write can produce an inversion candidate, with the actual privileged-operation policy explicitly unverified; neither is a confirmed privilege escalation. Review the actual requirement, trusted principal, check order, middleware and permitted privileged operations before deciding whether a missing or ineffective guard is a defect. Dynamic routes, reflection, class dispatch, arbitrary global mutations and framework dispatch are outside the bounded function summaries. Recursive calls and complexity limits remain explicit gaps. Python columns are one-based AST byte offsets.

## Optional JavaScript/TypeScript AST

`scripts/hydrascan_javascript.py` invokes the bundled `hydrascan_js_ast.cjs` with JSON source strings. The bridge uses the pinned `@babel/parser` from HydraScan's own trusted runtime, not application dependencies or parser configuration. It recognizes JS, TS and JSX syntax, selected local/module function flows and input boundaries including dynamic code, shell calls, raw HTML rendering and outbound URLs. Templates, regex literals and JSX text controls are parsed as syntax. Recognized sanitizers and origin/redirect forms remain narrow counterevidence requiring runtime validation.

Install the optional parser explicitly with a compatible Node version from the repository root:

```text
npm ci --prefix skills/hydrascan/scripts/javascript-parser
python skills/hydrascan/scripts/hydrascan.py doctor
```

For a separate installation, use `--js-parser-root /path/to/runtime` with `doctor` and `scan`, or `HYDRASCAN_JS_PARSER_ROOT`. The runtime contains `node_modules`; `--node` or `HYDRASCAN_NODE` selects the executable. No automatic install or source upload occurs. The Python base runner continues without the parser.

Check each result's `backend`: `babel-ast`, `lexical-fallback` or `none`. Missing Node/parser, timeout, parse failure and resource rejection are recorded, and fallback covers only accepted source within its own limited lexical patterns. A missing-parser run must not be reported as AST coverage. Partial AST evidence survives an analysis bound, with its gap retained. Runtime availability is recorded in `run.json`; a successful doctor check does not prove every file parsed successfully.

HTML script extraction preserves original line/column offsets. Inert markup and framework expressions still need separate reviewer coverage. Class dispatch, computed calls, external library semantics, reachability and complete sanitizer behavior remain explicit limitations. JavaScript columns use Babel's one-based character positions and should not be compared directly with Python byte offsets for non-ASCII text.

JS defaults bound accepted source to 1,000,000 bytes per file, 8,000,000 bytes per project and 2,000 files; AST traversal is capped at 150,000 nodes, helper depth at eight and the subprocess at 20 seconds. These analyzer bounds can be narrower than the runner's snapshot bounds; read both inventory exclusions and analysis gaps. Python defaults are 1,000,000 bytes per file, 8,000,000 bytes per project, 1,000 files, 120,000 aggregate AST nodes, 24,000 expression evaluations, call depth six, 160 call contexts and 16 branch states. Source exclusions, context-manager semantics, callbacks, undispatched callers and unsupported paths stay unverified; they withhold legacy-signal suppression when applicable.

## Measure changes honestly

Test distinct reachable code forms and legitimate controls alongside stored regressions. Freeze independently written cases before implementations see them. Save the first pass, code hashes, rule mapping, false positives, misses and unresolved cases. After using failures to improve the engine, report the same cases as regression validation; preserve the original independent score. Candidate detection rates are not confirmed vulnerability counts or a guarantee of coverage on other applications.
