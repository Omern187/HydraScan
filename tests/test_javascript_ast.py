"""Inert AST/flow cases and fallback contracts; application strings never run."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'skills/hydrascan/scripts/hydrascan_javascript.py'
spec = importlib.util.spec_from_file_location('javascript_ast_tests', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class JavaScriptFallbackTests(unittest.TestCase):
    def test_missing_node_retains_candidates_and_explicit_gap(self):
        signals, gaps, tasks = module.inspect_project({'route.js': 'eval(request.query.code)'}, node='hydrascan-nonexistent-node')
        self.assertEqual([s['rule'] for s in signals], ['js-dynamic-code'])
        self.assertEqual(signals[0]['backend'], 'lexical-fallback')
        self.assertEqual(signals[0]['proof_state'], 'candidate')
        self.assertEqual(gaps[0]['rule'], 'js-ast-unavailable')
        self.assertEqual(tasks, [])

    def test_timeout_retains_only_lexical_evidence(self):
        with patch.object(module, '_run', side_effect=subprocess.TimeoutExpired('node', 1)):
            signals, gaps, _ = module.inspect_project({'a.js': 'eval(value)'})
        self.assertEqual(gaps[0]['rule'], 'js-ast-timeout')
        self.assertEqual(signals[0]['backend'], 'lexical-fallback')

    def test_excluded_source_is_not_silently_analyzed(self):
        with patch.object(module, '_run') as run:
            signals, gaps, _ = module.inspect_project({'large.js': 'eval(input)'}, max_source_bytes=2)
        run.assert_not_called()
        self.assertEqual(signals, [])
        self.assertEqual(gaps[0]['backend'], 'none')

    def test_invalid_bridge_evidence_falls_back(self):
        invalid = {'schema_version': 1, 'available': True, 'signals': [{}], 'gaps': [], 'tasks': []}
        with patch.object(module, '_run', return_value=invalid):
            signals, gaps, _ = module.inspect_project({'a.js': 'eval(value)'})
        self.assertEqual(signals[0]['backend'], 'lexical-fallback')
        self.assertEqual(gaps[0]['rule'], 'js-ast-unavailable')

    def test_invalid_bounds_rejected(self):
        for value in [True, 0, -2, 'all', float('nan'), float('inf'), float('-inf')]:
            with self.assertRaises(ValueError):
                module.inspect_project({'a.js': ''}, max_nodes=value)


class JavaScriptAstTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = os.environ.get('HYDRASCAN_JS_PARSER_ROOT')
        info = module.doctor(parser_root=cls.runtime)
        if not info['available']:
            raise unittest.SkipTest('Optional pinned Babel parser unavailable; fallback tests still run')

    def inspect(self, sources, **options):
        result = module.inspect_project(sources, parser_root=self.runtime, **options)
        self.assertFalse(any(g['rule'] == 'js-ast-unavailable' for g in result[1]), result[1])
        return result

    def rules(self, source, path='a.js'):
        return {s['rule'] for s in self.inspect({path: source})[0]}

    def test_real_templates_regex_and_quoted_examples(self):
        source = r'''const example = "eval(req.query.code)";
const pattern = /eval\(req.query.code\)/;
const inert = `literal eval(req.query.code)`;
element.innerHTML = `<section>${`<b>${req.query.label}</b>`}</section>`;'''
        signals, _, _ = self.inspect({'page.js': source})
        self.assertEqual([s['rule'] for s in signals], ['html-rendering'])
        self.assertEqual(signals[0]['line'], 4)
        self.assertEqual(signals[0]['backend'], 'babel-ast')

    def test_ts_module_helper_argument_and_return_flow(self):
        sources = {
            'util.ts': 'export function compose(value: string): string { return `<b>${value}</b>`; }',
            'route.ts': 'import { compose as format } from "./util.js";\nexport function route(req: any, res: any) { const body = format(req.query.name); res.send(body); }',
        }
        signals, _, _ = self.inspect(sources)
        self.assertEqual([s['rule'] for s in signals], ['js-response-rendering'])
        self.assertTrue(any(t['path'] == 'util.ts' for t in signals[0]['trace']))
        sources['route.ts'] = sources['route.ts'].replace('req.query.name', '"fixed"')
        self.assertEqual(self.inspect(sources)[0], [])

    def test_imported_execution_alias_and_argument_array_control(self):
        source = '''const { exec: launch, execFile: runFile } = require('node:child_process');
launch('tool ' + req.query.name);
runFile('tool', [req.query.name]);'''
        signals, _, _ = self.inspect({'process.cjs': source})
        self.assertEqual([s['rule'] for s in signals], ['js-shell'])
        self.assertEqual(signals[0]['line'], 2)
        self.assertEqual(self.rules('function custom(eval, value) { return eval(value); }'), set())
        self.assertIn('js-shell', self.rules("import { spawn } from 'child_process'; spawn('tool', [req.query.name], {shell: true});"))

    def test_jsx_escaped_children_and_explicit_raw_html(self):
        source = '''export function Label({text}: {text: string}) { return <strong>{text}</strong>; }
export function Raw({text}: {text: string}) { return <div dangerouslySetInnerHTML={{__html: text}} />; }'''
        signals, _, _ = self.inspect({'view.tsx': source})
        self.assertEqual([s['rule'] for s in signals], ['html-rendering'])
        self.assertEqual(signals[0]['line'], 2)

    def test_known_sanitizer_binding_and_unknown_filter(self):
        safe = "import purifier from 'dompurify'; element.innerHTML = purifier.sanitize(req.query.html);"
        self.assertEqual(self.rules(safe), set())
        self.assertIn('html-rendering', self.rules(safe.replace("'dompurify'", "'custom-filter'")))

    def test_eval_alias_and_local_function_shadow(self):
        source = '''const interpret = eval;
interpret(req.query.code);
function safe(eval, value) { return eval(value); }
safe(value => value, req.query.code);'''
        signals, _, _ = self.inspect({'a.js': source})
        self.assertEqual([s['rule'] for s in signals], ['js-dynamic-code'])
        self.assertEqual(signals[0]['line'], 2)

    def test_origin_guard_is_review_task_and_reassignment_invalidates_it(self):
        source = '''const target = new URL(req.query.url);
if (target.origin !== 'https://example.invalid') throw Error('origin');
fetch(target, {redirect: 'error'});'''
        signals, _, tasks = self.inspect({'a.js': source})
        self.assertEqual(signals, [])
        self.assertEqual([t['rule'] for t in tasks], ['js-outbound-control-review'])
        self.assertNotIn('proof_state', tasks[0])
        changed = source.replace('fetch(target', 'target = new URL(req.query.other);\nfetch(target')
        self.assertIn('js-outbound-input', self.rules(changed))
        changed = source.replace('fetch(target', 'target.href = req.query.other;\nfetch(target')
        self.assertIn('js-outbound-input', self.rules(changed))

    def test_html_only_executable_scripts_and_original_offsets(self):
        source = '''<!-- <script>eval(req.query.no)</script> -->
<script type="application/ld+json">{"example": "eval(req.query.no)"}</script>
<template><script>eval(req.query.no)</script></template>
<script>eval(req.query.code)</script>'''
        signals, _, _ = self.inspect({'index.html': source})
        self.assertEqual([s['rule'] for s in signals], ['js-dynamic-code'])
        self.assertEqual((signals[0]['line'], signals[0]['column']), (4, 9))

    def test_parse_failure_fallback_does_not_affect_valid_sibling(self):
        signals, gaps, _ = self.inspect({'broken.ts': 'const value: = ; eval(input);', 'valid.js': 'const data="eval(input)";'})
        self.assertTrue(any(g['rule'] == 'js-parse-error' and g['path'] == 'broken.ts' for g in gaps))
        self.assertEqual([s['path'] for s in signals], ['broken.ts'])
        self.assertEqual(signals[0]['backend'], 'lexical-fallback')

    def test_framework_script_types_and_skipped_markup_gap(self):
        for extension in ['vue', 'svelte']:
            source = '<div>{@html request.body.html}</div>\n<script lang="ts">const input: string = request.body.code; eval(input);</script>'
            signals, gaps, _ = self.inspect({'view.' + extension: source})
            self.assertEqual([s['rule'] for s in signals], ['js-dynamic-code'])
            self.assertEqual(signals[0]['backend'], 'babel-ast')
            self.assertTrue(any(g['rule'] == 'js-embedded-markup-coverage' for g in gaps))

    def test_search_parameter_instance_flow_and_text_control(self):
        source = '''function display(target) {
 const params = new URLSearchParams(window.location.search);
 const value = params.get('name');
 target.innerHTML = `<em>${`<b>${value}</b>`}</em>`;
}'''
        self.assertIn('html-rendering', self.rules(source))
        self.assertEqual(self.rules(source.replace('innerHTML', 'textContent')), set())
        self.assertEqual(self.rules(source.replace('window.location.search', "'name=static'")), set())

    def test_destructured_component_props_through_parameter_lookup(self):
        source = '''export function Widget({search}: {search: string}) {
 const value = new URLSearchParams(search).get('name') || '';
 return <article dangerouslySetInnerHTML={{__html: value}} />;
}'''
        self.assertIn('html-rendering', self.rules(source, 'widget.tsx'))
        self.assertEqual(self.rules(source.replace('<article dangerouslySetInnerHTML={{__html: value}} />', '<article>{value}</article>'), 'widget.tsx'), set())

    def test_sql_module_return_bind_call_and_driver_parameter_controls(self):
        sources = {
            'builder.ts': 'export function query(term: string) { return `SELECT name FROM things WHERE term = ${term}`; }',
            'route.ts': '''import {query as make} from './builder';
export async function handler(req: any) {
 const execute = db.query.bind(db);
 return await execute(make(req.query.term));
}''',
        }
        signals, gaps, _ = self.inspect(sources)
        self.assertEqual([s['rule'] for s in signals], ['js-sql-composition'])
        self.assertEqual(signals[0]['path'], 'route.ts')
        self.assertTrue(any(t['path'] == 'builder.ts' for t in signals[0]['trace']))
        self.assertTrue(any(g['rule'] == 'js-sql-receiver-policy' for g in gaps))
        self.assertEqual(signals[0]['proof_state'], 'candidate')
        for expression in ['db.query.call(db, statement)', 'db.query.apply(db, [statement])']:
            self.assertIn('js-sql-composition', self.rules("const statement = 'SELECT ' + req.query.term; " + expression))
        for expression in ["db.query('SELECT name FROM things WHERE term = $1', [req.query.term])",
                           "db.execute({sql: 'SELECT name FROM things WHERE term = ?', values: [req.query.term]})",
                           "db.query({text: 'SELECT name FROM things WHERE term = $1', values: [req.query.term]})"]:
            self.assertNotIn('js-sql-composition', self.rules(expression))
        sources['builder.ts'] = "export function query(term: string) { return ['SELECT name FROM things WHERE term = $1', [term]]; }"
        sources['route.ts'] = sources['route.ts'].replace('return await execute(make(req.query.term));', 'const [text, params] = make(req.query.term); return await execute(text, params);')
        self.assertEqual(self.inspect(sources)[0], [])

    def test_object_spread_and_assign_unknown_properties_preserve_flow(self):
        for source in [
            'const value = {...req.body}; target.innerHTML = value.html;',
            'const value={}; Object.assign(value, req.body); target.innerHTML=value.html;',
            'const first={...req.body}; const value={html:"fixed",...first}; target.innerHTML=value.html;',
        ]:
            self.assertIn('html-rendering', self.rules(source))
        self.assertEqual(self.rules('const value={...req.body,html:"fixed"}; target.innerHTML=value.html;'), set())
        self.assertEqual(self.rules('const value={}; Object.assign(value,req.body,{html:"fixed"}); target.innerHTML=value.html;'), set())

    def test_custom_sanitizer_options_need_review_and_retain_input(self):
        for options in ['req.body.options', '{allowedTags:["script"]}']:
            source = "import sanitize from 'sanitize-html'; target.innerHTML=sanitize(req.query.html," + options + ');'
            signals, _, tasks = self.inspect({'a.js': source})
            self.assertEqual([s['rule'] for s in signals], ['html-rendering'])
            self.assertTrue(any(t['rule'] == 'js-sanitizer-configuration-review' for t in tasks))
        self.assertEqual(self.rules("import sanitize from 'sanitize-html'; target.innerHTML=sanitize(req.query.html,{});"), set())

    def test_conditional_url_alias_mutation_cannot_preserve_guard(self):
        source = '''const u = new URL(req.query.url);
if (u.origin !== 'https://allowed.invalid') throw Error('denied');
if (req.query.x) { u.hostname = req.query.host; }
fetch(u,{redirect:'error'});'''
        self.assertIn('js-outbound-input', self.rules(source))
        self.assertIn('js-outbound-input', self.rules(source.replace('if (req.query.x) { u.hostname', 'const alias=u; if (req.query.x) { alias.hostname')))
        control=source.replace("if (req.query.x) { u.hostname = req.query.host; }", '')
        self.assertEqual(self.inspect({'a.js':control})[0], [])
        self.assertIn('js-outbound-input', self.rules(control.replace("'https://allowed.invalid'", 'req.query.expected')))
        safe_or=control.replace("u.origin !== 'https://allowed.invalid'", "u.origin !== 'https://allowed.invalid' || u.pathname !== '/public'")
        self.assertEqual(self.inspect({'a.js':safe_or})[0], [])
        unknown="function handler(input,allowed){const u=new URL(input);if(u.origin!==allowed)return;fetch(u,{redirect:'error'});}"
        self.assertIn('js-outbound-input', self.rules(unknown))
        runtime="const allowed=JSON.parse(require('fs').readFileSync(process.argv[2])).origin;"+control.replace("'https://allowed.invalid'",'allowed')
        self.assertEqual(self.inspect({'a.js':runtime})[0], [])
        self.assertTrue(any(t['rule']=='js-outbound-control-review' for t in self.inspect({'a.js':runtime})[2]))
        loop=control.replace("fetch(u", "while(req.query.more){u.hostname=req.query.host;} fetch(u")
        self.assertIn('js-outbound-input', self.rules(loop))

    def test_html_response_scripts_keep_original_escaped_literal_positions(self):
        import json
        html='<div id="x"></div><script>target.innerHTML = new URL(location.href).searchParams.get("q");</script>'
        source='''function send(res, body, type = 'text/plain') {
 res.writeHead(200, {'Content-Type':type}); res.end(body);
}
send(res, '''+json.dumps(html)+''', 'text/html');'''
        signals, _, _ = self.inspect({'server.js':source})
        self.assertEqual([s['rule'] for s in signals], ['html-rendering'])
        original=source.index('target.innerHTML')
        self.assertEqual(signals[0]['line'], source.count('\n',0,original)+1)
        self.assertEqual(signals[0]['column'], original-source.rfind('\n',0,original))
        self.assertEqual(signals[0]['embedded_context'], 'literal served HTML script')
        self.assertEqual(self.inspect({'server.js':source.replace('innerHTML', 'textContent')})[0], [])
        badge=html.replace('new URL(location.href).searchParams.get("q")', '"<strong>Fixed</strong>"')
        self.assertEqual(self.inspect({'server.js':source.replace(json.dumps(html),json.dumps(badge))})[0], [])
        self.assertEqual(self.inspect({'server.js':source.replace("'text/html');", "'text/plain');")})[0], [])
        inert='<!--<script>eval(location.search)</script>--><script type="application/ld+json">{"code":"eval(location.search)"}</script>'
        self.assertEqual(self.inspect({'server.js':source.replace(json.dumps(html),json.dumps(inert))})[0], [])
        dynamic=source.replace(json.dumps(html),'req.query.html')
        signals,gaps,_=self.inspect({'server.js':dynamic})
        self.assertIn('js-response-rendering',{s['rule'] for s in signals})
        self.assertTrue(any(g['rule']=='js-html-content-gap' for g in gaps))

    def test_literal_conditional_response_and_raw_bound_query(self):
        self.assertEqual(self.rules("response.end(error ? 'error' : 'ok');"), set())
        self.assertIn('js-response-rendering', self.rules("response.end(error ? req.query.message : 'ok');"))
        self.assertIn('js-sql-composition', self.rules("const execute=db.raw.bind(db); execute('SELECT '+req.query.value);"))
        self.assertNotIn('js-sql-composition', self.rules("const execute=db.raw.bind(db); execute('SELECT ?',[req.query.value]);"))

    def test_node_runtime_executable_and_mutation(self):
        source="const {spawnSync}=require('child_process'); spawnSync(process.execPath,['-e','process.exit(0)',req.query.value]);"
        self.assertEqual(self.rules(source), set())
        self.assertIn('js-process-command', self.rules('process.execPath=req.query.executable;'+source))

    def test_unknown_receiver_parameter_bound_method_keeps_query_identity(self):
        source='''export async function lookup(req: Request,res: Response,db: any) {
 const value=String(req.query.value ?? '');
 const sql=`SELECT title FROM documents WHERE label = '${value}'`;
 const query=db.raw.bind(db);
 return res.json(await query(sql));
}'''
        signals,gaps,_=self.inspect({'handler.ts':source})
        self.assertEqual([s['rule'] for s in signals], ['js-sql-composition'])
        self.assertTrue(any(g['rule']=='js-sql-receiver-identity' for g in gaps))
        self.assertEqual(signals[0]['proof_state'],'candidate')
        control=source.replace("const sql=`SELECT title FROM documents WHERE label = '${value}'`;", "const sql='SELECT title FROM documents WHERE label = ?';").replace('query(sql)', 'query(sql,[value])')
        self.assertEqual(self.inspect({'handler.ts':control})[0], [])
        for expression in ['db.raw.call(db,sql)', 'db.raw.apply(db,[sql])']:
            forwarded=source.replace('query(sql)',expression)
            self.assertIn('js-sql-composition',{s['rule'] for s in self.inspect({'handler.ts':forwarded})[0]})

    def test_recursive_flow_and_node_bound_are_explicit(self):
        _, gaps, _ = self.inspect({'a.js': 'function recurse(value) { return recurse(value); } recurse(req.query.x);'})
        self.assertTrue(any(g['rule'] == 'js-call-bound' for g in gaps))
        signals, gaps, _ = self.inspect({'a.js': 'eval(req.query.x);'}, max_nodes=2)
        self.assertTrue(any(g['rule'] == 'js-resource-bound' for g in gaps))
        self.assertEqual(signals[0]['backend'], 'lexical-fallback')

    def test_options_and_analyzed_strings_are_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'should-not-exist'
            import json
            source = "require('fs').writeFileSync(" + json.dumps(str(marker)) + ", 'bad');"
            self.inspect({'inert.cjs': source})
            self.assertFalse(marker.exists())
        signals, _, _ = self.inspect({'a.js': "import https from 'https'; https.get('https://example.invalid', {rejectUnauthorized: false});"})
        self.assertEqual([s['rule'] for s in signals], ['js-tls-verification'])


if __name__ == '__main__':
    unittest.main()
