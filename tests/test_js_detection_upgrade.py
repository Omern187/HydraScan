"""Inert source strings: candidate recall, safe pairs and misleading controls."""
import importlib.util
import os
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'skills/hydrascan/scripts/hydrascan_javascript.py'
SPEC = importlib.util.spec_from_file_location('js_detection_upgrade', PATH)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class JavaScriptDetectionUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = os.environ.get('HYDRASCAN_JS_PARSER_ROOT')
        if not module.doctor(parser_root=cls.runtime)['available']:
            raise unittest.SkipTest('Optional pinned Babel parser unavailable')

    def inspect(self, source):
        sources = source if isinstance(source, dict) else {'route.js': source}
        signals, gaps, tasks = module.inspect_project(sources, parser_root=self.runtime)
        self.assertFalse(any(g['rule'] in {'js-ast-unavailable', 'js-parse-error', 'js-resource-bound'} for g in gaps), gaps)
        self.assertTrue(all(s['proof_state'] == 'candidate' and s['backend'] == 'babel-ast' for s in signals))
        return signals, gaps, tasks

    def rules(self, source):
        return {s['rule'] for s in self.inspect(source)[0]}

    def test_fs_import_alias_destructure_and_promise_variants(self):
        for source in [
            "const fs=require('node:fs'); fs.readFile('/data/'+req.query.name);",
            "const {unlinkSync:remove}=require('fs'); remove(req.params.name);",
            "import {readFile as read} from 'node:fs/promises'; read(req.query.file);",
            "import fs from 'fs'; fs.promises.writeFile(req.body.file, 'fixed');",
            "const fs=require('fs'); fs.createReadStream(req.query.file);",
        ]:
            with self.subTest(source=source):
                self.assertIn('js-path-input', self.rules(source))
        for source in [
            "const fs=require('fs'); fs.readFile('/data/public.txt');",
            "const fs={readFile(value){return value}}; fs.readFile(req.query.file);",
            "const text=\"fs.readFile(req.query.file)\"; // fs.unlink(req.body.name)",
        ]:
            self.assertNotIn('js-path-input', self.rules(source))

    def test_fs_helpers_keep_cross_module_input_and_sink_positions(self):
        signals, _, _ = self.inspect({
            'file.ts': "import {readFile} from 'fs/promises';\nexport function read(name:string){return readFile('/data/'+name);}",
            'route.ts': "import {read} from './file.js'; read(req.query.name);",
        })
        signal = next(s for s in signals if s['rule'] == 'js-path-input')
        self.assertEqual((signal['path'], signal['line']), ('file.ts', 2))
        self.assertTrue(any(t['path'] == 'route.ts' and t['kind'] == 'source' for t in signal['trace']))

    def test_sendfile_download_and_basename_partial_controls(self):
        for sink in ['res.sendFile', 'res.download', 'res.status(200).sendFile']:
            self.assertIn('js-path-input', self.rules('function route(req,res){'+sink+'(req.query.file);}'))
        prefix = "const fs=require('fs'),path=require('path');"
        control = prefix + "fs.readFile(path.join('/data',path.basename(req.query.name)));"
        signals, _, tasks = self.inspect(control)
        self.assertNotIn('js-path-input', {s['rule'] for s in signals})
        self.assertIn('js-path-control-review', {t['rule'] for t in tasks})
        self.assertIn('not a safety proof', next(t['detail'] for t in tasks if t['rule'] == 'js-path-control-review'))
        for source in [
            prefix + "fs.readFile(path.join('/data',path.basename(req.query.name),req.query.other));",
            prefix + "fs.readFile(path.basename(req.query.name));",
            prefix + "fs.readFile(path.normalize('/data/'+req.query.name));",
            "const fs=require('fs'); function basename(x){return x}; fs.readFile('/data/'+basename(req.query.name));",
        ]:
            self.assertIn('js-path-input', self.rules(source))
        signals, _, tasks = self.inspect(prefix + 'fs.readFile(process.argv[2]);')
        self.assertNotIn('js-path-input', {s['rule'] for s in signals})
        self.assertIn('js-path-runtime-review', {t['rule'] for t in tasks})

    def test_redirect_browser_and_response_variants(self):
        for source in [
            'res.redirect(req.query.next);', 'res.redirect(302,req.query.next);',
            'function route(req,res){res.status(303).redirect(req.body.next);}',
            'window.location.href=location.hash.slice(1);',
            'location.assign(req.query.next);', 'document.location.replace(req.query.next);',
            'const next=new URLSearchParams(location.search).get("next"); window.location.href=next;',
        ]:
            self.assertIn('js-open-redirect', self.rules(source))
        for source in ['res.redirect("/home");', 'location.replace("/home");',
                       'const service={redirect(value){return value}}; service.redirect(req.query.next);']:
            self.assertNotIn('js-open-redirect', self.rules(source))

    def test_url_encoding_and_vague_guards_do_not_prove_redirect_policy(self):
        for source in [
            'res.redirect(encodeURIComponent(req.query.next));',
            'if(req.query.next.startsWith("/")){res.redirect(req.query.next);}',
            'if(isSafe(req.query.next)){window.location.href=req.query.next;}',
        ]:
            self.assertIn('js-open-redirect', self.rules(source))
        self.assertIn('js-url-content', self.rules('document.getElementById("next").href=encodeURIComponent(req.query.next);'))
        self.assertIn('js-url-content', self.rules('const anchor=document.createElement("a"); anchor.href=req.query.next;'))
        self.assertNotIn('js-url-content', self.rules('document.getElementById("next").href="/home";'))
        self.assertNotIn('js-url-content', self.rules('const inventory={href:"/"}; inventory.href=req.query.next;'))

    def test_mongo_operator_values_and_scalar_safe_pairs(self):
        prefix = "const users=req.app.locals.db.collection('users');"
        for query in ['req.body', '{email:req.body.email}', '{...req.body}',
                      '{email:{$ne:req.body.exclude}}', '{email:identity(req.body.email)}']:
            self.assertIn('js-nosql-input', self.rules(prefix+'users.findOne('+query+');'))
        for query in ['{email:"fixed"}', '{email:String(req.body.email)}',
                      '{age:Number(req.body.age)}', '{email:`${req.body.email}`}',
                      '{email:req.query.x?String(req.body.email):"fallback"}',
                      '{email:{$eq:String(req.body.email)}}']:
            self.assertNotIn('js-nosql-input', self.rules(prefix+'users.findOne('+query+');'))
        self.assertNotIn('js-nosql-input', self.rules('const list={findOne(x){return x}}; list.findOne(req.body);'))
        self.assertNotIn('js-nosql-input', self.rules('custom.findOne(req.body);'))

    def test_mongoose_receiver_and_input_type_sanitizer_name_are_not_proof(self):
        source = "import mongoose from 'mongoose'; const User=mongoose.model('User',schema); User.findOne({email:req.body.email});"
        self.assertIn('js-nosql-input', self.rules(source))
        self.assertNotIn('js-nosql-input', self.rules(source.replace('req.body.email', 'String(req.body.email)')))
        self.assertIn('js-nosql-input', self.rules(source.replace('req.body.email', 'sanitize(req.body.email)')))

    def test_jwt_decode_claim_consumption_preview_and_verify_pairs(self):
        prefix = "const jwt=require('jsonwebtoken'); const claims=jwt.decode(req.headers.authorization.slice(7));"
        for use in ['res.json({user:claims.sub});', 'if(claims.admin){allow();}', 'authorize(claims.roles);']:
            signals, _, _ = self.inspect(prefix+use)
            signal = next(s for s in signals if s['rule'] == 'js-jwt-unverified')
            self.assertTrue(any(t['kind'] == 'decode' for t in signal['trace']))
            self.assertIn('prior verification', signal['detail'])
        for source in [prefix+'res.json(claims);', prefix+'res.json({expires:claims.exp});',
                       prefix.replace('jwt.decode(req.headers.authorization.slice(7))', 'jwt.verify(req.headers.authorization.slice(7),key)')+'res.json({user:claims.sub});',
                       "const decoder={decode(x){return x}}; const claims=decoder.decode(req.body); allow(claims.admin);",
                       "const jwt=require('jsonwebtoken'); const claims=jwt.decode('fixture'); allow(claims.admin);",
                       "const jwt=require('jsonwebtoken'); function preview(token){return jwt.decode(token).sub;}",
        ]:
            self.assertNotIn('js-jwt-unverified', self.rules(source))

    def test_jwt_explicit_policy_pairs(self):
        prefix = "import {verify as check} from 'jsonwebtoken';"
        for options in ["{algorithms:['none']}", '{ignoreExpiration:true}', '{ignoreNotBefore:true}']:
            self.assertIn('js-jwt-policy', self.rules(prefix+'check(req.headers.authorization,key,'+options+');'))
        for options in ["{algorithms:['RS256']}", '{ignoreExpiration:false}', '{ignoreNotBefore:false}']:
            self.assertNotIn('js-jwt-policy', self.rules(prefix+'check(req.headers.authorization,key,'+options+');'))
        self.assertNotIn('js-jwt-policy', self.rules('preview({ignoreExpiration:true});'))

    def test_tls_identity_literal_override_and_shadowed_process_pairs(self):
        for source in ["process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';",
                       "const tls=require('tls'); tls.connect({rejectUnauthorized:false});",
                       "import {Agent as SecureAgent} from 'https'; new SecureAgent({rejectUnauthorized:false});"]:
            self.assertIn('js-tls-verification', self.rules(source))
        for source in ["process.env.NODE_TLS_REJECT_UNAUTHORIZED='1';", 'configure({rejectUnauthorized:false});',
                       "const https={get(x){return x}}; https.get({rejectUnauthorized:false});",
                       "const process={env:{}}; process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';"]:
            self.assertNotIn('js-tls-verification', self.rules(source))

    def test_relative_encoded_query_controls_and_adversarial_url_prefixes(self):
        for value in ["'/api/search?q='+encodeURIComponent(req.query.q)",
                      '`/api/search?q=${encodeURIComponent(req.query.q)}`']:
            signals, _, tasks = self.inspect('fetch('+value+');')
            self.assertNotIn('js-outbound-input', {s['rule'] for s in signals})
            self.assertIn('js-outbound-relative-review', {t['rule'] for t in tasks})
        for value in ["'//external.invalid/?q='+encodeURIComponent(req.query.q)",
                      "'/api/'+encodeURIComponent(req.query.q)", "'/api?q='+req.query.q",
                      "req.query.base+'?q='+encodeURIComponent(req.query.q)",
                      "'https://example.invalid/?q='+encodeURIComponent(req.query.q)"]:
            self.assertIn('js-outbound-input', self.rules('fetch('+value+');'))

    def test_fixed_url_response_data_taint_and_text_content_pair(self):
        source = "async function render(){const response=await fetch('/api/comments'); const body=await response.text(); target.innerHTML=body;} render();"
        self.assertIn('html-rendering', self.rules(source))
        self.assertEqual(self.rules(source.replace('innerHTML', 'textContent')), set())

    def test_repeated_url_composition_stays_bounded_without_clean_claim(self):
        source = 'let url=encodeURIComponent(req.query.q);' + 'url=url+url;' * 40 + 'fetch("/api?q="+url);'
        signals, gaps, _ = self.inspect(source)
        self.assertIn('js-outbound-input', {s['rule'] for s in signals})
        self.assertIn('js-url-composition-bound', {g['rule'] for g in gaps})


class PostDisclosureControlTests(unittest.TestCase):
    """Regression variants added after independent round-two cases were disclosed."""
    @classmethod
    def setUpClass(cls):
        cls.runtime = os.environ.get('HYDRASCAN_JS_PARSER_ROOT')
        if not module.doctor(parser_root=cls.runtime)['available']:
            raise unittest.SkipTest('Optional pinned Babel parser unavailable')

    inspect = JavaScriptDetectionUpgradeTests.inspect
    rules = JavaScriptDetectionUpgradeTests.rules

    def test_finite_literal_map_path_and_redirect_are_partial_review_tasks(self):
        for source, rule, task in [
            ("const paths=new Map([['manual','/srv/public/manual.pdf'],['guide','/srv/public/guide.pdf']]); const selected=paths.get(req.query.name); if(!selected)return; res.sendFile(selected);", 'js-path-input', 'js-path-control-review'),
            ("const routes=new Map([['home','/home'],['profile','/profile']]); const selected=routes.get(req.query.next); if(!selected)return; res.redirect(selected);", 'js-open-redirect', 'js-redirect-control-review'),
        ]:
            source='function route(req,res){'+source+'}'
            signals, _, tasks = self.inspect(source)
            self.assertNotIn(rule, {s['rule'] for s in signals})
            self.assertIn(task, {t['rule'] for t in tasks})
            self.assertIn('not a safety proof', next(t['detail'] for t in tasks if t['rule'] == task))
        source="const routes=new Map([['home','https://service.invalid/home']]); location.replace(routes.get(req.query.next));"
        self.assertNotIn('js-open-redirect', self.rules(source))

    def test_mutations_reassignments_and_escapes_anywhere_invalidate_map_control(self):
        prefix="let routes=new Map([['home','/home']]);"
        sink="res.redirect(routes.get(req.query.next));"
        for mutation in [
            "routes.set('home',req.query.next);", 'routes.delete("home");', 'routes.clear();',
            "routes=new Map([['home',req.query.next]]);", 'const alias=routes; alias.set("home",req.query.next);',
            'retain(routes);', 'exports.routes=routes;', 'const lookup=routes.get;',
            'function later(){routes.set("home",req.query.next);}',
            'function shadow(routes){return routes;}',
            'Map.prototype.get=function(){return req.query.next;};',
        ]:
            with self.subTest(mutation=mutation):
                self.assertIn('js-open-redirect', self.rules(prefix+sink+mutation))
                path_source=(prefix+sink+mutation).replace("'/home'", "'/srv/public/home.pdf'").replace('res.redirect', 'res.sendFile')
                self.assertIn('js-path-input', self.rules(path_source))
        for source in [
            "const routes=new Map([['home',req.query.next]]);"+sink,
            "const routes=new Map([['home','javascript:alert(1)']]);"+sink,
            "const routes=new Map([['home','//external.invalid/']]);"+sink,
            "const routes={get(key){return req.query.next}};"+sink,
        ]:
            self.assertIn('js-open-redirect', self.rules(source))

    def test_exact_http_origin_redirect_partial_control_and_adversarial_guards(self):
        source="function route(req,res){const destination=new URL(req.query.next,'https://service.invalid'); if(destination.origin!=='https://service.invalid')return res.status(400).end(); res.redirect(destination.href);}"
        signals, _, tasks = self.inspect(source)
        self.assertNotIn('js-open-redirect', {s['rule'] for s in signals})
        self.assertIn('js-redirect-control-review', {t['rule'] for t in tasks})
        for altered in [
            source.replace("destination.origin!=='https://service.invalid'", "destination.origin!=='null'"),
            source.replace("destination.origin!=='https://service.invalid'", "destination.origin!=='javascript://service.invalid'"),
            source.replace("destination.origin!=='https://service.invalid'", 'destination.origin!==req.query.allowed'),
            source.replace("destination.origin!=='https://service.invalid'", 'destination.origin!==configuredOrigin'),
            source.replace("destination.origin!=='https://service.invalid'", "destination.origin!=='https://service.invalid' && req.query.reject"),
            source.replace('return res.status(400).end()', 'console.log("denied")'),
            source.replace('res.redirect(destination.href)', 'destination.hostname=req.query.host;res.redirect(destination.href)'),
            source.replace('res.redirect(destination.href)', 'res.redirect(destination.href);function later(){destination.hostname=req.query.host;}'),
            source.replace('res.redirect(destination.href)', 'const alias=destination;res.redirect(destination.href);retain(alias)'),
            source.replace('res.redirect(destination.href)', 'res.redirect(destination.href);destination.searchParams.set("x",req.query.x)'),
            source.replace('res.redirect(destination.href)', 'res.redirect(req.query.other)'),
        ]:
            with self.subTest(source=altered):
                self.assertIn('js-open-redirect', self.rules(altered))

    def test_mutable_map_fixed_key_lookup_preserves_unresolved_content(self):
        for sink, rule, initial in [('res.sendFile', 'js-path-input', '/srv/public/manual.pdf'),
                                    ('res.redirect', 'js-open-redirect', '/home')]:
            prefix="const choices=new Map([['manual',"+repr(initial)+"]]);"
            lookup=sink+"(choices.get('manual'));"
            self.assertNotIn(rule, self.rules(prefix+lookup))
            for mutation in [
                "choices.set('manual',req.query.value);",
                "const alias=choices; alias.set('manual',req.query.value);",
                "function update(map,value){map.set('manual',value)} update(choices,req.query.value);",
                "retain(choices);",
                "function later(){choices.set('manual',req.query.value);}",
            ]:
                with self.subTest(sink=sink, mutation=mutation):
                    signals, gaps, _ = self.inspect(prefix+mutation+lookup)
                    self.assertIn(rule, {s['rule'] for s in signals})
                    self.assertIn('js-map-state-gap', {g['rule'] for g in gaps})
                    self.assertTrue(any('Mutable Map contents' in t['detail'] for s in signals if s['rule'] == rule for t in s['trace']))


if __name__ == '__main__':
    unittest.main()
