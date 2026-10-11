"""Security candidates and counterexamples; snippets are parsed, never executed."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/hydrascan/scripts'))
import hydrascan


class DetectionUpgrade(unittest.TestCase):
    def analyze(self, source, name='case.py'):
        with tempfile.TemporaryDirectory(prefix='hs-detection-') as folder:
            root = Path(folder)
            (root / name).write_text(source, encoding='utf-8')
            return hydrascan.analyze(root, [{'path': name}])

    def rules(self, source, name='case.py'):
        return {item['rule'] for item in self.analyze(source, name)[0]}

    def test_credential_forms_and_artifact_values(self):
        fake = 'fixture-sensitive-value-7390184'
        forms = {
            'case.py': f'SECRET_KEY = "{fake}"\nAWS_SECRET_ACCESS_KEY = "{fake}"\nSIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\\n{fake}\\n-----END RSA PRIVATE KEY-----"\nDATABASE_URL = "postgres://alice:{fake}@localhost/demo"\n',
            'config.yml': f'db:\n  password: {fake}\nservices:\n  db:\n    environment:\n      - POSTGRES_PASSWORD={fake}\n',
            'config.ini': f'[db]\npassword = {fake}\n',
            'config.properties': f'db.password={fake}\n',
            'bootstrap.sh': f'export API_KEY="{fake}"\n',
            'Containerfile': f'FROM python:3\nENV API_KEY="{fake}"\n',
        }
        for name, source in forms.items():
            with self.subTest(name=name):
                candidates, gaps, tasks = self.analyze(source, name)
                self.assertIn('embedded-credential', {c['rule'] for c in candidates})
                self.assertNotIn(fake, json.dumps([candidates, gaps, tasks]))

    def test_credential_comments_prompts_and_environment_are_clear(self):
        for name, source in {
            'case.py': '# SECRET_KEY="fixture-sensitive-value-7390184"\nDOC = \'password="fixture-sensitive-value-7390184"\'\npassword="Enter your password to continue"\nFORM={"password":"Password must be at least 12 characters"}\nimport os\nSECRET_KEY=os.environ["SECRET_KEY"]\n',
            'config.json': '{"password":"Password is required", "api_key":"Paste the key from your dashboard"}',
            'config.yml': '# password: fixture-sensitive-value-7390184\npassword: ${DATABASE_PASSWORD}\n',
            'config.ini': 'password = ${DATABASE_PASSWORD}\n',
            'bootstrap.sh': '# API_KEY="fixture-sensitive-value-7390184"\n',
            'settings.js': '// API_KEY="fixture-sensitive-value-7390184"\n',
        }.items():
            with self.subTest(name=name):
                self.assertNotIn('embedded-credential', self.rules(source, name))

    def test_parser_aliases_and_shadowed_receivers(self):
        for module, method in [('marshal', 'loads'), ('jsonpickle', 'decode')]:
            with self.subTest(module=module):
                self.assertIn('python-deserialization', self.rules(f'import {module} as p\ndef load(body):\n    return p.{method}(body)\n'))
                self.assertNotIn('python-deserialization', self.rules(f'import {module} as p\ndef load(p, body):\n    return p.{method}(body)\n'))
        self.assertNotIn('python-deserialization', self.rules('import json\ndef load(body):\n    return json.loads(body)\n'))

    def test_explicit_xml_entity_policy(self):
        source = 'from lxml import etree as xml\ndef load(body):\n    parser=xml.XMLParser(resolve_entities=True, no_network=True)\n    return xml.fromstring(body, parser)\n'
        self.assertIn('python-xml-external-entities', self.rules(source))
        self.assertNotIn('python-xml-external-entities', self.rules(source.replace('resolve_entities=True', 'resolve_entities=False')))
        self.assertNotIn('python-xml-external-entities', self.rules(source.replace('def load(body):', 'def load(body, xml):')))

    def test_jwt_options_alias_and_verified_control(self):
        source = 'import jwt as tokens\ndef identity(raw):\n    policy={"verify_signature":False}\n    return tokens.decode(raw, options=policy)["sub"]\n'
        self.assertIn('python-jwt-unverified', self.rules(source))
        self.assertNotIn('python-jwt-unverified', self.rules(source.replace('False', 'True')))
        self.assertNotIn('python-jwt-unverified', self.rules(source.replace('def identity(raw):', 'def identity(raw, tokens):')))

    def test_security_context_weak_hash_and_random(self):
        self.assertIn('python-weak-crypto', self.rules('import hashlib as hashes\ndef hash_password(value):\n    return hashes.md5(value.encode()).hexdigest()\n'))
        self.assertNotIn('python-weak-crypto', self.rules('import hashlib\ndef checksum(value):\n    return hashlib.md5(value).hexdigest()\n'))
        self.assertIn('python-weak-random', self.rules('import random as rng\ndef reset_token():\n    return "".join(rng.choice("0123456789") for _ in range(20))\n'))
        self.assertNotIn('python-weak-random', self.rules('import random\ndef simulate():\n    return random.choice([1,2,3])\n'))
        self.assertNotIn('python-weak-random', self.rules('import secrets\ndef reset_token():\n    return secrets.token_urlsafe(24)\n'))

    def test_tls_client_setting_and_unrelated_attribute(self):
        source = 'import requests\ndef fetch():\n    client=requests.Session()\n    client.verify=False\n    return client.get("https://example.invalid").text\n'
        self.assertIn('python-tls-verification', self.rules(source))
        self.assertNotIn('python-tls-verification', self.rules(source.replace('client.verify=False', 'client.verify=True')))
        self.assertNotIn('python-tls-verification', self.rules('def f(widget):\n    widget.verify=False\n'))

    def test_flask_debug_receiver(self):
        self.assertIn('python-debug-exposure', self.rules('from flask import Flask\napp=Flask(__name__)\napp.run(host="0.0.0.0", debug=True)\n'))
        self.assertNotIn('python-debug-exposure', self.rules('def f(app):\n    app.run(debug=True)\n'))
        self.assertNotIn('python-debug-exposure', self.rules('from flask import Flask\napp=Flask(__name__)\napp.run(debug=False)\n'))

    def test_redirect_destination_and_literal(self):
        self.assertIn('python-open-redirect', self.rules('from flask import request, redirect\ndef login():\n    return redirect(request.args["next"])\n'))
        self.assertNotIn('python-open-redirect', self.rules('from flask import redirect\ndef login():\n    return redirect("/home")\n'))

    def test_manual_archive_output_path_and_fixed_output(self):
        source = 'import zipfile\ndef unpack(file):\n    with zipfile.ZipFile(file) as archive:\n        for member in archive.namelist():\n            with open("/srv/data/"+member, "wb") as output:\n                output.write(archive.read(member))\n'
        self.assertIn('python-archive-extraction', self.rules(source))
        self.assertNotIn('python-archive-extraction', self.rules(source.replace('"/srv/data/"+member', '"/srv/data/fixed.txt"')))

    def test_flask_html_text_context_and_escape(self):
        source = 'from flask import Flask, request\nfrom markupsafe import escape\napp=Flask(__name__)\n@app.get("/hello")\ndef hello():\n    name=request.args["name"]\n    if not name:\n        return "empty"\n    return "<h1>"+name+"</h1>"\n'
        self.assertIn('html-rendering', self.rules(source))
        self.assertNotIn('html-rendering', self.rules(source.replace('"<h1>"+name+', '"<h1>"+escape(name)+')))
        self.assertNotIn('html-rendering', self.rules(source.replace('@app.get("/hello")\n', '')))

    def test_html_escape_does_not_protect_script_context(self):
        source = 'from flask import Flask, request\nfrom markupsafe import escape\napp=Flask(__name__)\n@app.get("/")\ndef page():\n    return "<script>const x="+escape(request.args["x"])+";</script>"\n'
        self.assertIn('html-rendering', self.rules(source))

    def test_markup_fixed_escaped_and_mixed_input(self):
        self.assertIn('html-rendering', self.rules('from markupsafe import Markup\ndef mark(value):\n    return Markup(value)\n'))
        self.assertNotIn('html-rendering', self.rules('from markupsafe import Markup, escape\ndef mark(value):\n    return Markup(escape(value))\n'))
        self.assertIn('html-rendering', self.rules('from markupsafe import Markup, escape\ndef mark(value, other):\n    return Markup(escape(value)+other)\n'))
        self.assertNotIn('html-rendering', self.rules('from markupsafe import Markup\ndef mark():\n    return Markup("<b>fixed</b>")\n'))

    def test_mass_assignment_keys_and_fixed_field_control(self):
        source = 'from flask import request\nfrom flask_login import current_user\ndef profile():\n    for key,value in request.get_json().items():\n        setattr(current_user,key,value)\n'
        self.assertIn('python-mass-assignment', self.rules(source))
        self.assertNotIn('python-mass-assignment', self.rules(source.replace('setattr(current_user,key,value)', 'setattr(current_user,"display_name",value)')))
        self.assertNotIn('python-mass-assignment', self.rules(source.replace('def profile():', 'def profile(current_user):')))
