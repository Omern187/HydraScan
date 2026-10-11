/* Parse source strings only. Never import, evaluate or execute reviewed code. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {createRequire} = require('node:module');
const {pathToFileURL} = require('node:url');
const METHOD = 'JavaScript Babel AST and bounded local/module call flow';
const INPUT = 'Command, code, and template injection';
const CONTENT = 'XSS and content injection';
const SSRF = 'SSRF and outbound trust';
const FILES = 'Files, paths and archives';
const QUERY = 'SQL and data query injection';
const TRANSPORT = 'Cryptography and transport';
const ACCESS = 'Authentication and recovery';
const PROTOCOL = 'Protocol and header handling';
const MAX_INPUT = 36_000_000;
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const pos = (node) => ({line: node?.loc?.start.line || 1, column: (node?.loc?.start.column || 0) + 1});
const kids = node => Object.entries(node || {}).filter(([key]) => !['loc', 'extra', 'tokens', 'comments', 'errors'].includes(key))
  .flatMap(([, value]) => Array.isArray(value) ? value : [value]).filter(value => value && typeof value.type === 'string');
function walk(node, visit) { const pending = [node]; while (pending.length) {const item = pending.pop(); if (!item) continue; visit(item); pending.push(...kids(item));} }
const nameOf = node => !node ? '' : node.type === 'Identifier' ? node.name :
  ['MemberExpression', 'OptionalMemberExpression'].includes(node.type) ? nameOf(node.object) + '.' + (node.computed ? node.property.value || '?' : node.property.name) : '';
const fixed = value => ({dynamic: false, literal: value, trace: [], clean: []});
const unknown = (trace = []) => ({dynamic: true, trace, clean: []});
const merge = values => ({dynamic: values.some(v => v.dynamic),
  scalar: values.length>0 && values.every(v => v.scalar || !v.dynamic && own(v,'literal') && (v.literal===null || typeof v.literal!=='object')),
  trace: values.flatMap(v => v.trace || []).slice(-24), clean: values.length ? (values[0].clean || []).filter(c => values.every(v => (v.clean || []).includes(c))) : []});
const functionTypes = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod']);

function scriptRegions(html) {
  const regions=[],tags=/<!--[\s\S]*?-->|<\/?([A-Za-z][\w:-]*)\b(?:[^"'<>]|"[^"]*"|'[^']*')*>/g;
  let template=0,match;
  while ((match=tags.exec(html))) {
    const tag=(match[1] || '').toLowerCase(),closing=/^<\//.test(match[0]);
    if (tag==='template') template=Math.max(0,template+(closing?-1:1));
    if (tag!=='script' || closing) continue;
    const end=/<\/script\s*>/gi; end.lastIndex=tags.lastIndex; const close=end.exec(html);
    if (!close) break;
    const attributes=match[0].slice(match[0].search(/\s|>/));
    const attrs=/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
    let selected='',attribute;
    while ((attribute=attrs.exec(attributes))) if(attribute[1].toLowerCase()==='type') selected=(attribute[2]??attribute[3]??attribute[4]??'').trim().toLowerCase().split(';')[0];
    if(!template && ['', 'module','text/javascript','application/javascript','text/ecmascript','application/ecmascript'].includes(selected))
      regions.push({offset:tags.lastIndex,source:html.slice(tags.lastIndex,close.index)});
    tags.lastIndex=end.lastIndex;
  }
  return regions;
}

function literalOffsets(origin,value) {
  const raw=origin.file.source.slice(origin.node.start,origin.node.end), offsets=[];
  let decoded='';
  for(let index=1;index<raw.length-1;) {
    const start=index; let output=raw[index++];
    if(output==='\\') {
      const escaped=raw[index++],simple={n:'\n',r:'\r',t:'\t',b:'\b',f:'\f',v:'\v','0':'\0'};
      if(escaped==='\n' || escaped==='\u2028' || escaped==='\u2029') output='';
      else if(escaped==='\r') {if(raw[index]==='\n') index++; output='';}
      else if(escaped==='x') {output=String.fromCharCode(parseInt(raw.slice(index,index+2),16)); index+=2;}
      else if(escaped==='u') {
        if(raw[index]==='{') {const end=raw.indexOf('}',index); if(end<0)return null; output=String.fromCodePoint(parseInt(raw.slice(index+1,end),16)); index=end+1;}
        else {output=String.fromCharCode(parseInt(raw.slice(index,index+4),16)); index+=4;}
      } else output=own(simple,escaped)?simple[escaped]:escaped;
    }
    decoded+=output;
    for(let unit=0;unit<output.length;unit++) offsets.push(origin.node.start+start);
  }
  return decoded===value ? offsets : null;
}

function positionAt(text,index) {
  const prefix=text.slice(0,index),lines=prefix.split(/\r\n|[\r\n\u2028\u2029]/);
  return {line:lines.length,column:lines[lines.length-1].length+1};
}

function indexAt(text,line,column) {
  const lines=text.split(/\r\n|[\r\n\u2028\u2029]/); let index=0;
  for(let i=0;i<line-1;i++) {
    index+=lines[i]?.length || 0;
    index+=text.slice(index,index+2)==='\r\n'?2:1;
  }
  return index+column-1;
}

function stableBindings(ast) {
  // ponytail: whole-file name identity is conservative across scopes; no alias proof.
  const parents=new WeakMap(), bindings=new Map(), rejected=new Set();
  let nativeMap=true,nativeURL=true;
  walk(ast,node=>{
    for(const child of kids(node)) parents.set(child,node);
    if(node.type!=='VariableDeclarator' || node.id.type!=='Identifier') return;
    const init=node.init;
    if(init?.type!=='NewExpression' || !['Map','URL'].includes(nameOf(init.callee))) return;
    let values=null;
    if(nameOf(init.callee)==='Map') {
      const entries=init.arguments.length===1 && init.arguments[0].type==='ArrayExpression' && init.arguments[0].elements;
      if(!entries?.length || entries.length>64 || !entries.every(entry=>entry?.type==='ArrayExpression' && entry.elements.length===2 && entry.elements.every(value=>value?.type==='StringLiteral'))) return;
      values=entries.map(entry=>entry.elements[1].value);
    }
    if(bindings.has(node.id.name)) rejected.add(node.id.name);
    bindings.set(node.id.name,{node,kind:nameOf(init.callee),values});
  });
  walk(ast,node=>{
    if(node.type!=='Identifier') return;
    const parent=parents.get(node), grandparent=parents.get(parent);
    if(['Map','URL'].includes(node.name) && !(parent?.type==='NewExpression' && parent.callee===node)) {
      if(node.name==='Map') nativeMap=false; else nativeURL=false;
    }
    const binding=bindings.get(node.name);
    if(!binding || binding.node.id===node) return;
    const member=['MemberExpression','OptionalMemberExpression'].includes(parent?.type) && parent.object===node;
    const key=member && (parent.computed ? parent.property.value : parent.property.name);
    if(binding.kind==='Map') {
      if(!member || !['get','has'].includes(key) || !['CallExpression','OptionalCallExpression'].includes(grandparent?.type) || grandparent.callee!==parent) rejected.add(node.name);
    } else if(!member || !['href','origin','pathname','hostname','host','protocol','port','search','hash'].includes(key) ||
        grandparent?.type==='AssignmentExpression' && grandparent.left===parent || ['UpdateExpression','UnaryExpression'].includes(grandparent?.type)) rejected.add(node.name);
  });
  const maps=new Map(),urls=new Set();
  for(const [name,binding] of bindings) if(!rejected.has(name)) {
    if(binding.kind==='Map' && nativeMap) maps.set(binding.node.init.start,binding.values);
    if(binding.kind==='URL' && nativeURL) urls.add(binding.node.init.start);
  }
  return {maps,urls};
}

function analyze(parser, input) {
  const signals = [], gaps = [], tasks = [], fallback_paths = [], parsed_paths = [], modules = new Map(), seen = new Set(), called = new Set();
  const limit = {max_nodes: 150000, max_call_depth: 8, ...input.limits};
  let steps = 0;
  let embeddedCount=0;
  const maxSteps = Math.min(2_000_000, limit.max_nodes * 12);
  function item(file, node, rule, title, family, detail, trace = []) {
    return {path: file.path, ...pos(node), rule, title, family, method: METHOD, backend: 'babel-ast', detail, trace: trace.slice(-24)};
  }
  function gap(file, node, rule, detail) {
    const key = `${file.path}:${pos(node).line}:${rule}`;
    if (seen.has(key)) return; seen.add(key);
    gaps.push(item(file, node, rule, 'JavaScript AST coverage gap', 'Source analysis coverage', detail));
  }
  function step(file, node) { if (++steps > maxSteps) throw new Error('analysis operation bound exceeded'); }
  function evidence(file, node, rule, title, family, fact, detail) {
    if (!fact.dynamic || (family === CONTENT && fact.clean?.includes('html'))) return;
    const key = `${file.path}:${node.start}:${rule}`;
    if (seen.has(key)) return; seen.add(key);
    signals.push(item(file, node, rule, title, family, detail + ' Static candidate; verify reachability, trust boundaries and effective runtime controls.',
      [...fact.trace, {path: file.path, ...pos(node), kind: 'sink', detail: title}]));
  }
  function functionRef(file, node, name) {return {dynamic: false, trace: [], clean: [], fn: {file, node, name}};}
  function invalidateURL(fact,env) {
    if(!fact?.urlKey) return;
    for(const key of [...env.keys()]) if(key.startsWith('$guard:') && env.get(key.slice(7))?.urlKey===fact.urlKey) env.delete(key);
  }
  function embeddedResponse(fact,file,node) {
    if(typeof fact.literal!=='string') {
      gap(file,node,'js-html-content-gap','HTML response content is nonliteral or constructed at runtime; inserted scripts, escaping and template behavior require review.'); return;
    }
    if(!fact.literalOrigin || fact.literal.length>128_000 || input.embedded_depth || embeddedCount>=20) {
      if(/<script\b/i.test(fact.literal)) gap(file,node,'js-html-content-gap','Embedded script origin or analysis budget is unresolved; no embedded-script proof is inferred.');
      return;
    }
    const origin=fact.literalOrigin, offsets=literalOffsets(origin,fact.literal);
    if(!offsets) {gap(file,node,'js-html-content-gap','HTML string escape mapping is outside the supported subset; inspect embedded scripts manually.'); return;}
    for(const region of scriptRegions(fact.literal)) {
      if(++embeddedCount>20) {gap(file,node,'js-html-content-gap','Embedded script count bound reached.'); break;}
      const nested=analyze(parser,{sources:{[origin.file.path]:region.source},limits:limit,embedded_depth:1});
      const mapped=(entry)=>{
        const decodedIndex=region.offset+indexAt(region.source,entry.line,entry.column);
        const absolute=offsets[Math.min(decodedIndex,offsets.length-1)];
        return {...entry,path:origin.file.path,...positionAt(origin.file.source,absolute)};
      };
      for(const [key,destination] of [['signals',signals],['gaps',gaps],['tasks',tasks]]) for(const entry of nested[key]) {
        const translated={...mapped(entry),trace:entry.trace.map(mapped),embedded_context:'literal served HTML script'};
        const identity=`inline:${translated.path}:${translated.line}:${translated.column}:${translated.rule}`;
        if(!seen.has(identity)) {seen.add(identity); destination.push(translated);}
      }
    }
  }
  function resolveModule(file, request) {
    if (!request.startsWith('.')) return null;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(file.path), request));
    for (const candidate of [base, ...['.js','.jsx','.mjs','.cjs','.ts','.tsx','.mts','.cts'].map(e=>base+e), ...['.js','.ts','.tsx','.jsx'].map(e=>base+'/index'+e)]) {
      if (modules.has(candidate)) return modules.get(candidate);
    }
    // TypeScript imports may use runtime .js names while the supplied file is .ts.
    for (const e of ['.ts', '.tsx']) if (modules.has(base.replace(/\.js$/, e))) return modules.get(base.replace(/\.js$/, e));
    return null;
  }
  function imported(file, request, importedName) {
    const target = resolveModule(file, request);
    if (target) {
      const local = target.exports.get(importedName);
      if (local && target.functions.has(local)) return functionRef(target, target.functions.get(local), local);
      return {dynamic: true, trace: [], clean: [], module: target, call: importedName};
    }
    if (request.startsWith('.')) gap(file, file.ast, 'js-unresolved-module', `Relative module ${request} was not supplied; call flow is incomplete.`);
    return {dynamic: false, trace: [], clean: [], call: request.replace(/^node:/, '') + (importedName === '*' || importedName === 'default' ? '' : '.' + importedName)};
  }
  for (const [rawPath, source] of Object.entries(input.sources || {})) {
    const file = {path: rawPath.replace(/\\/g, '/'), source, functions: new Map(), exports: new Map(), env: new Map()};
    try {
      const isTS = /\.(?:[cm]?ts|tsx|vue|svelte)$/i.test(file.path);
      const plugins = [ 'decorators-legacy', ...(isTS ? ['typescript'] : []), ...(/\.(?:jsx|tsx|js|mjs|cjs)$/i.test(file.path) ? ['jsx'] : []) ];
      file.ast = parser.parse(source, {sourceType: 'unambiguous', plugins, errorRecovery: false,
        attachComment: false, createImportExpressions: true});
      let count = 0; walk(file.ast, node => {
        if (++count > limit.max_nodes) throw new Error('AST node bound exceeded');
        if(node.type==='AssignmentExpression' && nameOf(node.left)==='process.execPath') file.execPathMutation=true;
      });
      modules.set(file.path, file); parsed_paths.push(rawPath);
      file.stable=stableBindings(file.ast);
      for (const original of file.ast.program.body) {
        const node = original.declaration || original;
        if (node.type === 'FunctionDeclaration' && node.id) file.functions.set(node.id.name, node);
        if (node.type === 'VariableDeclaration') for (const declaration of node.declarations)
          if (declaration.id.type === 'Identifier' && functionTypes.has(declaration.init?.type)) file.functions.set(declaration.id.name, declaration.init);
        if (original.type === 'ExportDefaultDeclaration' && functionTypes.has(node.type)) {
          const name = node.id?.name || '<default>'; file.functions.set(name, node); file.exports.set('default', name);
        }
        if (original.type === 'ExportNamedDeclaration') {
          if (node.id?.name) file.exports.set(node.id.name, node.id.name);
          if (node.type === 'VariableDeclaration') for (const declaration of node.declarations) if (declaration.id.name) file.exports.set(declaration.id.name, declaration.id.name);
          for (const specifier of original.specifiers || []) file.exports.set(specifier.exported.name || specifier.exported.value, specifier.local?.name);
          if (original.source) gap(file, original, 'js-unresolved-reexport', 'Re-exported call summaries are not resolved.');
        }
      }
    } catch (error) {
      fallback_paths.push(rawPath);
      const rule = /bound/.test(error.message) ? 'js-resource-bound' : 'js-parse-error';
      gaps.push(item(file, {loc: {start: error.loc || {line: 1, column: 0}}}, rule, 'JavaScript parse unavailable', 'Source analysis coverage',
        `${error.reasonCode || error.name}: ${error.message}; lexical fallback only for this file.`));
    }
  }
  function bind(pattern, fact, env, file) {
    if (!pattern) return;
    if (pattern.type === 'Identifier') env.set(pattern.name, fact);
    else if (pattern.type === 'AssignmentPattern') bind(pattern.left, fact, env, file);
    else if (pattern.type === 'RestElement') bind(pattern.argument, fact, env, file);
    else if (pattern.type === 'ObjectPattern') for (const property of pattern.properties) {
      const key = property.key?.name || property.key?.value;
      bind(property.value || property.argument, fact.props?.get(key) || {...fact, call: fact.call ? fact.call + '.' + key : ''}, env, file);
    }
    else if (pattern.type === 'ArrayPattern') for (let i=0;i<pattern.elements.length;i++)
      bind(pattern.elements[i],fact.elements?.[i] || fact,env,file);
  }
  function trace(file, node, kind, detail) {return {path: file.path, ...pos(node), kind, detail};}
  const requestDerived = fact => fact?.trace?.some(entry => entry.kind === 'source' &&
    /(?:req|request)\.(?:query|params|body|headers|cookies)|(?:window\.)?location|document\.cookie/.test(entry.detail));
  const operatorInput = fact => fact?.dynamic && !fact.scalar && (fact.props ?
    [...fact.props.values()].some(operatorInput) || fact.unknownProperties : true);
  function relativeQuery(fact) {
    const parts=fact.urlParts;
    if(!parts?.some(part=>part.dynamic)) return false;
    let prefix='';
    for(const part of parts) {if(part.dynamic) break; if(typeof part.literal!=='string') return false; prefix+=part.literal;}
    return /^\/(?![/\\])[^\\\x00-\x20]*[?#]/.test(prefix) && parts.every(part=>!part.dynamic || part.urlEncoded);
  }
  function redirect(file,node,target,env,title,detail) {
    const origin=[...env].some(([key,policy])=>key.startsWith('$guard:') && policy.literalHTTPOrigin &&
      target.urlHref && target.stableURL && env.get(key.slice(7))?.urlKey===target.urlKey);
    const finite=target.finiteChoices?.every(value=>/^(?:\/(?![/\\])|https?:\/\/)[^\\\x00-\x20]*$/i.test(value));
    if(target.dynamic && (origin || finite)) tasks.push(item(file,node,'js-redirect-control-review','Review redirect destination control',PROTOCOL,
      origin ? 'An exact literal HTTP(S) origin rejection precedes use of the same stable URL href. Verify intended destinations, middleware and runtime URL behavior; this partial control is not a safety proof.' :
      'A request key selects among a finite literal destination map with no observed mutation or escape. Verify intended destinations and runtime policy; this partial control is not a safety proof.',target.trace));
    else evidence(file,node,'js-open-redirect',title,PROTOCOL,target,detail);
  }
  function get(node, env, file, stack) {
    if (!node) return fixed(undefined); step(file, node);
    if (['TSAsExpression','TSTypeAssertion','TSNonNullExpression','TSSatisfiesExpression','ParenthesizedExpression','AwaitExpression','YieldExpression','ChainExpression'].includes(node.type)) return get(node.expression || node.argument, env, file, stack);
    if (node.type !== 'TemplateLiteral' && node.type.endsWith('Literal') || node.type === 'JSXText')
      return {...fixed(node.value), ...(node.type === 'StringLiteral' ? {literalOrigin:{file,node}} : {})};
    if (node.type === 'Identifier') return env.get(node.name) || { ...unknown([trace(file,node,'unresolved',`Unresolved value ${node.name}`)]), call: node.name};
    if (functionTypes.has(node.type)) return functionRef(file, node, node.id?.name || '<callback>');
    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const a=get(node.left,env,file,stack), b=get(node.right,env,file,stack);
      const fact=merge([a,b]), parts=[...(a.urlParts || [a]),...(b.urlParts || [b])];
      if(parts.length>64) gap(file,node,'js-url-composition-bound','URL composition exceeded the bounded part summary; dynamic URL candidates remain eligible.');
      return {...fact, scalar:true, ...(parts.length<=64 ? {urlParts:parts} : {})};
    }
    if (node.type === 'TemplateLiteral') {
      const expressions=node.expressions.map(n=>get(n,env,file,stack)), parts=[];
      if(node.quasis.length+expressions.length<=64)
        node.quasis.forEach((quasi,index)=>{parts.push(fixed(quasi.value.cooked)); if(expressions[index]) parts.push(expressions[index]);});
      else gap(file,node,'js-url-composition-bound','URL template exceeded the bounded part summary; dynamic URL candidates remain eligible.');
      return {...merge(expressions), scalar:true, ...(parts.length ? {urlParts:parts} : {})};
    }
    if (node.type === 'ConditionalExpression') {
      get(node.test,env,file,stack);
      const a=get(node.consequent,env,file,stack),b=get(node.alternate,env,file,stack);
      return a.literal === b.literal && a.literal !== undefined ? a : merge([a,b]);
    }
    if (node.type === 'TaggedTemplateExpression') {
      const fact = get(node.quasi,env,file,stack); const tag = get(node.tag,env,file,stack);
      if (tag.call?.endsWith('html')) evidence(file,node,'js-template-rendering','Dynamic tagged HTML template',CONTENT,fact,'Template escaping depends on the tagged-template implementation.');
      return fact;
    }
    if (node.type === 'ObjectExpression') {
      const props = new Map(), spreads=[];
      for (const prop of node.properties) {
        if (prop.type === 'SpreadElement') {
          const spread = get(prop.argument,env,file,stack); spreads.push(spread);
          if (spread.dynamic && (!spread.props || spread.unknownProperties)) props.clear();
          for (const [k,v] of spread.props || []) props.set(k,v); continue;
        }
        const key = prop.computed ? get(prop.key,env,file,stack).literal : prop.key.name || prop.key.value;
        props.set(key, prop.type === 'ObjectMethod' ? functionRef(file,prop,key) : get(prop.value,env,file,stack));
      }
      return {...merge([...props.values(),...spreads]), props,
        unknownProperties:spreads.some(spread=>spread.dynamic && (!spread.props || spread.unknownProperties))};
    }
    if (['MemberExpression','OptionalMemberExpression'].includes(node.type)) {
      const base = get(node.object,env,file,stack), key = node.computed ? get(node.property,env,file,stack).literal : node.property.name;
      if (base.props?.has(key)) return base.props.get(key);
      if(base.jwtDecoded && ['sub','admin','role','roles','userId','user_id','permissions'].includes(key))
        evidence(file,node,'js-jwt-unverified','Decoded JWT claims used for identity or privilege',ACCESS,base,
          'A request-derived token was decoded without verification in this bounded flow, then identity or privilege claims were read. Check prior verification middleware and how these claims are used; claim access alone does not prove an authentication bypass.');
      if (base.module) {const local=base.module.exports.get(key); if (local && base.module.functions.has(local)) return functionRef(base.module,base.module.functions.get(local),local);}
      const call = base.call ? base.call + '.' + (key || '?') : '';
      const raw = nameOf(node);
      if(raw==='process.execPath' && !env.has('process') && !file.execPathMutation) return fixed('Node runtime executable');
      if (/^(?:req|request)\.(?:query|params|body|headers|cookies)(?:\.|$)|^(?:window\.)?location(?:\.|$)|^document\.cookie$|^process\.argv/.test(raw))
        return {...unknown([trace(file,node,'source',`Request/runtime input ${raw}`)]), call, receiverFact:base};
      return {...base, call, receiverFact:base,
        urlHref:base.url && key==='href',
        searchParams:base.searchParams || (base.url && key === 'searchParams')};
    }
    if (node.type === 'AssignmentExpression') {
      if (node.left.type === 'Identifier') env.delete('$guard:'+node.left.name);
      else if (['MemberExpression','OptionalMemberExpression'].includes(node.left.type) && node.left.object.type === 'Identifier')
        {env.delete('$guard:'+node.left.object.name);invalidateURL(env.get(node.left.object.name),env);}
      const value = get(node.right,env,file,stack);
      if (['MemberExpression','OptionalMemberExpression'].includes(node.left.type)) {
        const key=node.left.computed ? get(node.left.property,env,file,stack).literal : node.left.property.name;
        const target=nameOf(node.left), base=get(node.left.object,env,file,stack);
        if(target==='process.env.NODE_TLS_REJECT_UNAUTHORIZED' && !env.has('process') && ['0',0].includes(value.literal))
          evidence(file,node,'js-tls-verification','TLS peer verification disabled',TRANSPORT,unknown([trace(file,node,'configuration','Explicit process TLS verification override')]),
            'The Node TLS verification environment setting is explicitly disabled. Verify process timing and connection reachability.');
        if(/^(?:window\.|globalThis\.|document\.)?location\.(?:href|search|hash)$/.test(target) && key==='href')
          redirect(file,node,value,env,'Variable browser navigation target','Input reaches browser navigation. Verify protocol and destination policy; no safe destination is inferred from URL encoding.');
        else if(key==='href' && base.domElement) evidence(file,node,'js-url-content','Variable link URL',CONTENT,value,
          'Dynamic href values need protocol and destination validation; HTML escaping or URL encoding alone does not establish a safe URL. Verify the receiver is a navigable link.');
        if (['innerHTML','outerHTML','srcdoc'].includes(key)) evidence(file,node,'html-rendering','HTML rendering sink',CONTENT,value,'Dynamic content reaches an HTML parsing property.');
        if (base.props) base.props.set(key,value);
      } else bind(node.left,value,env,file);
      return value;
    }
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
      const callee = get(node.callee,env,file,stack);
      let args = node.arguments.map(n=>get(n.type==='SpreadElement'?n.argument:n,env,file,stack));
      let call = callee.call || (node.callee.type === 'Identifier' && env.has(node.callee.name) ? '' : nameOf(node.callee));
      if (callee.boundCall) {call=callee.boundCall.call; args=[...callee.boundCall.args,...args];}
      if(node.type==='NewExpression' && call==='Map' && file.stable.maps.has(node.start))
        return {...fixed(undefined), finiteMap:file.stable.maps.get(node.start)};
      if(node.type==='NewExpression' && call==='Map' && !env.has('Map')) {
        gap(file,node,'js-map-state-gap','Map contents are not a stable finite literal binding; mutations, aliases or escapes leave lookup values unresolved, including fixed-key lookups.');
        return unknown([...args.flatMap(arg=>arg.trace),trace(file,node,'unresolved','Mutable Map contents are unresolved')].slice(-24));
      }
      if(callee.receiverFact?.finiteMap && /\.get$/.test(call || nameOf(node.callee)))
        return {...merge(args), finiteChoices:callee.receiverFact.finiteMap,
          trace:[...args.flatMap(arg=>arg.trace),trace(file,node,'control','Finite literal Map lookup; no observed mutation or escape')]};
      if (call === 'require' && !env.has('require') && args.length === 1 && typeof args[0].literal === 'string')
        return imported(file,args[0].literal,'*');
      if (callee.fn) return invoke(callee.fn,args,stack,node,file);
      if (callee.bound) return invoke(callee.bound.fn,[...callee.bound.args,...args],stack,node,file);
      if (call.endsWith('.bind') && ['MemberExpression','OptionalMemberExpression'].includes(node.callee.type)) {
        const original=get(node.callee.object,env,file,stack); if (original.fn) return {...fixed(undefined), bound:{fn:original.fn,args:args.slice(1)}};
        if (original.call) return {...fixed(undefined), boundCall:{call:original.call,args:args.slice(1)}};
        const syntax=nameOf(node.callee.object);
        if (/(?:^|\.)(?:query|execute|raw)$/.test(syntax)) {
          gap(file,node,'js-sql-receiver-identity','A bound query/execute/raw method belongs to an unresolved receiver. Only its method syntax is preserved; driver identity and runtime behavior require review.');
          return {...fixed(undefined),boundCall:{call:syntax,args:args.slice(1)}};
        }
      }
      if (call.endsWith('.call') || call.endsWith('.apply')) {
        const original=get(node.callee.object,env,file,stack);
        const forwarded=call.endsWith('.call')?args.slice(1):args[1]?.elements || [unknown()];
        if (original.fn) return invoke(original.fn,forwarded,stack,node,file);
        if (original.call) {call=original.call; args=forwarded;}
        else if (/(?:^|\.)(?:query|execute|raw)$/.test(nameOf(node.callee.object))) {
          gap(file,node,'js-sql-receiver-identity','An explicitly forwarded query/execute/raw method belongs to an unresolved receiver. Method syntax is retained without assuming a database driver.');
          call=nameOf(node.callee.object); args=forwarded;
        }
      }
      if (['URLSearchParams','window.URLSearchParams','globalThis.URLSearchParams'].includes(call))
        return {...(args[0] || fixed('')), searchParams:true, trace:[...(args[0]?.trace||[]),trace(file,node,'call','URLSearchParams input')]};
      if (callee.searchParams && /\.(?:get|getAll)$/.test(call || nameOf(node.callee)))
        return {...merge([callee.receiverFact || callee,...args]), trace:[...(callee.trace||[]),trace(file,node,'call','URLSearchParams lookup')]};
      if (['dompurify.sanitize','dompurify.default.sanitize','sanitize-html','sanitize-html.default'].includes(call.toLowerCase())) {
        if (args.length > 1 && (args[1].dynamic || !args[1].props || args[1].props.size)) {
          tasks.push(item(file,node,'js-sanitizer-configuration-review','Review custom sanitizer configuration',CONTENT,'Custom sanitizer options were supplied. Verify allowed tags, attributes, protocols and library behavior; taint is retained until the configuration is validated.',args[0]?.trace || []));
          return {...(args[0] || fixed('')), clean:[], trace:[...(args[0]?.trace||[]),trace(file,node,'control-gap','Custom sanitizer configuration is unresolved')]};
        }
        return {...(args[0] || fixed('')), clean:['html'], trace:[...(args[0]?.trace||[]),trace(file,node,'control',`Known HTML sanitizer ${call}`)]};
      }
      if (call === 'Object.assign' && args.length) {
        const target=args[0];
        invalidateURL(target,env);
        if (!target.props) target.props=new Map();
        for (const source of args.slice(1)) {
          if (source.dynamic && (!source.props || source.unknownProperties)) {target.props.clear();target.unknownProperties=true;}
          for (const [key,value] of source.props || []) target.props.set(key,value);
          target.dynamic ||= source.dynamic;
          target.trace=[...target.trace,...source.trace].slice(-24);
        }
        return target;
      }
      if (/^(?:https|tls|axios|request|undici)(?:\.|$)/.test(call) && args.some(value=>value.props?.get('rejectUnauthorized')?.literal === false)) {
        const tlsKey = `${file.path}:${node.start}:js-tls-verification`;
        if (!seen.has(tlsKey)) {
          seen.add(tlsKey);
          signals.push(item(file,node,'js-tls-verification','TLS peer verification disabled',TRANSPORT,'Explicit rejectUnauthorized:false options were observed on a recognized transport API. Static candidate; verify the runtime client, option semantics and connection reachability.'));
        }
      }
      if (/^fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|open|openSync|readdir|readdirSync|stat|statSync|access|accessSync|realpath|realpathSync)$/.test(call) ||
          /^(?:fs\/promises)\.(?:readFile|writeFile|appendFile|unlink|rm|rmdir|open|readdir|stat|access|realpath)$/.test(call) ||
          /\.(?:sendFile|download)$/.test(call) && (callee.receiverFact?.responseKey || /^(?:res|response|reply)\./.test(call))) {
        const target=args[0] || fixed('');
        if(target.dynamic && target.trace.some(entry=>entry.kind==='source' && /process\.argv/.test(entry.detail)) &&
            !target.trace.some(entry=>entry.kind==='parameter' || entry.kind==='source' && !/process\.argv/.test(entry.detail)))
          tasks.push(item(file,node,'js-path-runtime-review','Review command-line filesystem path',FILES,
            'A path comes from process.argv without a remote request source in this bounded flow. Verify the CLI caller and authorized roots; local command-line input alone does not establish a remote path vulnerability.',target.trace));
        else if(target.dynamic && target.finiteChoices) tasks.push(item(file,node,'js-path-control-review','Review finite path selection',FILES,
          'A request key selects among a finite literal path map with no observed mutation or escape. Verify authorized files, symbolic links and runtime policy; this partial control is not a safety proof.',target.trace));
        else if(target.dynamic && target.basenameRooted) tasks.push(item(file,node,'js-path-control-review','Review basename path restriction',FILES,
          'A known path.basename result was joined beneath a literal root. Verify dot names, platform separators, symbolic links and effective containment; this is a partial control, not a safety proof.',target.trace));
        else evidence(file,node,'js-path-input','Variable filesystem path',FILES,target,'Dynamic data reaches a filesystem path. Verify authorized roots, canonical containment, symbolic links and platform path semantics.');
      }
      const responseReceiver=callee.receiverFact?.responseKey || /^(?:res|response|reply)\./.test(call);
      if (/\.redirect$/.test(call) && responseReceiver)
        redirect(file,node,args[0]?.literal !== undefined && typeof args[0].literal==='number' ? args[1] || fixed('') : args[0] || fixed(''),env,'Variable HTTP redirect target',
          'Input reaches an HTTP redirect destination. Verify destination allowlists and protocol-relative URL handling.');
      if (/^(?:(?:window|globalThis|document)\.)?location\.(?:assign|replace)$/.test(call))
        redirect(file,node,args[0] || fixed(''),env,'Variable browser navigation target', 'Input reaches browser navigation. Verify protocol and destination policy.');
      if (/\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments)$/.test(call) &&
          (callee.receiverFact?.mongo || /^(?:mongoose|mongodb)\./.test(call)) && operatorInput(args[0]))
        evidence(file,node,'js-nosql-input','Operator-capable input reaches a document query',QUERY,args[0],
          'A Mongo-style filter includes dynamic values whose scalar types are unresolved. If objects are accepted, query operators may change filter semantics. Verify schema coercion, operator policy and body-parser behavior.');
      if(call==='jsonwebtoken.decode' && requestDerived(args[0]))
        return {...(args[0] || unknown()), jwtDecoded:true, trace:[...(args[0]?.trace || []),trace(file,node,'decode','JWT decoded without verification in this flow')]};
      if(call==='jsonwebtoken.verify') {
        const options=args[2],algorithms=options?.props?.get('algorithms');
        if(options?.props?.get('ignoreExpiration')?.literal===true || options?.props?.get('ignoreNotBefore')?.literal===true || algorithms?.elements?.some(a=>a.literal==='none'))
          evidence(file,node,'js-jwt-policy','JWT verification policy weakened',ACCESS,unknown([...(args[0]?.trace || []),trace(file,node,'configuration','Explicit JWT verification options')]),
            'Known JWT verification options disable time checks or permit the none algorithm. Verify token purpose, library version, key selection and effective authentication policy.');
      }
      if (['eval','Function','globalThis.eval','vm.runInContext','vm.runInNewContext','vm.runInThisContext'].includes(call)) {
        evidence(file,node,'js-dynamic-code','Dynamic JavaScript evaluation',INPUT,merge(args),'Dynamic data reaches a JavaScript interpreter.');
      }
      if (/(?:^|\.)(?:query|execute|raw)$/.test(call)) {
        let query=args[0] || fixed('');
        if (query.props?.has('text')) query=query.props.get('text');
        if (query.props?.has('sql')) query=query.props.get('sql');
        if (query.dynamic) {
          gap(file,node,'js-sql-receiver-policy','A query/execute/raw method received dynamic statement text; the receiver type, driver behavior and runtime query policy are unresolved. Separate parameter values do not sanitize statement text.');
          evidence(file,node,'js-sql-composition','Dynamic SQL statement text','SQL and data query injection',query,'Dynamic data reaches query/execute/raw statement text. Verify receiver API, parameter binding and identifier construction.');
        }
      }
      if (/^(?:child_process|node:child_process)\.(?:exec|execSync)$/.test(call) || ['execSync','exec'].includes(call) && !env.has(call))
        evidence(file,node,'js-shell','Dynamic shell command',INPUT,args[0]||fixed(''),'A shell parses the composed command.');
      if (/^child_process\.(?:execFile|execFileSync|spawn|spawnSync)$/.test(call)) {
        const opts=args.find(a=>a.props?.has('shell'));
        const usesShell=opts?.props.get('shell');
        if (usesShell && (usesShell.dynamic || usesShell.literal !== false)) evidence(file,node,'js-shell','Shell-enabled process execution',INPUT,merge(args),'The process options enable a shell; arguments need shell-context review.');
        else evidence(file,node,'js-process-command','Dynamic process executable',INPUT,args[0]||fixed(''),'Variable executable selection needs review; ordinary bound arguments are not shell composition.');
      }
      if (['fetch','globalThis.fetch','axios','axios.get','axios.post','axios.request','http.get','http.request','https.get','https.request'].includes(call)) {
        let target=args[0]||fixed(''); if (target.props?.has('url')) target=target.props.get('url');
        const guardName=node.arguments[0]?.type==='Identifier'?node.arguments[0].name:null;
        const redirect=args[1]?.props?.get('redirect')?.literal;
        if(relativeQuery(target)) {
          tasks.push(item(file,node,'js-outbound-relative-review','Review relative outbound URL context',SSRF,
            'A literal single-slash URL prefix confines encoded dynamic terms to its query or fragment. Verify runtime base URL, client URL resolution and redirects; no whole-request safety proof is inferred.',target.trace));
        } else if (guardName && env.get('$guard:'+guardName) && redirect==='error') {
          const policy=env.get('$guard:'+guardName);
          tasks.push(item(file,node,'js-outbound-control-review','Review URL allowlist control',SSRF,`Exact URL-origin rejection and redirect:error were observed (${policy.originPolicy || 'literal'}). Verify origin configuration provenance, DNS/address handling and platform behavior; this does not prove the request is safe.`,target.trace));
        } else evidence(file,node,'js-outbound-input','Variable URL reaches an outbound client',SSRF,target,'Check allowed origins, DNS/address handling and redirects. A variable URL alone is not SSRF proof.');
      }
      if (call.endsWith('.insertAdjacentHTML')) evidence(file,node,'html-rendering','HTML rendering sink',CONTENT,args[1]||fixed(''),'Dynamic content reaches insertAdjacentHTML.');
      if (/\.(?:html|write|writeln)$/.test(call)) evidence(file,node,'html-rendering','HTML rendering sink',CONTENT,args[0]||fixed(''),'Verify HTML context and library escaping behavior.');
      const responseKey=callee.receiverFact?.responseKey || (/^(?:res|response|reply)\./.test(call) ? call.split('.')[0] : null);
      if(responseKey) {
        if(/\.writeHead$/.test(call)) {
          const headers=args.find(arg=>arg.props?.has('Content-Type') || arg.props?.has('content-type'));
          if(headers) env.set('$mime:'+responseKey,headers.props.get('Content-Type') || headers.props.get('content-type'));
        } else if(/\.(?:setHeader|header|set)$/.test(call) && String(args[0]?.literal).toLowerCase()==='content-type') env.set('$mime:'+responseKey,args[1] || unknown());
        else if(/\.type$/.test(call)) env.set('$mime:'+responseKey,args[0] || unknown());
        if(/\.(?:send|end)$/.test(call)) {
          const mime=String(env.get('$mime:'+responseKey)?.literal || '').toLowerCase().split(';')[0].trim(),body=args[0] || fixed('');
          if(['text/html','application/xhtml+xml','html'].includes(mime)) {
            embeddedResponse(body,file,node);
            evidence(file,node,'js-response-rendering','Dynamic HTML response content',CONTENT,body,'HTML response content needs output escaping and script-context validation.');
          } else if(!['text/plain','application/json','json','text'].includes(mime))
            evidence(file,node,'js-response-rendering','Dynamic response content',CONTENT,body,'Response content type is unresolved; confirm render context and output escaping.');
        }
      }
      if (/\.(?:render|renderString)$/.test(call)) evidence(file,node,'js-template-interpreter','Dynamic template selection or source',INPUT,args[0]||fixed(''),'Confirm whether the first argument is interpreted template source or an allowlisted template name; bound context data is distinct.');
      if (['setTimeout','setInterval'].includes(call) && !args[0]?.fn) evidence(file,node,'js-dynamic-code','Potential string timer evaluation',INPUT,args[0]||fixed(''),'Verify whether the timer argument is a string or callable.');
      for (const arg of args) if (arg.fn) invoke(arg.fn,null,stack,node,file);
      if (call === 'URL') return {...(args[0]||unknown()), url:true,urlKey:file.path+':'+node.start,stableURL:file.stable.urls.has(node.start)};
      if(/^(?:(?:window|globalThis)\.)?document\.(?:getElementById|querySelector|createElement)$/.test(call))
        return {...unknown([trace(file,node,'source','DOM element values are runtime data')]), domElement:true};
      if (/^path(?:\.(?:posix|win32))?\.basename$/.test(call)) return {...merge(args), basename:true};
      if (/^path(?:\.(?:posix|win32))?\.(?:join|resolve)$/.test(call)) {
        const dynamic=args.filter(arg=>arg.dynamic);
        return {...merge(args), basenameRooted:typeof args[0]?.literal==='string' && /^(?:\/|[A-Za-z]:[\\/])/.test(args[0].literal) &&
          dynamic.length>0 && dynamic.every(arg=>arg.basename)};
      }
      if (/^(?:String|Number|Boolean|JSON\.stringify|encodeURIComponent)$/.test(call)) return {...merge(args), scalar:true, urlEncoded:call==='encodeURIComponent', call:''};
      if (/\.collection$/.test(call) || /^(?:mongoose|mongodb)(?:\.|$)/.test(call))
        return {...merge(args), mongo:true};
      if (['fetch','globalThis.fetch','axios','axios.get','axios.post','axios.request','http.get','http.request','https.get','https.request'].includes(call))
        return {...unknown([trace(file,node,'source','Outbound response data; response schema and trust are unresolved')]), networkResponse:true};
      if(callee.receiverFact?.networkResponse && /\.(?:json|text)$/.test(call))
        return {...unknown(callee.receiverFact.trace), trace:[...callee.receiverFact.trace,trace(file,node,'call','Response body data')]};
      const propagated=[...args,...(callee.receiverFact ? [callee.receiverFact] : [])];
      return {...merge(propagated.length?propagated:[unknown([trace(file,node,'unresolved',`Unresolved return from ${call || 'call'}`)])]),
        ...(callee.receiverFact?.responseKey && /\.(?:status|type|header|set|setHeader)$/.test(call) ? {responseKey:callee.receiverFact.responseKey} : {}),
        trace:[...propagated.flatMap(a=>a.trace||[]),trace(file,node,'call',`Return propagated conservatively through ${call || 'unresolved call'}`)].slice(-24)};
    }
    if (node.type === 'JSXElement' || node.type === 'JSXFragment') {
      const facts=[];
      for (const attr of node.openingElement?.attributes || []) {
        if (attr.type==='JSXSpreadAttribute') {facts.push(get(attr.argument,env,file,stack)); gap(file,attr,'js-jsx-spread','JSX spread attributes may hide rendering sinks; inspect component behavior.'); continue;}
        if (attr.value?.type==='JSXExpressionContainer') {
          const value=get(attr.value.expression,env,file,stack); facts.push(value);
          if (attr.name?.name==='dangerouslySetInnerHTML') evidence(file,attr,'html-rendering','JSX raw HTML rendering',CONTENT,value.props?.get('__html')||value,'Dynamic __html reaches dangerouslySetInnerHTML.');
        }
      }
      for (const child of node.children || []) facts.push(get(child,env,file,stack));
      // Ordinary JSX expression children are escaped by React; they are not raw HTML sinks.
      return merge(facts);
    }
    if (node.type === 'ArrayExpression') {const elements=node.elements.filter(Boolean).map(n=>get(n,env,file,stack)); return {...merge(elements),elements};}
    if (node.type === 'JSXExpressionContainer') return get(node.expression,env,file,stack);
    return merge(kids(node).map(child=>get(child,env,file,stack)));
  }
  function invoke(ref,args,stack,caller,callerFile) {
    const key=ref.file.path+':'+ref.node.start; called.add(key);
    if (stack.includes(key) || stack.length >= limit.max_call_depth) {
      gap(callerFile,caller,'js-call-bound','Recursive or deep helper call exceeded the bounded summary depth.'); return merge(args||[unknown()]);
    }
    const env=new Map(ref.file.env), next=[...stack,key];
    for (let i=0;i<ref.node.params.length;i++) {
      const parameter=ref.node.params[i]; const fact=args ? (args[i]||fixed(undefined)) : unknown([trace(ref.file,parameter,'parameter',`Unresolved caller input ${nameOf(parameter) || 'destructured parameter'}`)]);
      const bound=parameter.type === 'AssignmentPattern' && fact.literal === undefined && !fact.dynamic ? get(parameter.right,env,ref.file,next) : fact;
      const parameterName=parameter.type==='AssignmentPattern'?nameOf(parameter.left):nameOf(parameter);
      bind(parameter,{...bound,...(['res','response','reply'].includes(parameterName)?{responseKey:parameterName}:{}),trace:[...bound.trace,trace(callerFile,caller||ref.node,'call',`Argument ${i+1} enters ${ref.name}`)]},env,ref.file);
    }
    if (ref.node.body.type!=='BlockStatement') return get(ref.node.body,env,ref.file,next);
    const returns=[]; execute(ref.node.body.body,env,ref.file,next,returns);
    const result=returns.length === 1 ? returns[0] : returns.length ? merge(returns) : fixed(undefined);
    return {...result, trace:[...result.trace,trace(ref.file,ref.node,'return',`Return from ${ref.name}`)]};
  }
  function guard(node,env,file,stack) {
    if (node?.type !== 'IfStatement') return;
    const body=node.consequent.type==='BlockStatement'?node.consequent.body:[node.consequent];
    if (!body.length || !['ReturnStatement','ThrowStatement'].includes(body[body.length-1].type) || node.alternate) return;
    const alternatives=[];
    function rejection(test) {
      if(test.type==='LogicalExpression' && test.operator==='||') {rejection(test.left);rejection(test.right);}
      else alternatives.push(test);
    }
    rejection(node.test);
    for(const test of alternatives) {
      if(test.type!=='BinaryExpression' || test.operator!=='!==') continue;
      const left=test.left,right=test.right;
      if(left.type!=='MemberExpression' || left.property.name!=='origin' || left.object.type!=='Identifier') continue;
      if(!env.get(left.object.name)?.url) continue;
      let policy='literal-origin';
      if(right.type!=='StringLiteral') {
        if(right.type!=='Identifier' || !env.has(right.name)) continue;
        const expected=env.get(right.name);
        if(expected.trace.some(entry=>entry.kind==='parameter')) continue;
        if(expected.trace.some(entry=>entry.kind==='source' && /(?:req|request)\.(?:query|params|body|headers|cookies)|(?:window\.)?location|document\.cookie/.test(entry.detail))) continue;
        policy='runtime-origin-binding requires provenance validation';
      }
      let literalHTTPOrigin=false;
      if(right.type==='StringLiteral' && /^https?:\/\//.test(right.value)) {
        try {literalHTTPOrigin=new URL(right.value).origin===right.value;} catch {}
      }
      env.set('$guard:'+left.object.name,{originPolicy:policy,literalHTTPOrigin});
    }
  }
  function execute(nodes,env,file,stack,returns) {
    for (const original of nodes) {
      if (!original) continue; step(file,original); const node=original.declaration||original;
      if (original.type==='ImportDeclaration') continue;
      if (node.type==='FunctionDeclaration') {if(node.id) env.set(node.id.name,functionRef(file,node,node.id.name)); continue;}
      if (node.type==='VariableDeclaration') {
        for (const d of node.declarations) {
          if (d.id.type === 'Identifier') env.delete('$guard:'+d.id.name);
          bind(d.id,get(d.init,env,file,stack),env,file);
        }
      } else if (node.type==='ReturnStatement') {returns.push(get(node.argument,env,file,stack)); break;}
      else if (node.type==='ThrowStatement') {get(node.argument,env,file,stack); break;}
      else if (node.type==='ExpressionStatement') {
        const e=node.expression; if(e.type==='AssignmentExpression' && e.left.type==='Identifier') env.delete('$guard:'+e.left.name);
        get(e,env,file,stack);
      } else if (node.type==='BlockStatement') execute(node.body,env,file,stack,returns);
      else if (node.type==='IfStatement') {
        get(node.test,env,file,stack);
        const a=new Map(env), b=new Map(env);
        execute(node.consequent.type==='BlockStatement'?node.consequent.body:[node.consequent],a,file,stack,returns);
        if(node.alternate) execute(node.alternate.type==='BlockStatement'?node.alternate.body:[node.alternate],b,file,stack,returns);
        for(const key of new Set([...a.keys(),...b.keys()])) {
          if(key.startsWith('$guard:')) {
            if(a.get(key) && b.get(key)) env.set(key,a.get(key));
            else env.delete(key);
            continue;
          }
          const av=a.get(key),bv=b.get(key); if(av&&bv) env.set(key,av===bv?av:merge([av,bv]));
        }
        guard(node,env,file,stack);
      } else if (['ForStatement','ForOfStatement','ForInStatement','WhileStatement','DoWhileStatement','TryStatement','SwitchStatement'].includes(node.type)) {
        gap(file,node,'js-control-flow-summary','Loop/exception/switch flow is conservatively bounded; branch dominance and execution counts are not proved.');
        for(const key of [...env.keys()]) {
          if(key.startsWith('$guard:')) env.delete(key);
          if(key.startsWith('$mime:')) env.set(key,unknown());
        }
        const branch=new Map(env);
        if(node.init) {if(node.init.type==='VariableDeclaration') execute([node.init],branch,file,stack,returns); else get(node.init,branch,file,stack);}
        if(node.right) get(node.right,branch,file,stack); if(node.test) get(node.test,branch,file,stack);
        if(node.left?.type==='VariableDeclaration') for(const d of node.left.declarations) bind(d.id,unknown(),branch,file);
        for(const part of [node.body,node.block,node.handler?.body,node.finalizer]) if(part) execute(part.type==='BlockStatement'?part.body:[part],branch,file,stack,returns);
        for(const c of node.cases||[]) execute(c.consequent,branch,file,stack,returns);
        for(const [key,v] of branch) if(!key.startsWith('$guard:')) env.set(key,env.has(key)?merge([env.get(key),v]):v);
      } else if (node.type==='ClassDeclaration') gap(file,node,'js-class-summary','Class methods, instance dispatch and inheritance are outside the bounded helper summaries.');
      else if (!node.type.startsWith('TS') && !['ExportAllDeclaration','EmptyStatement'].includes(node.type)) get(node,env,file,stack);
    }
  }
  // Initialize all module bindings before evaluation, so supplied imports can summarize helpers.
  for(const file of modules.values()) {
    for(const [name,node] of file.functions) file.env.set(name,functionRef(file,node,name));
    for(const node of file.ast.program.body) if(node.type==='ImportDeclaration') {
      for(const spec of node.specifiers) file.env.set(spec.local.name,imported(file,node.source.value,
        spec.type==='ImportNamespaceSpecifier'?'*':spec.type==='ImportDefaultSpecifier'?'default':spec.imported.name||spec.imported.value));
    }
  }
  try {
    for(const file of modules.values()) execute(file.ast.program.body,file.env,file,[],[]);
    for(const file of modules.values()) for(const [name,node] of file.functions) if(!called.has(file.path+':'+node.start)) invoke({file,node,name},null,[],node,file);
  } catch(error) {
    for(const file of modules.values()) gap(file,file.ast,'js-resource-bound',`Analysis stopped: ${error.message}; partial AST evidence retained.`);
  }
  for(const file of modules.values()) gap(file,file.ast,'js-analysis-limits','Babel parsed this file. Bounded local/module summaries do not establish runtime reachability, types, framework policy, reflection, complete call graphs, sanitizer correctness or whole-program coverage.');
  return {schema_version:1,available:true,signals,gaps,tasks,fallback_paths,parsed_paths};
}

async function main() {
  let raw='';
  for await (const chunk of process.stdin) {raw+=chunk; if(Buffer.byteLength(raw)>MAX_INPUT) throw new Error('JSON input bound exceeded');}
  const input=JSON.parse(raw);
  if(input.schema_version!==1 || typeof input.parser_root!=='string') throw new Error('invalid request schema');
  const [major,minor]=process.versions.node.split('.').map(Number);
  if (!(major === 22 && minor >= 18 || major === 24 && minor >= 11 || major > 24))
    return {schema_version:1,available:false,detail:`Node ${process.versions.node} is unsupported by pinned Babel 8; require ^22.18.0 or >=24.11.0.`};
  const resolver=createRequire(path.join(path.resolve(input.parser_root),'package.json'));
  let parser,version;
  try {
    // Resolution is anchored solely to the optional scanner runtime, never the target.
    const entry=resolver.resolve('@babel/parser');
    const packageEntry=resolver.resolve('@babel/parser/package.json');
    version=JSON.parse(fs.readFileSync(packageEntry,'utf8')).version;
    if(version!=='8.0.7') throw new Error(`Expected pinned @babel/parser 8.0.7; found ${version}`);
    parser=await import(pathToFileURL(entry).href);
  } catch(error) {return {schema_version:1,available:false,version,detail:`Optional Babel parser unavailable: ${error.message}`};}
  if(input.action==='doctor') return {schema_version:1,available:true,version,detail:'Pinned Babel parser available; source strings are parsed without application execution.'};
  if(!input.sources || typeof input.sources!=='object' || Array.isArray(input.sources) || Object.entries(input.sources).some(([p,s])=>typeof s!=='string' || !p)) throw new Error('invalid source map');
  return analyze(parser,input);
}
main().then(result=>process.stdout.write(JSON.stringify(result))).catch(error=>{
  process.stdout.write(JSON.stringify({schema_version:1,available:false,detail:`AST bridge error: ${error.message}`}));
});
