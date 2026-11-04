const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const vm=require('node:vm');
const ts=require(process.env.TYPESCRIPT_LIB||require.resolve('typescript'));
if(ts.version!=='5.9.3')throw Error('Generator requires TypeScript5.9.3');
const core=process.env.PLAYWRIGHT_CORE_DIR;if(!core)throw Error('PLAYWRIGHT_CORE_DIR is required');
if(JSON.parse(fs.readFileSync(path.join(core,'package.json'),'utf8')).version!=='1.64.1')throw Error('Pinned Playwright version mismatch');
const bundle=fs.readFileSync(path.join(core,'lib/coreBundle.js'),'utf8');
const literal=bundle.split('\n').find(line=>/^\s*source\d* = '/.test(line)&&line.includes('packages/injected/src/injectedScript.ts'));
if(!literal)throw Error('Pinned injected source not found');
const raw=vm.runInNewContext(literal.slice(literal.indexOf('=')+1).trim().replace(/;$/,''),{}, {timeout:1000});
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
if(hash(raw)!=='852e40f938e72e6129b6c9a8bde3f4cc6cfe5cecb5ac734b6b06c8ad1fde42bf')throw Error('Pinned Playwright1.64.1 injected source mismatch');
function slice(a,b){const i=raw.indexOf(a),j=raw.indexOf(b,i);if(i<0||j<=i)throw Error('marker');return raw.slice(i,j);}
function func(name){const a=raw.indexOf('function '+name+'('),s=ts.createSourceFile('fn.js',raw.slice(a),ts.ScriptTarget.ESNext,true,ts.ScriptKind.JS);return raw.slice(a,a+s.statements[0].end);}
const evaluator=slice('// packages/injected/src/selectorEvaluator.ts','// packages/injected/src/selectorGenerator.ts');
const layout=slice('// packages/injected/src/layoutSelectorUtils.ts','// packages/injected/src/selectorUtils.ts');
const names=raw.match(/var customCSSNames = .*?;/)[0];
const source=layout+func('parentElementOrShadowHost')+'\n'+func('normalizeWhiteSpace')+'\n'+evaluator+names;
const packetRoot=process.env.RAW_CSS_PACKET_ROOT||path.resolve(__dirname,'../..');
const f=ts.factory,call=(n,args=[])=>f.createCallExpression(f.createIdentifier(n),undefined,args),stmt=n=>f.createExpressionStatement(call(n));
const domReads=new Set(['parentElement','parentNode','host','shadowRoot','firstElementChild','nextElementSibling','previousElementSibling','documentElement','nodeType']);
let functions=0,loops=0,reads=0,atoms=0,rects=0;
const sf=ts.createSourceFile('pinned.js',source,ts.ScriptTarget.ESNext,true,ts.ScriptKind.JS);
const tx=ts.transform(sf,[ctx=>{function visit(node){
 let n=ts.visitEachChild(node,visit,ctx);
 if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)){
   const name=n.expression.name.text;
   if((name==='querySelectorAll'&&ts.isIdentifier(n.expression.expression)&&n.expression.expression.text==='root')||(name==='matches'&&ts.isIdentifier(n.expression.expression)&&n.expression.expression.text==='element')){atoms++;return call(name==='matches'?'__matchesAtom':'__queryAtom',[n.expression.expression,...n.arguments]);}
   if(name==='getBoundingClientRect'){rects++;return call('__rect',[n.expression.expression]);}
 }
 if(ts.isPropertyAccessExpression(n)&&domReads.has(n.name.text)){reads++;return call('__read',[n.expression,f.createStringLiteral(n.name.text)]);}
 if(ts.isForStatement(n)||ts.isForOfStatement(n)||ts.isForInStatement(n)||ts.isWhileStatement(n)||ts.isDoStatement(n)){
  loops++;const b=f.createBlock([stmt('__step'),...(ts.isBlock(n.statement)?n.statement.statements:[n.statement])],true);
  if(ts.isForStatement(n))n=f.updateForStatement(n,n.initializer,n.condition,n.incrementor,b);else if(ts.isForOfStatement(n))n=f.updateForOfStatement(n,n.awaitModifier,n.initializer,n.expression,b);else if(ts.isForInStatement(n))n=f.updateForInStatement(n,n.initializer,n.expression,b);else if(ts.isWhileStatement(n))n=f.updateWhileStatement(n,n.expression,b);else n=f.updateDoStatement(n,b,n.expression);
 }
 if((ts.isFunctionDeclaration(n)||ts.isFunctionExpression(n)||ts.isArrowFunction(n)||ts.isMethodDeclaration(n)||ts.isConstructorDeclaration(n))&&n.body){
  functions++;const body=ts.isBlock(n.body)?n.body:f.createBlock([f.createReturnStatement(n.body)],true);const b=f.createBlock([stmt('__enter'),f.createTryStatement(body,undefined,f.createBlock([stmt('__leave')],true))],true);
  if(ts.isFunctionDeclaration(n))n=f.updateFunctionDeclaration(n,n.modifiers,n.asteriskToken,n.name,n.typeParameters,n.parameters,n.type,b);else if(ts.isFunctionExpression(n))n=f.updateFunctionExpression(n,n.modifiers,n.asteriskToken,n.name,n.typeParameters,n.parameters,n.type,b);else if(ts.isArrowFunction(n))n=f.updateArrowFunction(n,n.modifiers,n.typeParameters,n.parameters,n.type,n.equalsGreaterThanToken,b);else if(ts.isMethodDeclaration(n))n=f.updateMethodDeclaration(n,n.modifiers,n.asteriskToken,n.name,n.questionToken,n.typeParameters,n.parameters,n.type,b);else n=f.updateConstructorDeclaration(n,n.modifiers,n.parameters,b);
 }
 return n;
}return n=>ts.visitNode(n,visit);}]);
const guarded=ts.createPrinter({newLine:ts.NewLineKind.LineFeed}).printFile(tx.transformed[0]);tx.dispose();
const head=`// Copyright (c) Microsoft Corporation. Licensed under the Apache License, Version 2.0.\n// Exact Playwright1.64.1 CSS evaluator/layout semantics with bounded policy hooks.\n// Generated by cli/scripts/generate-native-css-evaluator.cjs; never strip custom pseudos or substitute qSA for the AST.\nfunction createRawCssEvaluator(__policy, __step, __limit, __unavailable) {\n let __depth=0;\n let normalizedWhitespaceCache;\n function __enter(){__step();if(__depth>=256)throw __limit;++__depth;}\n function __leave(){--__depth;}\n for(const key of ['read','queryAtom','matchesAtom','rect','isVisible','textFacts','textMatch','skipText','isIssued','authorizeContext','finishContext'])if(typeof __policy[key]!=='function')throw __unavailable;\n function __receiver(node){if(node===undefined||node===null)throw new Error('Invalid CSS engine receiver');}\n function __read(node,key){__step();__receiver(node);return __policy.read(node,key);}\n function __queryAtom(root,css){__step();__receiver(root);const values=__policy.queryAtom(root,css);if(values==null||typeof values[Symbol.iterator]!=='function')throw __unavailable;const out=[];for(const value of values){__step();if(out.length>=100000)throw __limit;out.push(value);}return out;}\n function __matchesAtom(element,css){__step();__receiver(element);const result=__policy.matchesAtom(element,css);if(typeof result!=='boolean')throw __unavailable;return result;}\n function __rect(element){__step();__receiver(element);const rect=__policy.rect(element);if(!rect)throw __unavailable;return rect;}\n function isElementVisible(element){__step();__receiver(element);const result=__policy.isVisible(element);if(typeof result!=='boolean')throw __unavailable;return result;}\n function shouldSkipForTextMatching(element){__step();__receiver(element);const result=__policy.skipText(element);if(typeof result!=='boolean')throw __unavailable;return result;}\n function elementText(cache,element){__step();__receiver(element);const facts=__policy.textFacts(element);if(facts==null||typeof facts.full!=='string'||typeof facts.normalized!=='string'||!Array.isArray(facts.immediate))throw __unavailable;for(const value of facts.immediate){__step();if(typeof value!=='string')throw __unavailable;}return facts;}\n function elementMatchesText(cache,element,matcher){__step();__receiver(element);const result=__policy.textMatch(element,matcher);if(!['none','self','selfAndChildren'].includes(result))throw __unavailable;return result;}\n`;
const tail=`\n function __context(context){__step();if(!context||__policy.authorizeContext(context)!==true)throw __unavailable;}\n return {\n  query(context,selector){try{__context(context);const evaluator=new SelectorEvaluatorImpl();const result=evaluator.query(context,selector);for(const element of result){__step();if(element===undefined||element===null)throw new Error('Invalid CSS engine output');if(__policy.isIssued(element)!==true)throw __unavailable;}return result;}finally{__policy.finishContext();}},\n  matches(element,selector,context){try{__context(context);if(__policy.isIssued(element)!==true)throw __unavailable;const evaluator=new SelectorEvaluatorImpl();return evaluator.matches(element,selector,context);}finally{__policy.finishContext();}}\n };\n}\n`;
const output=head+guarded+tail;
const dest=path.join(packetRoot,'cli/src/native/client_observation/selector_css_evaluator.js');fs.writeFileSync(dest,output);
fs.writeFileSync(path.join(packetRoot,'cli/tests/fixtures/native-css-evaluator.manifest.json'),JSON.stringify({upstreamInjectedSha256:hash(raw),upstreamSliceSha256:hash(source),helperSha256:hash(output),functions,loops,domReads:reads,nativeAtoms:atoms,rectCalls:rects,policyAdapterImplemented:true,generatorTypeScript:ts.version},null,2)+'\n');
