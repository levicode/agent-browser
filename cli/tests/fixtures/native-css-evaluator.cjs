const fs=require('node:fs'),assert=require('node:assert/strict'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const helperDir=process.argv[2]||path.join(__dirname,'../../src/native/client_observation');
const core=process.env.PLAYWRIGHT_CORE_DIR;assert.ok(core,'PLAYWRIGHT_CORE_DIR must name installed1.64.1');assert.equal(JSON.parse(fs.readFileSync(path.join(core,'package.json'),'utf8')).version,'1.64.1');
const bundle=fs.readFileSync(path.join(core,'lib/coreBundle.js'),'utf8');
const literal=bundle.split('\n').find(line=>/^\s*source\d* = '/.test(line)&&line.includes('packages/injected/src/injectedScript.ts'));
const raw=vm.runInNewContext(literal.slice(literal.indexOf('=')+1).trim().replace(/;$/,''),{}, {timeout:1000});
assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),'852e40f938e72e6129b6c9a8bde3f4cc6cfe5cecb5ac734b6b06c8ad1fde42bf');
const names=raw.match(/var customCSSNames = .*?;/)[0];
const parserSource=raw.slice(raw.indexOf('// packages/isomorphic/cssTokenizer.ts'),raw.indexOf('// packages/isomorphic/selectorParser.ts'))+names;
const parse=new Function(parserSource+';return s=>parseCSS(s,customCSSNames).selector;')();
const source=raw.slice(raw.indexOf('// packages/injected/src/layoutSelectorUtils.ts'),raw.indexOf('// packages/injected/src/selectorUtils.ts'))+func('parentElementOrShadowHost')+'\n'+func('normalizeWhiteSpace')+'\n'+raw.slice(raw.indexOf('// packages/injected/src/selectorEvaluator.ts'),raw.indexOf('// packages/injected/src/selectorGenerator.ts'))+names;
function func(name){const a=raw.indexOf('function '+name+'(');let j=raw.indexOf('{',a),n=0;for(;j<raw.length;j++){if(raw[j]==='{')n++;if(raw[j]==='}'&&!--n)break;}return raw.slice(a,j+1);}
const makeEvaluator=new Function(fs.readFileSync(path.join(helperDir,'selector_css_evaluator.js'),'utf8')+';return createRawCssEvaluator;')();
const makePolicy=new Function(fs.readFileSync(path.join(helperDir,'selector_css_policy.js'),'utf8')+';return createRawCssPolicy;')();
class Node {
 constructor(id,tag='DIV',type=1){Object.assign(this,{id,nodeName:tag,nodeType:type,parentNode:null,ownerDocument:null,childNodes:[],shadowRoot:null,text:'',visible:true,box:{left:0,top:0,right:20,bottom:20,width:20,height:20}});}
 append(...nodes){for(const n of nodes){n.parentNode=this;n.assignDocument(this.nodeType===9?this:this.ownerDocument);this.childNodes.push(n);}return this;}
 assignDocument(doc){this.ownerDocument=doc;for(const c of this.childNodes)c.assignDocument(doc);if(this.shadowRoot)this.shadowRoot.assignDocument(doc);}
 get parentElement(){return this.parentNode?.nodeType===1?this.parentNode:null;}
 get firstChild(){return this.childNodes[0]||null;}
 get nextSibling(){const a=this.parentNode?.childNodes||[];return a[a.indexOf(this)+1]||null;}
 get previousSibling(){const a=this.parentNode?.childNodes||[];return a[a.indexOf(this)-1]||null;}
 get firstElementChild(){return this.childNodes.find(n=>n.nodeType===1)||null;}
 get nextElementSibling(){let n=this.nextSibling;while(n&&n.nodeType!==1)n=n.nextSibling;return n;}
 get previousElementSibling(){const a=this.parentNode?.childNodes||[];return a.slice(0,a.indexOf(this)).reverse().find(n=>n.nodeType===1)||null;}
 get documentElement(){return this.nodeType===9?this.firstElementChild:undefined;}
 get children(){return this.childNodes.filter(n=>n.nodeType===1);}
 matches(css){if(css==='*')return true;if(css[0]==='#')return this.id===css.slice(1);if(css==='.row')return this.id==='a'||this.id==='b';if(css==='.row:nth-child(1 of :scope)')return this.id==='b';if(css==='[id="a"]')return this.id==='a';if(/^[a-z]+$/.test(css))return this.nodeName===css.toUpperCase();throw Error('Fixture native CSS atom not implemented: '+css);}
 querySelectorAll(css){const out=[];function visit(n){for(const c of n.childNodes){if(c.nodeType===1&&c.matches(css))out.push(c);visit(c);}}visit(this);return out;}
 getBoundingClientRect(){return this.box;}
}
const doc=new Node('doc','#document',9),html=new Node('html','HTML'),body=new Node('body','BODY'),section=new Node('section','SECTION'),a=new Node('a'),beta=new Node('beta','SPAN'),b=new Node('b'),shown=new Node('shown','BUTTON'),hidden=new Node('hidden','BUTTON'),host=new Node('host'),shadow=new Node('shadow','#shadow-root',11),inside=new Node('inside','SPAN');
doc.append(html);html.append(body);body.append(section);section.append(a,b,shown,hidden,host);a.text='Alpha ';beta.text='Beta';a.append(beta);b.text='Alpha Beta';shown.text='Save';hidden.text='Save';hidden.visible=false;shadow.mode='open';shadow.host=host;shadow.assignDocument(doc);host.shadowRoot=shadow;shadow.append(inside);inside.text='shadow';shown.box={left:40,right:60,top:0,bottom:20,width:20,height:20};hidden.box={left:0,right:20,top:40,bottom:60,width:20,height:20};
function nodes(root,out=[]){out.push(root);for(const child of root.childNodes)nodes(child,out);if(root.shadowRoot)nodes(root.shadowRoot,out);return out;}
const authorized=new Set(nodes(doc)),issued=new Set([...authorized].filter(n=>n.nodeType===1)),denied=new Set(),protectedNodes=new Set();let allowDocument=true;let calls=[],work=0,cap=1000000;
const limit={},unavailable={};const step=()=>{if(++work>cap)throw limit;};
const normalize=s=>s.replace(/[\u200b\u00ad]/g,'').trim().replace(/\s+/g,' ');
function facts(e){let full=e.text;for(const c of e.childNodes)full+=facts(c).full;if(e.shadowRoot)full+=facts(e.shadowRoot).full;return{full,normalized:normalize(full),immediate:e.text?[e.text]:[]};}
const oracleTextMatch=new Function('Node','elementText','shouldSkipForTextMatching',func('elementMatchesText')+';return elementMatchesText;')({ELEMENT_NODE:1},(cache,e)=>facts(e),()=>false);
const authority={document:doc,isAuthorizedNode:n=>authorized.has(n)&&!denied.has(n),isAuthorizedRoot:n=>allowDocument&&(n===doc||n===shadow),isIssued:n=>issued.has(n),textFacts:e=>protectedNodes.has(e)?null:facts(e),textMatch:(e,m)=>protectedNodes.has(e)?'protected':oracleTextMatch(new Map(),e,m),isVisible:e=>e.visible,skipText:()=>false};
const native={read(n,key){calls.push(['read',n.id,key]);assert.ok(!denied.has(n),'no read before authorization');return n[key];},querySelectorAll(n,css){calls.push(['qsa',n.id,css]);return n.querySelectorAll(css);},matches(n,css){calls.push(['matches',n.id,css]);return n.matches(css);},rect:n=>n.getBoundingClientRect()};
const policy=makePolicy(authority,native,step,limit,unavailable),actual=makeEvaluator(policy,step,limit,unavailable);
const parseCandidate=new Function(fs.readFileSync(path.join(helperDir,'selector_css_parser.js'),'utf8')+';return createRawCssParser;')()(step,limit);
const Oracle=new Function('elementText','elementMatchesText','shouldSkipForTextMatching','isElementVisible','normalizedWhitespaceCache',source+';return SelectorEvaluatorImpl;')((cache,e)=>facts(e),oracleTextMatch,()=>false,e=>e.visible,undefined);
function outcome(fn){try{return{ids:fn().map(e=>e.id)}}catch(e){if(e===limit)return{private:'limit'};if(e===unavailable)return{private:'unavailable'};return{name:e.name,message:e.message};}}
const cssCases=['.row:has-text("Alpha")','.row:text("Alpha")','.row:text-is("Alpha Beta")','.row:text-matches("^Alpha Beta$")','button:visible',':nth-match(.row,2)',':is(#b,#a)',':where(.row)',':not(button)','#a:has(span)',':scope',':scope > .row',':light(span)','#inside',':is(#inside,#a)',':nth-match(:is(#b,#a),1)',':not(:text("Gamma"))','#shown:right-of(#a)','#a:left-of(#shown)','#shown:above(#hidden)','#hidden:below(#a)','#a:near(#shown,50)','.row:nth-child(1 of :scope)',':is()',':has()',':text()',':text-is(1)',':text-matches("[")',':has-text()',':visible(1)',':nth-match(.row,0)',':nth-match(.row,"2")',':right-of()',':scope(1)'];
let cases=0,parserRejected=0;
for(const css of cssCases)for(const scope of [doc,section]){
 let ast;try{ast=parse(css);}catch{parserRejected++;continue;}const ctx={scope,pierceShadow:true};work=0;calls=[];const expected=outcome(()=>new Oracle().query(ctx,ast));const observed=outcome(()=>actual.query(ctx,parseCandidate(css).selector));assert.deepEqual(observed,expected,css+' @'+scope.id);assert.throws(()=>policy.read(doc,'nodeType'),e=>e===unavailable,'proof revoked after query');cases++;
}
let matchCases=0;
for(const css of ['.row:has-text("Alpha")','.row:text("Alpha")','.row:text-is("Alpha Beta")','.row:text-matches("^Alpha Beta$")',':is(#a,#b)',':not(#b)'])for(const element of [a,b]){work=0;const ast=parse(css),ctx={scope:section,pierceShadow:true};assert.equal(actual.matches(element,parseCandidate(css).selector,ctx),new Oracle().matches(element,ast,ctx),css+' matches '+element.id);matchCases++;}
work=0;calls=[];actual.query({scope:doc,pierceShadow:true},parse(':is(#a,#a)'));assert.equal(calls.filter(c=>c[0]==='qsa'&&c[2]==='#a').length,2,'one cached atom per light root, not per duplicate branch');
work=0;calls=[];actual.query({scope:doc,pierceShadow:true},parse(':is(#a,#a)'));assert.equal(calls.filter(c=>c[0]==='qsa'&&c[2]==='#a').length,2,'fresh perquery cache, no proof reuse across calls');
for(const [css,ids]of [['.row:has-text("Alpha")',['a','b']],['.row:text("Alpha")',['a','b']],['.row:text-is("Alpha Beta")',['b']],['.row:text-matches("^Alpha Beta$")',['a','b']],['button:visible',['shown']],[':nth-match(.row,2)',['b']]]){work=0;assert.deepEqual(actual.query({scope:doc,pierceShadow:true},parseCandidate(css).selector).map(e=>e.id),ids,'six original observations '+css);}
work=0;calls=[];actual.query({scope:doc,pierceShadow:true},parse('.row:nth-child(1 of :scope)'));assert.ok(calls.some(c=>c[0]==='qsa'&&c[2]==='.row:nth-child(1 of :scope)'),'nativeCSS atom stays qSA, not per-element matches');
for(const css of ['.row:text-is("Alpha Beta")',':not(:has-text("secret"))']){protectedNodes.add(a);work=0;assert.throws(()=>actual.query({scope:doc,pierceShadow:true},parse(css)),e=>e===unavailable,'protected text never guesses even negated');protectedNodes.clear();}
denied.add(beta);work=0;calls=[];assert.throws(()=>actual.query({scope:doc,pierceShadow:true},parse('button')),e=>e===unavailable);assert.equal(calls.some(c=>c[0]==='qsa'),false);denied.clear();
allowDocument=false;work=0;calls=[];assert.throws(()=>actual.query({scope:section,pierceShadow:true},parse('.row')),e=>e===unavailable,'Elementscope grants no ownerdoc authority');assert.equal(calls.some(c=>c[0]==='qsa'),false);allowDocument=true;
const wrong=new Node('wrong');authorized.add(wrong);work=0;assert.throws(()=>actual.query({scope:wrong,pierceShadow:true},parse('*')),e=>e===unavailable,'wrong/disconnected root');authorized.delete(wrong);
const savedOwner=b.ownerDocument;b.ownerDocument=new Node('otherdoc','#document',9);work=0;assert.throws(()=>actual.query({scope:doc,pierceShadow:true},parse('.row')),e=>e===unavailable,'wrong-document descendant');b.ownerDocument=savedOwner;
shadow.mode='closed';work=0;assert.throws(()=>actual.query({scope:doc,pierceShadow:true},parse('#a')),e=>e===unavailable,'closed root not authorized by queryscope');shadow.mode='open';
host.shadowRoot=null;work=0;assert.throws(()=>actual.query({scope:shadow,pierceShadow:true},parse('*')),e=>e===unavailable,'closed-root context missing from owner proof');host.shadowRoot=shadow;
issued.delete(b);work=0;assert.throws(()=>actual.query({scope:doc,pierceShadow:true},parse('#b')),e=>e===unavailable,'unissued match never projected');issued.add(b);
work=0;policy.authorizeContext({scope:doc,pierceShadow:true});work=0;calls=[];policy.queryAtom(doc,'*');const firstCost=work;assert.ok(firstCost>=authorized.size);const nativeBefore=calls.filter(c=>c[0]==='qsa').length;cap=work+authorized.size-1;assert.throws(()=>policy.queryAtom(doc,'*'),e=>e===limit,'each native scan prepays whole proof');assert.equal(calls.filter(c=>c[0]==='qsa').length,nativeBefore);policy.finishContext();cap=1000000;
work=0;cap=40;assert.throws(()=>actual.query({scope:doc,pierceShadow:true},parse('.row')),e=>e===limit);cap=1000000;work=0;assert.deepEqual(actual.query({scope:doc,pierceShadow:true},parse('#a')).map(e=>e.id),['a'],'guard depth/proof restored after refusal');
// Every skipped comment/text sibling is charged on EACH walk, not only preflight.
const comments=Array.from({length:30},(_,i)=>new Node('comment'+i,'#comment',8));
for(const n of comments){n.parentNode=section;n.assignDocument(doc);authorized.add(n);}
section.childNodes.splice(2,0,...comments);
work=0;policy.authorizeContext({scope:doc,pierceShadow:true});work=0;calls=[];
assert.equal(policy.read(b,'nextElementSibling'),shown);const walkCost=work;
assert.ok(walkCost>=comments.length);assert.equal(policy.read(shown,'previousElementSibling'),b);
assert.ok(!calls.some(c=>['firstElementChild','nextElementSibling','previousElementSibling','documentElement'].includes(c[2])),'no native uncharged element sibling walks');
cap=work+walkCost-1;assert.throws(()=>policy.read(b,'nextElementSibling'),e=>e===limit,'repeat sibling walk consumes fresh work');
policy.finishContext();cap=1000000;section.childNodes.splice(2,comments.length);for(const n of comments)authorized.delete(n);
console.log(JSON.stringify({differentialCases:cases,matchCases,parserRejected,originalSix:6,candidateParserJoint:true,policyNegativeControls:10,atomicCostAndRestore:true,boundedSiblingWalk:true,kind:'exact evaluator with explicit DOM/CSS/rendering primitives; no real browser/native proof'}));
