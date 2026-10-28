const fs=require('node:fs'),assert=require('node:assert/strict');
const path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const core=process.env.PLAYWRIGHT_CORE_DIR;assert.ok(core,'PLAYWRIGHT_CORE_DIR must be installed1.64.1');assert.equal(JSON.parse(fs.readFileSync(path.join(core,'package.json'),'utf8')).version,'1.64.1');
const bundle=fs.readFileSync(path.join(core,'lib/coreBundle.js'),'utf8');const line=bundle.split('\n').find(s=>/^\s*source\d* = /.test(s)&&s.includes('packages/injected/src/injectedScript.ts'));
const raw=vm.runInNewContext(line.slice(line.indexOf('=')+1).trim().replace(/;$/,''),{}, {timeout:1000});assert.equal(crypto.createHash('sha256').update(raw).digest('hex'),'852e40f938e72e6129b6c9a8bde3f4cc6cfe5cecb5ac734b6b06c8ad1fde42bf');
const pinned=raw.slice(raw.indexOf('// packages/isomorphic/cssTokenizer.ts'),raw.indexOf('// packages/isomorphic/selectorParser.ts'))+raw.match(/var customCSSNames = .*?;/)[0];
const reference=new Function(pinned+'; return s=>parseCSS(s,customCSSNames);')();
const make=new Function(fs.readFileSync(path.join(__dirname,'../../src/native/client_observation/selector_css_parser.js'),'utf8')+';return createRawCssParser;')();
let work=0,cap=1000000;const limit={};const actual=make(()=>{if(++work>cap)throw limit;},limit);
const cases=['.row:has-text("Alpha")','.row:text("Alpha")','.row:text-is("Alpha Beta")','.row:text-matches("^Alpha Beta$")','button:visible',':nth-match(.row, 2)',':scope',':light(.row)',':is(div,span)',':where(div > button)',':not(:text("x"))','div:has(> span)',':right-of(button, 20)',':left-of(#a)',':above(input)',':below(input)',':near(.x, 10)','svg|a','div\\:a','.a\\20 b','[data-x="x >> y"]','[x="a\\\"b"]','/*comment*/ div','div >> span','',':',':has-text()',':text-matches("[")',':nth-match(.x,0)',':nth-match(.x,"1")','@media','.x{a:b}',':foo(a(b))',':scope > LEGEND','div, span','div + span ~ a','text=Alpha'];
for(const atom of ['div','#x','.row','[id="x"]',':scope',':text("x")'])for(const op of [' ', ' > ', ' + ', ' ~ ', ', '])cases.push(atom+op+'span');
function outcome(fn,s){try{return{value:fn(s)}}catch(e){if(e===limit)return{limit:true};return{name:e.name,message:e.message}}}
for(const s of cases){work=0;assert.deepEqual(outcome(actual,s),outcome(reference,s),s);}
work=0;assert.throws(()=>actual('x'.repeat(65537)),e=>e===limit);
work=0;cap=10;assert.throws(()=>actual(':has('.repeat(100)+'div'+')'.repeat(100)),e=>e===limit);cap=1000000;
work=0;assert.throws(()=>actual(':has('.repeat(300)+'div'+')'.repeat(300)),e=>e===limit);
work=0;assert.deepEqual(actual('.row:has-text("Alpha")'),reference('.row:has-text("Alpha")'),'depth restored after refusal');
console.log(JSON.stringify({exactPinnedCases:cases.length,limitControls:4,functions:134,loops:26,kind:'pure parser source only; no CSS DOM execution'}));
