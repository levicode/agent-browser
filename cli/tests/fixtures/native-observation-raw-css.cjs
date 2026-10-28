// Raw extended CSS baseline and security controls against actual production MATCH_QUERY.
// Explicit DOM double, not a browser/native transport acceptance.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const sourcePath = process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs');
const source = fs.readFileSync(sourcePath, 'utf8');
const script = require('./native-observation-script.cjs')(sourcePath, 'MATCH_QUERY');
const matchQuery = eval(`(${script})`);
let document;
class Node {
  constructor(nodeType) { this._nodeType = nodeType; this._children = []; this._parentNode = null; this.connected = true; }
  get nodeType() { return this._nodeType; }
  get parentNode() { return this._parentNode; }
  set parentNode(value) { this._parentNode=value; }
  get childNodes() { return this._children; }
  set childNodes(children) { this._children = children; }
  get ownerDocument() { return document; }
  get isConnected() { return this.connected; }
  get parentElement() { return this.parentNode?.nodeType === 1 ? this.parentNode : null; }
  append(...children) { for (const child of children) { child.parentNode = this; this._children.push(child); } return this; }
  getRootNode() { let node = this; while (node.parentNode) node = node.parentNode; return node; }
  // Native qSA walks the actual light tree, not an overridable childNodes
  // getter. Shadow discovery belongs to production selectChain, not this DOM.
  querySelectorAll(css) {
    const found = [], pending = [...this._children].reverse();
    while (pending.length) {
      const node = pending.pop();
      if (node.nodeType === 1 && node.matches(css)) found.push(node);
      for (let i = node._children.length - 1; i >= 0; i--) pending.push(node._children[i]);
    }
    return found;
  }
  contains(target) { for (let node = target; node; node = node.parentNode) if (node === this) return true; return false; }
}
class Element extends Node {
  constructor(tag = 'div', id = '') { super(1); this.localName = tag; this.nodeName = tag.toUpperCase(); this.id = id; this._shadowRoot = null; this.secure = false; }
  get shadowRoot() { return this._shadowRoot; }
  set shadowRoot(value) { this._shadowRoot=value; }
  checkVisibility() { return !this.hidden; }
  getBoundingClientRect() { return {width:this.hidden?0:20,height:this.hidden?0:20,left:0,right:20,top:0,bottom:20}; }
  matches(selector) {
    if (selector === '*') return true;
    if (selector === '.row') return this.row === true;
    if (selector === '[data-probe=":text(Alpha)"]') return this.id === 'css-a';
    if (selector === 'button' || selector === 'section' || selector === 'span' || selector === 'div') return this.localName === selector;
    if (selector === ':scope') return false;
    if (selector.startsWith('#')) return this.id === selector.slice(1);
    if (selector.startsWith('input:not(')) return this.localName === 'textarea' || this.localName === 'select' || this.localName === 'input' && !['checkbox', 'radio'].includes(this.type);
    if (selector.startsWith('input[type="password" i],')) return this.localName === 'input' && this.type === 'password' || this.secure;
    throw Error(`Unexpected fixture selector: ${selector}`);
  }
  attachShadow(mode) { const root = new ShadowRoot(this,mode); if (mode === 'open') this.shadowRoot = root; return root; }
}
class Input extends Element {
  constructor(type = 'text', id = '') { super('input', id); this.type = type; }
}
class Text extends Node { constructor(value) { super(3); this.nodeValue = value; } }
class ShadowRoot extends Node { constructor(host,mode){super(11);this._host=host;this._mode=mode;} get host(){return this._host;} get mode(){return this._mode;} }
class Document extends Node { constructor(){super(9);} }
global.ShadowRoot=ShadowRoot;global.Document=Document;
global.Node = Node; global.Element = Element; global.HTMLInputElement = Input;
document = global.document = new Document();
document.defaultView={getComputedStyle:element=>({display:element.hidden?'none':'block',visibility:'visible'})};
const html=new Element('html','html'),body=new Element('body','body');document.head = new Element('head','head');html.append(document.head,body);document.append(html);
const text = value => new Text(value);

Object.defineProperty(Node.prototype,'firstChild',{get(){return this._children[0]||null;}});
Object.defineProperty(Node.prototype,'nextSibling',{get(){if(!this.parentNode)return null;const siblings=this.parentNode._children;return siblings[siblings.indexOf(this)+1]||null;}});

const section=new Element('section','section'),a=new Element('div','css-a'),b=new Element('div','css-b'),beta=new Element('span','beta'),shown=new Element('button','css-shown'),hidden=new Element('button','css-hidden');
a.row=b.row=true;beta.append(text('Beta'));a.append(text('Alpha '),beta);b.append(text('Alpha Beta'));shown.append(text('Save'));hidden.append(text('Save'));hidden.hidden=true;section.append(a,b,shown,hidden);body.append(section);
let inventory=[html,document.head,body,section,a,beta,b,shown,hidden];
const leaf=body=>({kind:'selector',nativeParts:[{engine:'css',body}]});
function result(expression){return matchQuery(expression,inventory.map(e=>({states:{secure:e.secure||e.type==='password',hidden:!!e.hidden}})),inventory.map(()=>[]),inventory.map(()=>null),'.secure',inventory.map(()=>false),...inventory);}
let checks=0;
function ids(label,expression,expected){const actual=result(expression);assert.equal(actual.error,undefined,label+JSON.stringify(actual));assert.deepEqual(actual.indices.map(i=>inventory[i].id),expected,label);checks++;}
function error(label,expression,expected){assert.equal(result(expression).error,expected,label);checks++;}
ids('baseline has-text',leaf('.row:has-text("Alpha")'),['css-a','css-b']);
ids('baseline text',leaf('.row:text("Alpha")'),['css-a','css-b']);
ids('baseline text-is',leaf('.row:text-is("Alpha Beta")'),['css-b']);
ids('baseline text-matches',leaf('.row:text-matches("^Alpha Beta$")'),['css-a','css-b']);
ids('baseline visible',leaf('button:visible'),['css-shown']);
ids('baseline nth-match',leaf(':nth-match(.row,2)'),['css-b']);
ids('complete AST nested is order',leaf(':is(#css-shown,.row:text-is("Alpha Beta"))'),['css-b','css-shown']);
ids('complete AST mixed not',leaf('.row:not(:text-is("Alpha Beta"))'),['css-a']);
ids('scoped complete AST',{kind:'selector',nativeParts:[{engine:'css',body:'#section'},{engine:'css',body:':scope > .row:has-text("Alpha")'}]},['css-a','css-b']);
ids('ordinary CSS keeps existing path',leaf('.row'),['css-a','css-b']);
error('malformed extended arguments',leaf('.row:text()'),'raw-selector-error');
error('invalid fractional engine output opaque backend',leaf(':nth-match(.row,1.5)'),'raw-selector-error');
error('invalid nested fractional sort receiver opaque backend',leaf(':is(:nth-match(.row,1.5),#css-a)'),'raw-selector-error');
error('invalid deeper fractional sort receiver opaque backend',leaf(':nth-match(:is(:nth-match(.row,1.5),#css-a),1)'),'raw-selector-error');
for(const css of ['#css-a:near(:nth-match(.row,1.5))',':nth-match(.row,1.5):near(#css-a)',':nth-match(.row,1.5):visible',':nth-match(.row,1.5):text("Alpha")',':nth-match(.row,1.5):text-is("Alpha")',':nth-match(.row,1.5):has-text("Alpha")',':nth-match(.row,1.5):has(span)']) error('invalid engine receiver across private wrappers '+css,leaf(css),'raw-selector-error');

for(const engine of ['internal:has','internal:has-not','internal:chain']) {
  error('eager nested CSS syntax even empty '+engine,{kind:'selector',nativeParts:[{engine:'css',body:'#absent'},{engine,body:JSON.stringify('css=:is(')}]},'raw-selector-error');
  ids('nested runtime argument error remains lazy '+engine,{kind:'selector',nativeParts:[{engine:'css',body:'#absent'},{engine,body:JSON.stringify('css=.row:text(1)')}]},[]);
}

let privateReads=0;const secret=new Input('password','private');Object.defineProperty(secret,'value',{get(){privateReads++;throw Error('private value acquired');}});a.append(secret);inventory.push(secret);
error('protected not cannot invent positive',leaf('.row:not(:has-text("PrivateSecret"))'),'unsupported-capability');
error('protected text-is cannot invent positive',leaf('.row:text-is("Alpha Beta")'),'unsupported-capability');
assert.equal(privateReads,0);checks++;
a._children.pop();secret.parentNode=null;inventory.pop();
const unknown=new Element('div','unissued');body.append(unknown);let scans=0;const originalQsa=Node.prototype.querySelectorAll;Node.prototype.querySelectorAll=function(css){scans++;return originalQsa.call(this,css);};
error('unissued structural node refuses before CSS scan',leaf('.row:has-text("Alpha")'),'unsupported-capability');assert.equal(scans,0);checks++;ids('quoted pseudo is data not extension dispatch',leaf('[data-probe=":text(Alpha)"]'),['css-a']);Node.prototype.querySelectorAll=originalQsa;body._children.pop();unknown.parentNode=null;
const host=new Element('div','host'),open=host.attachShadow('open'),openRow=new Element('div','open-row');openRow.row=true;openRow.append(text('ShadowProbe'));open.append(openRow);section.append(host);inventory.push(host,openRow);
ids('open root exact text',leaf('.row:has-text("ShadowProbe")'),['open-row']);
ids('light exact nested text',leaf(':light(.row:has-text("ShadowProbe"))'),[]);
const closedHost=new Element('div','closed-host'),closed=closedHost.attachShadow('closed'),closedRow=new Element('div','closed-row');closedRow.row=true;closedRow.append(text('ClosedProbe'));closed.append(closedRow);section.append(closedHost);inventory.push(closedHost,closedRow);
ids('closed root never discovered',leaf('.row:has-text("ClosedProbe")'),[]);
const oversized=new Element('div','oversized');oversized.row=true;oversized.append(text('x'.repeat(1048577)));section.append(oversized);inventory.push(oversized);
error('existing text root cap retained',leaf('.row:has-text("x")'),'resource-limit');
section._children.pop();oversized.parentNode=null;inventory.pop();
for(let i=0;i<30000;i++)body.append(new Node(8));
scans=0;Node.prototype.querySelectorAll=function(css){scans++;return originalQsa.call(this,css);};
error('complete proof consumes original shared work budget before scan',leaf('.row:has-text("Alpha")'),'resource-limit');assert.equal(scans,0);checks++;Node.prototype.querySelectorAll=originalQsa;
body._children.length=body._children.length-30000;
ids('independent next query recovers after typed budget refusal',leaf('.row:has-text("Alpha")'),['css-a','css-b']);
console.log(JSON.stringify({checks,privateValueReads:privateReads,kind:'actual MATCH_QUERY source DOM double; no browser/native transport'}));
