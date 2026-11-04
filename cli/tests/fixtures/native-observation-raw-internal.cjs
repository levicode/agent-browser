// Raw internal baseline and security controls against actual production MATCH_QUERY.
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
  constructor(nodeType) { this.nodeType = nodeType; this._children = []; this.parentNode = null; this.connected = true; }
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
  constructor(tag = 'div', id = '') { super(1); this.localName = tag; this.nodeName = tag.toUpperCase(); this.id = id; this.shadowRoot = null; this.secure = false; }
  matches(selector) {
    if (selector === '*') return true;
    if (selector === 'section') return this.localName === 'section';
    if (selector === '.item') return ['a','b','c'].includes(this.id);
    if (selector === ':scope') return false;
    const attr = selector.match(/^\[id=(".*")\]$/);
    if (attr) return this.id === JSON.parse(attr[1]);
    if (selector.startsWith('#')) return this.id === selector.slice(1);
    if (selector.startsWith('input:not(')) return this.localName === 'textarea' || this.localName === 'select' || this.localName === 'input' && !['checkbox', 'radio'].includes(this.type);
    if (selector.startsWith('input[type="password" i],')) return this.localName === 'input' && this.type === 'password' || this.secure;
    throw Error(`Unexpected fixture selector: ${selector}`);
  }
  attachShadow(mode) { const root = new Node(11); root.host = this; if (mode === 'open') this.shadowRoot = root; return root; }
}
class Input extends Element {
  constructor(type = 'text', id = '') { super('input', id); this.type = type; }
}
class Text extends Node { constructor(value) { super(3); this.nodeValue = value; } }
global.Node = Node; global.Element = Element; global.HTMLInputElement = Input;
document = global.document = new Node(9);
document.head = new Element('head'); document.append(document.head);
const text = value => new Text(value);

Object.defineProperty(Node.prototype,'firstChild',{get(){return this._children[0]||null;}});
Object.defineProperty(Node.prototype,'nextSibling',{get(){if(!this.parentNode)return null;const siblings=this.parentNode._children;return siblings[siblings.indexOf(this)+1]||null;}});

Object.defineProperty(Node.prototype,'firstElementChild',{get(){return this._children.find(n=>n.nodeType===1)||null;}});
Object.defineProperty(Node.prototype,'nextElementSibling',{get(){if(!this.parentNode)return null;const a=this.parentNode._children;return a.slice(a.indexOf(this)+1).find(n=>n.nodeType===1)||null;}});
const one=new Element('section','one'),two=new Element('section','two');
const a=new Element('span','a').append(text('Alpha')),b=new Element('span','b').append(text('Beta')),c=new Element('span','c').append(text('Gamma'));
one.append(a,b);two.append(c);const body=new Element('body','body');body.append(one,two);document.append(body);
let inventory=[one,a,b,two,c];
const leaf=(engine,body)=>({kind:'selector',nativeParts:[{engine,body}]});
const nested=(outer,engine,inner)=>({kind:'selector',nativeParts:[{engine:'css',body:outer},{engine,body:JSON.stringify(inner)}]});
function result(expression){return matchQuery(expression,inventory.map(e=>({states:{secure:e.secure||e.type==='password',hidden:false}})),inventory.map(()=>[]),inventory.map(()=>null),'.secure',inventory.map(()=>false),...inventory);}
let checks=0;
function ids(label,expression,expected){const actual=result(expression);assert.equal(actual.error,undefined,label+JSON.stringify(actual));assert.deepEqual(actual.indices.map(i=>inventory[i].id),expected,label);checks++;}
function error(label,expression,expected){assert.equal(result(expression).error,expected,label);checks++;}
ids('baseline has',nested('section','internal:has','css=#a'),['one']);
ids('baseline has-not',nested('section','internal:has-not','css=#a'),['two']);
ids('baseline and',nested('.item','internal:and','css=#b'),['b']);
ids('baseline or DOM order',nested('#c','internal:or','css=#a'),['a','c']);
ids('baseline chain',nested('#one','internal:chain','css=.item'),['a','b']);
const malformed={kind:'selector',nativeParts:[{engine:'css',body:'section'},{engine:'internal:has',body:'{"selector":"css=#a"}'}]};
error('baseline malformed opaque backend',malformed,'raw-selector-error');
error('eager malformed on empty roots',{...malformed,nativeParts:[{engine:'css',body:'#missing'},malformed.nativeParts[1]]},'raw-selector-error');
ids('relative root identity',nested('#one','internal:has','css=:scope'),['one']);
ids('relative chain excludes outside',nested('#one','internal:chain','css=#c'),[]);
ids('or deduplicates',nested('#a','internal:or','css=#a'),['a']);
error('nested has checks light',nested('#one','internal:has','id:light=a'),'deprecated-selector');
error('nested has-not checks light',nested('#one','internal:has-not','id:light=a'),'deprecated-selector');
ids('nested light miss no exception',nested('#one','internal:has','id:light=absent'),[]);
ids('chain light unchecked',nested('#one','internal:chain','id:light=a'),['a']);
ids('or right light unchecked',nested('#c','internal:or','id:light=a'),['a','c']);
for(const inner of ['role=button','*css=#a','internal:control=enter-frame'])error('finite unsupported '+inner,nested('#one','internal:has',inner),'unsupported-capability');
error('nested authored input budget',nested('#one','internal:has','x'.repeat(65537)),'resource-limit');
error('nested part budget',nested('#one','internal:has',Array(257).fill('css=*').join(' >> ')),'resource-limit');
const host=new Element('div','host'),open=host.attachShadow('open'),inside=new Element('span','inside');open.append(inside);one.append(host);inventory.push(host,inside);
ids('shadow DOM order not inventory order',nested('#inside','internal:or','css=#b'),['b','inside']);
const unissued=new Element('span','unissued');one.append(unissued);
ids('raw nested excludes unissued',nested('#one','internal:chain','css=#unissued'),[]);
let privateReads=0;
const secret=new Input('password','private');Object.defineProperty(secret,'value',{get(){privateReads++;throw Error('private value read');}});one.append(secret);inventory.push(secret);
ids('nested raw text secure miss',nested('#one','internal:has','text=PrivateSecret'),[]);
ids('nested raw text ordinary positive despite secure sibling',nested('#one','internal:has','text=Alpha'),['one']);
assert.equal(privateReads,0);checks++;
const first=Array(130).fill('css=*').join(' >> '),second=Array(130).fill('css=*').join(' >> ');
error('aggregate nested budget never reset',{kind:'selector',nativeParts:[{engine:'css',body:'#missing'},{engine:'internal:has',body:JSON.stringify(first)},{engine:'internal:has',body:JSON.stringify(second)}]},'resource-limit');
console.log(JSON.stringify({checks,kind:'actual MATCH_QUERY source DOM double; no browser/native transport'}));
