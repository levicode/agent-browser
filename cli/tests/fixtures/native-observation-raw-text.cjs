// Raw text baseline and security controls against actual production MATCH_QUERY.
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
const section=new Element('section','section');
const a=new Element('div','text-a').append(text('Alpha   Beta'));
const child=new Element('span','text-child').append(text('Beta'));
const b=new Element('div','text-b').append(text('Alpha '),child);
const gamma=new Element('div','text-gamma').append(text('Gamma'));
section.append(a,b,gamma);document.append(section);
let inventory=[section,a,b,child,gamma];
const leaf=(engine,body)=>({kind:'selector',nativeParts:[{engine,body}]});
function result(expression){return matchQuery(expression,inventory.map(e=>({states:{secure:e.secure||e.type==='password',hidden:false}})),inventory.map(()=>[]),inventory.map(()=>null),'.secure',inventory.map(()=>false),...inventory);}
let checks=0;
function ids(label,expression,expected){const actual=result(expression);assert.equal(actual.error,undefined,label+JSON.stringify(actual));assert.deepEqual(actual.indices.map(i=>inventory[i].id),expected,label);checks++;}
ids('actual baseline lax',leaf('text','alpha beta'),['text-a','text-b']);
ids('actual baseline exact immediate',leaf('text','"Alpha Beta"'),['text-a']);
ids('actual baseline regex full',leaf('text','/^Alpha\\s+Beta$/'),['text-a','text-b']);
ids('actual baseline implicit quote compiler output',leaf('text','"Alpha Beta"'),['text-a']);
ids('actual baseline element root',{kind:'selector',nativeParts:[{engine:'css',body:'#text-a'},{engine:'text',body:'Alpha'}]},['text-a']);
assert.equal(result(leaf('text:light','Gamma')).error,'deprecated-selector');checks++;
ids('light miss',leaf('text:light','absent'),[]);
ids('right nested light remains unchecked',{kind:'union',left:leaf('css','#missing'),right:leaf('text:light','Gamma')},['text-gamma']);
assert.equal(result(leaf('text','/[/')).error,'raw-selector-error');checks++;
ids('ordinary CSS remains available',leaf('css','#text-a'),['text-a']);
const host=new Element('div','host'),open=host.attachShadow('open'),openText=new Element('span','open-text').append(text('ShadowProbe'));open.append(openText);document.append(host);inventory.push(host,openText);
const closedHost=new Element('div','closed-host'),closed=closedHost.attachShadow('closed'),closedText=new Element('span','closed-text').append(text('ClosedProbe'));closed.append(closedText);document.append(closedHost);inventory.push(closedHost,closedText);
ids('raw text enters only open shadow',leaf('text','ShadowProbe'),['open-text']);
ids('raw text does not discover closed shadow',leaf('text','ClosedProbe'),[]);
ids('light text does not discover open shadow',leaf('text:light','ShadowProbe'),[]);
let privateReads=0;
const secret=new Input('password','private');Object.defineProperty(secret,'value',{get(){privateReads++;throw Error('private value was read');}});section.append(secret);inventory.push(secret);
ids('secure sibling cannot prune ordinary text',leaf('text','alpha beta'),['text-a','text-b']);
ids('private value never becomes text',leaf('text','PrivateValue'),[]);assert.equal(privateReads,0);checks++;
const oversized=new Element('div','oversized').append(text('x'.repeat(1048577)));document.append(oversized);inventory.push(oversized);
assert.equal(result(leaf('text','x')).error,'resource-limit');checks++;
console.log(JSON.stringify({checks,privateValueReads:privateReads,kind:'actual MATCH_QUERY explicit DOM double; no browser/native transport'}));
