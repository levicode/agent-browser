const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(process.env.UPLOAD_SOURCE || path.join(__dirname,'../../src/native/client_actions.rs'),'utf8');
const captureSource=source.match(/const UPLOAD_LABEL_CONTROL: &str = r#"([\s\S]*?)"#;/)?.[1];
// The baseline sent the exact label straight to UPLOAD_ADMISSIBILITY.
const capture=captureSource ? eval('('+captureSource+')') : function(){return 'unchanged'};
const admission=eval('('+source.match(/const UPLOAD_ADMISSIBILITY: &str = r#"([\s\S]*?)"#;/)[1]+')');
globalThis.document={};
globalThis.HTMLInputElement=class{};
globalThis.HTMLLabelElement=class{};
const file=(extra={})=>Object.assign(new HTMLInputElement(),{isConnected:true,ownerDocument:document,type:'file',disabled:false,webkitdirectory:false,multiple:false},extra);
const label=(control,extra={})=>Object.assign(new HTMLLabelElement(),{isConnected:true,ownerDocument:document,control},extra);
const upload=(node,directory=false,count=1)=>{
  const captured=capture.call(node);
  if(captured==='stale')return {status:'stale'};
  return admission.call(captured==='unchanged'?node:captured,directory,count);
};
for(const name of ['explicit for association','nested file input association'])test(name,()=>{
  const control=file();const node=label(control);
  assert.equal(capture.call(node),control);
  assert.equal(upload(node),true);
});
test('does not re-query or follow a replacement label',()=>{
  const control=file(),node=label(control);
  Object.defineProperty(node,'control',{get(){return control}});
  node.querySelector=()=>{throw new Error('selector lookup forbidden')};
  assert.equal(capture.call(node),control);
});
for(const [name,node] of [
  ['direct input',file()],['generic element',{isConnected:true,ownerDocument:document,control:file()}],
  ['text node',{isConnected:true,ownerDocument:document,nodeType:3,parentElement:label(file())}],
  ['label without control',label(null)],['wrong input type',label(file({type:'text'}))],
])test(name+' is not broadened',()=>{
  assert.equal(capture.call(node),'unchanged');
  if(name==='direct input')assert.equal(upload(node),true);
  else assert.equal(upload(node).status,'not-actionable');
});
for(const [name,node] of [
  ['detached label',label(file(),{isConnected:false})],
  ['foreign label document',label(file(),{ownerDocument:{}})],
  ['detached control',label(file({isConnected:false}))],
  ['foreign control document',label(file({ownerDocument:{}}))],
])test(name+' refuses without retargeting',()=>assert.equal(upload(node).status,'stale'));
for(const [name,extra,directory,count,diagnostic] of [
 ['disabled',{disabled:true},false,1,'disabled'],
 ['directory mismatch',{},true,1,'directory-mismatch'],
 ['file on directory input',{webkitdirectory:true},false,1,'directory-mismatch'],
 ['cardinality',{},false,2,'multiple-mismatch'],
])test(name+' retains upload preflight',()=>{
  assert.deepEqual(upload(label(file(extra)),directory,count),{status:'not-actionable',diagnostic});
});
test('multiple and directory inputs keep supported paths',()=>{
 assert.equal(upload(label(file({multiple:true})),false,2),true);
 assert.equal(upload(label(file({webkitdirectory:true})),true,2),true);
});
test('capture is read-only and returns no caller-visible selector or data',()=>{
 const control=file();const base=label(control);const before=Object.getOwnPropertyDescriptors(base);
 const guarded=new Proxy(base,{set(){throw Error('mutation')},defineProperty(){throw Error('mutation')},deleteProperty(){throw Error('mutation')}});
 assert.equal(capture.call(guarded),control);
 assert.deepEqual(Object.getOwnPropertyDescriptors(base),before);
 assert(!/querySelector|dispatchEvent|\.focus\(|\.click\(|getAttribute|textContent|innerHTML/.test(captureSource||''));
});
