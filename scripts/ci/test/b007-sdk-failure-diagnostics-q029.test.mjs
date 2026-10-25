// Synthetic diagnostic-only checks; no real SDK file or executable is touched.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {readFixedQ029SDKMetadata} from '../lib/b007-sdk-failure-diagnostics-q029.mjs';

const stat=(type='DIRECTORY',changes={})=>({dev:1n,ino:2n,mode:type==='DIRECTORY'?0o40755n:0o100644n,
 nlink:type==='DIRECTORY'?2n:1n,uid:1000n,gid:1000n,size:type==='DIRECTORY'?4096n:1337n,
 mtimeNs:3n,ctimeNs:4n,isDirectory:()=>type==='DIRECTORY',isFile:()=>type==='REGULAR',
 isSymbolicLink:()=>type==='SYMLINK',...changes});
function fake(options,body){
 const names=['lstatSync','openSync','fstatSync','closeSync','readSync','readFileSync'];
 const old=Object.fromEntries(names.map(n=>[n,fs[n]]));const opened=[],closed=[],memberPaths=[];
 let memberReads=0;const locations=new Map();
 try {
  fs.lstatSync=(p,flags)=>{
   assert.deepEqual(flags,{bigint:true});locations.set(p,(locations.get(p)??0)+1);
   if(p.endsWith('/CONTRIBUTING.md')){
    memberPaths.push(p);memberReads++;
    if(options.missing)throw Object.assign(new Error('untrusted secret/path'),{code:'ENOENT'});
    return stat(options.type??'REGULAR',memberReads>1&&options.after?options.after:options.change);
   }
   return stat(options.linkAncestor&&p.endsWith('/go')?'SYMLINK':'DIRECTORY',options.lstatChanged&&p==='/'&&locations.get(p)>1?{ino:9n}:{});
  };
  fs.openSync=(p,flags)=>{assert.ok(flags&fs.constants.O_NOFOLLOW);assert.ok(flags&fs.constants.O_DIRECTORY);assert.ok(!p.endsWith('/CONTRIBUTING.md'));opened.push(p);return 100+opened.length;};
  fs.fstatSync=()=>stat('DIRECTORY',options.fstatChanged?{ino:9n}:{});fs.closeSync=fd=>{closed.push(fd);if(options.closeFail)throw new Error('close');};
  fs.readSync=fs.readFileSync=()=>{throw new Error('SDK BODY READ FORBIDDEN');};
  body({opened,closed,memberPaths});
 }finally{for(const n of names)fs[n]=old[n];}
}
const noQualification=r=>{assert.equal(r.SDK_qualified,false);assert.equal(r.SDK_body_read,false);assert.equal(r.SDK_execution,false);assert.equal(r.original_failure_preserved,true);assert.ok(Buffer.byteLength(JSON.stringify(r))<4096);};

test('fixed post-failure snapshot does not claim qualification or original rejection stat',()=>fake({},v=>{
 const r=readFixedQ029SDKMetadata();noQualification(r);assert.equal(r.observation,'POST_FAILURE_SNAPSHOT_NOT_ORIGINAL_REJECTION_STAT');
 assert.equal(r.status,'OBSERVED');assert.equal(r.metadata.size,'1337');assert.equal(v.opened.length,6);assert.equal(v.closed.length,6);
 assert.equal(v.memberPaths.length,2);assert.ok(v.memberPaths.every(p=>p==='/proc/self/fd/106/CONTRIBUTING.md'));
}));
for(const [label,options,check]of[
 ['aliased file',{change:{nlink:2n}},r=>assert.equal(r.metadata.nlink,'2')],
 ['wrong size',{change:{size:1338n}},r=>assert.equal(r.metadata.size,'1338')],
 ['executable bit',{change:{mode:0o100755n}},r=>assert.equal(r.metadata.executable,true)],
 ['member symlink',{type:'SYMLINK'},r=>assert.equal(r.metadata.kind,'SYMLINK')],
 ['special member',{type:'SPECIAL'},r=>assert.equal(r.metadata.kind,'SPECIAL')],
 ['changing member',{after:{ino:99n}},r=>{assert.equal(r.status,'UNSTABLE');assert.equal(r.stable_snapshot,false);}],
 ['missing member',{missing:true},r=>{assert.equal(r.status,'UNAVAILABLE');assert.equal(r.error,'ENOENT');assert.equal(r.metadata,null);}],
 ['unbounded fields',{change:{size:-1n}},r=>{assert.equal(r.status,'UNAVAILABLE');assert.equal(r.metadata,null);}],
 ['close error',{closeFail:true},r=>{assert.equal(r.status,'UNAVAILABLE');assert.equal(r.close_errors,6);}]
])test(label,()=>fake(options,v=>{const r=readFixedQ029SDKMetadata();noQualification(r);check(r);assert.equal(v.closed.length,v.opened.length);}));
test('symlink ancestor stops before reading member metadata',()=>fake({linkAncestor:true},v=>{
 const r=readFixedQ029SDKMetadata();noQualification(r);assert.equal(r.status,'UNAVAILABLE');assert.equal(v.memberPaths.length,0);assert.equal(v.opened.length,v.closed.length);
}));
test('caller path/options never enter fixed metadata observer',()=>fake({},v=>{
 const r=readFixedQ029SDKMetadata('/tmp/arbitrary',{});noQualification(r);assert.equal(r.error,'CALLER_OPTIONS_FORBIDDEN');assert.equal(v.opened.length,0);assert.equal(v.memberPaths.length,0);
}));

for(const options of [{fstatChanged:true},{lstatChanged:true}])test('initial ancestor identity change is UNSTABLE '+Object.keys(options)[0],()=>fake(options,v=>{
 const r=readFixedQ029SDKMetadata();noQualification(r);assert.equal(r.status,'UNSTABLE');assert.equal(r.error,'Q029_UNSTABLE_ANCESTOR');assert.equal(r.stable_snapshot,false);assert.equal(v.opened.length,1);assert.equal(v.closed.length,1);assert.equal(v.memberPaths.length,0);
}));
