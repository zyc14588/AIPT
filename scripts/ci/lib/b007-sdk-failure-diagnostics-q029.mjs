// Unactivated Q029 proposal. This observes metadata and never qualifies an SDK.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT='/opt/hostedtoolcache/go/1.26.9/x64';
const MEMBER='CONTRIBUTING.md';
const FIELDS=['dev','ino','mode','nlink','uid','gid','size','mtimeNs','ctimeNs'];
const ANCESTOR_FIELDS=['dev','ino','mode','uid','gid'];
const same=(a,b,fields)=>fields.every(k=>a[k]===b[k]);
const kind=s=>s.isSymbolicLink()?'SYMLINK':s.isFile()?'REGULAR':s.isDirectory()?'DIRECTORY':'SPECIAL';
const boundedError=e=>['ENOENT','ENOTDIR','ELOOP','EACCES','EPERM','EBADF','EIO','Q029_UNSTABLE_ANCESTOR'].includes(e?.code)?e.code:'DIAGNOSTIC_ERROR';

export function readFixedQ029SDKMetadata() {
 const report={schema:'aipt.q029.fixed-SDK-post-failure-metadata/v1',
  observation:'POST_FAILURE_SNAPSHOT_NOT_ORIGINAL_REJECTION_STAT',
  root_class:'FIXED_HOSTED_GO_1_26_9_X64',member:MEMBER,
  expected:{regular:true,nlink:'1',bytes:'1337',executable:false},
  SDK_qualified:false,SDK_body_read:false,SDK_execution:false,
  original_failure_preserved:true,status:'UNAVAILABLE',metadata:null,
  stable_snapshot:false,error:null,close_errors:0};
 if(arguments.length!==0){report.error='CALLER_OPTIONS_FORBIDDEN';return report;}
 const held=[];
 const stable=d=>same(d.before,fs.fstatSync(d.fd,{bigint:true}),ANCESTOR_FIELDS)&&
  same(d.before,fs.lstatSync(d.location,{bigint:true}),ANCESTOR_FIELDS);
 const hold=location=>{
  const before=fs.lstatSync(location,{bigint:true});
  if(!before.isDirectory()||before.isSymbolicLink())throw new Error('NONPHYSICAL_ANCESTOR');
  const fd=fs.openSync(location,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_DIRECTORY);
  const item={fd,location,before};held.push(item);
  if(!stable(item))throw Object.assign(new Error('Unstable fixed directory'),{code:'Q029_UNSTABLE_ANCESTOR'});
  return item;
 };
 try {
  hold('/');
  for(const segment of ROOT.slice(1).split('/'))hold('/proc/self/fd/'+held.at(-1).fd+'/'+segment);
  const location='/proc/self/fd/'+held.at(-1).fd+'/'+MEMBER;
  const before=fs.lstatSync(location,{bigint:true});
  const fields=Object.fromEntries(FIELDS.map(k=>[k,String(before[k])]));
  // Fixed numeric stat fields only; errors and paths never enter public output.
  if(Object.values(fields).some(v=>!/^\d{1,24}$/.test(v)))throw new Error('UNBOUNDED_METADATA');
  report.metadata={kind:kind(before),...fields,executable:Boolean(Number(before.mode)&0o111)};
  const after=fs.lstatSync(location,{bigint:true});
  report.stable_snapshot=same(before,after,FIELDS)&&held.every(stable);
  report.status=report.stable_snapshot?'OBSERVED':'UNSTABLE';
 }catch(e){report.error=boundedError(e);report.status=report.error==='Q029_UNSTABLE_ANCESTOR'?'UNSTABLE':'UNAVAILABLE';report.stable_snapshot=false;}
 finally {
  for(const item of held.reverse()){
   try{fs.closeSync(item.fd);}catch{report.close_errors++;}
  }
  if(report.close_errors){report.status='UNAVAILABLE';report.stable_snapshot=false;report.error='DIAGNOSTIC_CLOSE_ERROR';}
 }
 return report;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const report=process.argv.length===2?readFixedQ029SDKMetadata():{
  schema:'aipt.q029.fixed-SDK-post-failure-metadata/v1',status:'UNAVAILABLE',error:'CALLER_OPTIONS_FORBIDDEN',
  SDK_qualified:false,SDK_body_read:false,SDK_execution:false,original_failure_preserved:true};
 const line=JSON.stringify(report)+'\n';
 process.stdout.write(Buffer.byteLength(line)<=4096?line:
  '{"schema":"aipt.q029.fixed-SDK-post-failure-metadata/v1","status":"UNAVAILABLE","error":"OUTPUT_BOUND","SDK_qualified":false}\n');
 process.exitCode=1;
}
