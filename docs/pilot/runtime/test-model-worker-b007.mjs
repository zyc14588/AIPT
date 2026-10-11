import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {stripTypeScriptTypes} from 'node:module';
import test from 'node:test';
import vm from 'node:vm';

// Pure formatter tests: no Worker main, credentials, runtime or model starts.
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const source=readFileSync(new URL('./model-process-worker-b007.ts',import.meta.url),'utf8');
const predecessor=readFileSync(new URL('../../../packages/model-harness-gateway/src/model-process-worker.ts',import.meta.url),'utf8');
const registration=JSON.parse(readFileSync(new URL('./model-worker-registration-b007.json',import.meta.url),'utf8'));
assert.equal(sha(source),registration.source_sha256);
assert.equal(sha(predecessor),registration.predecessor_source_sha256);
const excerpt=(body,first,next)=>{const a=body.indexOf('function '+first+'('),b=body.indexOf('function '+next+'(',a);assert.ok(a>0&&b>a);return body.slice(a,b);};
const before=excerpt(predecessor,'formatPrompt','writeOuter');
const after=excerpt(source,'formatPrompt','writeOuter');
assert.equal(source,predecessor.replace(before,after));
const constants=['MAX_FRAME_BYTES','AIPT_EFFECTIVE_SAMPLING_SCHEMA','AIPT_SAMPLING_ENFORCEMENT'].map(name=>{const line=source.split('\n').find(x=>x.startsWith('const '+name+' = '));assert.ok(line);return line;}).join('\n');
function formatter(body){
 const box=vm.createContext({Buffer,TextDecoder});
 const pure=constants+'\nfunction fail(code){throw new Error(code);}\n'+excerpt(body,'record','exactKeys')+excerpt(body,'requiredString','boundedInteger')+excerpt(body,'effectiveSampling','parseChild')+excerpt(body,'formatPrompt','writeOuter')+'\nglobalThis.format=formatPrompt;globalThis.identityString=requiredString;';
 vm.runInContext(stripTypeScriptTypes(pure,{mode:'strip'}),box,{timeout:1000});return box;
}
const current=formatter(source),frozen=formatter(predecessor);
const route={sampling_profile:{sha256:'0'.repeat(64),max_context_tokens:8192,max_output_tokens:1024,applied_parameters:['max_context_tokens','max_output_tokens'],unsupported_parameters:['temperature','top_p']}};
const request=value=>({prepared_context:value,session:{session_id:'NON-CANON-session'},invocation:{invocation_id:'NON-CANON-invoke',run_id:'NON-CANON-run',seat_id:'GM',kind:'ORIGINAL',attempt:1}});
const encoded=bytes=>Buffer.from(JSON.stringify({x:'x'.repeat(bytes-8)})).toString('base64');
test('B007 corrects the Base64 representation gap while preserving the frozen Worker',()=>{
 assert.ok(frozen.format(route,request(encoded(3072))));
 assert.throws(()=>frozen.format(route,request(encoded(3073))));
 assert.ok(current.format(route,request(encoded(3073))));
});
for(const bytes of [3072,5500,8192])test('Canonical '+bytes+' decoded bytes retain the published context ceiling',()=>assert.ok(current.format(route,request(encoded(bytes)))));
const rejected={empty:'',non_string:42,whitespace:'e30=\n',missing_padding:'e30',extra_padding:'e30==',trailing_junk:'e30=!',noncanonical_padding_bits:'e31=',non_ascii_base64:'e3é=',invalid_utf8:Buffer.from([255]).toString('base64'),invalid_json:Buffer.from('{bad').toString('base64'),decoded_context_over_limit:encoded(8193)};
for(const [name,value]of Object.entries(rejected))test('Reject '+name+' before prompt construction',()=>assert.throws(()=>current.format(route,request(value))));
test('Ordinary identity strings retain their separate 4096-character bound',()=>{
 assert.equal(current.identityString({x:'x'.repeat(4096)},'x').length,4096);
 assert.throws(()=>current.identityString({x:'x'.repeat(4097)},'x'));
});
