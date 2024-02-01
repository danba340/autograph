
var Module = (() => {
  var _scriptDir = import.meta.url;
  
  return (
async function(moduleArg = {}) {

var Module=moduleArg;var readyPromiseResolve,readyPromiseReject;Module["ready"]=new Promise((resolve,reject)=>{readyPromiseResolve=resolve;readyPromiseReject=reject});var moduleOverrides=Object.assign({},Module);var arguments_=[];var thisProgram="./this.program";var quit_=(status,toThrow)=>{throw toThrow};var ENVIRONMENT_IS_WEB=typeof window=="object";var ENVIRONMENT_IS_WORKER=typeof importScripts=="function";var ENVIRONMENT_IS_NODE=typeof process=="object"&&typeof process.versions=="object"&&typeof process.versions.node=="string";var scriptDirectory="";function locateFile(path){if(Module["locateFile"]){return Module["locateFile"](path,scriptDirectory)}return scriptDirectory+path}var read_,readAsync,readBinary;if(ENVIRONMENT_IS_NODE){const{createRequire:createRequire}=await import("module");var require=createRequire(import.meta.url);var fs=require("fs");var nodePath=require("path");if(ENVIRONMENT_IS_WORKER){scriptDirectory=nodePath.dirname(scriptDirectory)+"/"}else{scriptDirectory=require("url").fileURLToPath(new URL("./",import.meta.url))}read_=(filename,binary)=>{filename=isFileURI(filename)?new URL(filename):nodePath.normalize(filename);return fs.readFileSync(filename,binary?undefined:"utf8")};readBinary=filename=>{var ret=read_(filename,true);if(!ret.buffer){ret=new Uint8Array(ret)}return ret};readAsync=(filename,onload,onerror,binary=true)=>{filename=isFileURI(filename)?new URL(filename):nodePath.normalize(filename);fs.readFile(filename,binary?undefined:"utf8",(err,data)=>{if(err)onerror(err);else onload(binary?data.buffer:data)})};if(!Module["thisProgram"]&&process.argv.length>1){thisProgram=process.argv[1].replace(/\\/g,"/")}arguments_=process.argv.slice(2);quit_=(status,toThrow)=>{process.exitCode=status;throw toThrow};Module["inspect"]=()=>"[Emscripten Module object]"}else if(ENVIRONMENT_IS_WEB||ENVIRONMENT_IS_WORKER){if(ENVIRONMENT_IS_WORKER){scriptDirectory=self.location.href}else if(typeof document!="undefined"&&document.currentScript){scriptDirectory=document.currentScript.src}if(_scriptDir){scriptDirectory=_scriptDir}if(scriptDirectory.indexOf("blob:")!==0){scriptDirectory=scriptDirectory.substr(0,scriptDirectory.replace(/[?#].*/,"").lastIndexOf("/")+1)}else{scriptDirectory=""}{read_=url=>{var xhr=new XMLHttpRequest;xhr.open("GET",url,false);xhr.send(null);return xhr.responseText};if(ENVIRONMENT_IS_WORKER){readBinary=url=>{var xhr=new XMLHttpRequest;xhr.open("GET",url,false);xhr.responseType="arraybuffer";xhr.send(null);return new Uint8Array(xhr.response)}}readAsync=(url,onload,onerror)=>{var xhr=new XMLHttpRequest;xhr.open("GET",url,true);xhr.responseType="arraybuffer";xhr.onload=()=>{if(xhr.status==200||xhr.status==0&&xhr.response){onload(xhr.response);return}onerror()};xhr.onerror=onerror;xhr.send(null)}}}else{}var out=Module["print"]||console.log.bind(console);var err=Module["printErr"]||console.error.bind(console);Object.assign(Module,moduleOverrides);moduleOverrides=null;if(Module["arguments"])arguments_=Module["arguments"];if(Module["thisProgram"])thisProgram=Module["thisProgram"];if(Module["quit"])quit_=Module["quit"];var wasmBinary;if(Module["wasmBinary"])wasmBinary=Module["wasmBinary"];if(typeof WebAssembly!="object"){abort("no native wasm support detected")}function getSafeHeapType(bytes,isFloat){switch(bytes){case 1:return"i8";case 2:return"i16";case 4:return isFloat?"float":"i32";case 8:return isFloat?"double":"i64";default:abort(`getSafeHeapType() invalid bytes=${bytes}`)}}function SAFE_HEAP_LOAD(dest,bytes,unsigned,isFloat){if(dest<=0)abort(`segmentation fault loading ${bytes} bytes from address ${dest}`);if(dest%bytes!==0)abort(`alignment error loading from address ${dest}, which was expected to be aligned to a multiple of ${bytes}`);if(runtimeInitialized){var brk=_sbrk(0);if(dest+bytes>brk)abort(`segmentation fault, exceeded the top of the available dynamic heap when loading ${bytes} bytes from address ${dest}. DYNAMICTOP=${brk}`);if(brk<_emscripten_stack_get_base())abort(`brk >= _emscripten_stack_get_base() (brk=${brk}, _emscripten_stack_get_base()=${_emscripten_stack_get_base()})`);if(brk>wasmMemory.buffer.byteLength)abort(`brk <= wasmMemory.buffer.byteLength (brk=${brk}, wasmMemory.buffer.byteLength=${wasmMemory.buffer.byteLength})`)}var type=getSafeHeapType(bytes,isFloat);var ret=getValue_safe(dest,type);if(unsigned)ret=unSign(ret,parseInt(type.substr(1),10));return ret}function SAFE_HEAP_LOAD_D(dest,bytes,unsigned){return SAFE_HEAP_LOAD(dest,bytes,unsigned,true)}function segfault(){abort("segmentation fault")}function alignfault(){abort("alignment fault")}var wasmMemory;var ABORT=false;var EXITSTATUS;var HEAP8,HEAPU8,HEAP16,HEAPU16,HEAP32,HEAPU32,HEAPF32,HEAP64,HEAPU64,HEAPF64;function updateMemoryViews(){var b=wasmMemory.buffer;Module["HEAP8"]=HEAP8=new Int8Array(b);Module["HEAP16"]=HEAP16=new Int16Array(b);Module["HEAPU8"]=HEAPU8=new Uint8Array(b);Module["HEAPU16"]=HEAPU16=new Uint16Array(b);Module["HEAP32"]=HEAP32=new Int32Array(b);Module["HEAPU32"]=HEAPU32=new Uint32Array(b);Module["HEAPF32"]=HEAPF32=new Float32Array(b);Module["HEAPF64"]=HEAPF64=new Float64Array(b);Module["HEAP64"]=HEAP64=new BigInt64Array(b);Module["HEAPU64"]=HEAPU64=new BigUint64Array(b)}var __ATPRERUN__=[];var __ATINIT__=[];var __ATPOSTRUN__=[];var runtimeInitialized=false;function preRun(){if(Module["preRun"]){if(typeof Module["preRun"]=="function")Module["preRun"]=[Module["preRun"]];while(Module["preRun"].length){addOnPreRun(Module["preRun"].shift())}}callRuntimeCallbacks(__ATPRERUN__)}function initRuntime(){runtimeInitialized=true;callRuntimeCallbacks(__ATINIT__)}function postRun(){if(Module["postRun"]){if(typeof Module["postRun"]=="function")Module["postRun"]=[Module["postRun"]];while(Module["postRun"].length){addOnPostRun(Module["postRun"].shift())}}callRuntimeCallbacks(__ATPOSTRUN__)}function addOnPreRun(cb){__ATPRERUN__.unshift(cb)}function addOnInit(cb){__ATINIT__.unshift(cb)}function addOnPostRun(cb){__ATPOSTRUN__.unshift(cb)}var runDependencies=0;var runDependencyWatcher=null;var dependenciesFulfilled=null;function addRunDependency(id){runDependencies++;Module["monitorRunDependencies"]?.(runDependencies)}function removeRunDependency(id){runDependencies--;Module["monitorRunDependencies"]?.(runDependencies);if(runDependencies==0){if(runDependencyWatcher!==null){clearInterval(runDependencyWatcher);runDependencyWatcher=null}if(dependenciesFulfilled){var callback=dependenciesFulfilled;dependenciesFulfilled=null;callback()}}}function abort(what){Module["onAbort"]?.(what);what="Aborted("+what+")";err(what);ABORT=true;EXITSTATUS=1;what+=". Build with -sASSERTIONS for more info.";var e=new WebAssembly.RuntimeError(what);readyPromiseReject(e);throw e}var dataURIPrefix="data:application/octet-stream;base64,";var isDataURI=filename=>filename.startsWith(dataURIPrefix);var isFileURI=filename=>filename.startsWith("file://");var wasmBinaryFile;if(Module["locateFile"]){wasmBinaryFile="autograph.wasm";if(!isDataURI(wasmBinaryFile)){wasmBinaryFile=locateFile(wasmBinaryFile)}}else{wasmBinaryFile=new URL("autograph.wasm",import.meta.url).href}function getBinarySync(file){if(file==wasmBinaryFile&&wasmBinary){return new Uint8Array(wasmBinary)}if(readBinary){return readBinary(file)}throw"both async and sync fetching of the wasm failed"}function getBinaryPromise(binaryFile){if(!wasmBinary&&(ENVIRONMENT_IS_WEB||ENVIRONMENT_IS_WORKER)){if(typeof fetch=="function"&&!isFileURI(binaryFile)){return fetch(binaryFile,{credentials:"same-origin"}).then(response=>{if(!response["ok"]){throw"failed to load wasm binary file at '"+binaryFile+"'"}return response["arrayBuffer"]()}).catch(()=>getBinarySync(binaryFile))}else if(readAsync){return new Promise((resolve,reject)=>{readAsync(binaryFile,response=>resolve(new Uint8Array(response)),reject)})}}return Promise.resolve().then(()=>getBinarySync(binaryFile))}function instantiateArrayBuffer(binaryFile,imports,receiver){return getBinaryPromise(binaryFile).then(binary=>WebAssembly.instantiate(binary,imports)).then(instance=>instance).then(receiver,reason=>{err(`failed to asynchronously prepare wasm: ${reason}`);abort(reason)})}function instantiateAsync(binary,binaryFile,imports,callback){if(!binary&&typeof WebAssembly.instantiateStreaming=="function"&&!isDataURI(binaryFile)&&!isFileURI(binaryFile)&&!ENVIRONMENT_IS_NODE&&typeof fetch=="function"){return fetch(binaryFile,{credentials:"same-origin"}).then(response=>{var result=WebAssembly.instantiateStreaming(response,imports);return result.then(callback,function(reason){err(`wasm streaming compile failed: ${reason}`);err("falling back to ArrayBuffer instantiation");return instantiateArrayBuffer(binaryFile,imports,callback)})})}return instantiateArrayBuffer(binaryFile,imports,callback)}function createWasm(){var info={"a":wasmImports};function receiveInstance(instance,module){wasmExports=instance.exports;wasmMemory=wasmExports["f"];updateMemoryViews();addOnInit(wasmExports["g"]);removeRunDependency("wasm-instantiate");return wasmExports}addRunDependency("wasm-instantiate");function receiveInstantiationResult(result){receiveInstance(result["instance"])}if(Module["instantiateWasm"]){try{return Module["instantiateWasm"](info,receiveInstance)}catch(e){err(`Module.instantiateWasm callback failed with error: ${e}`);readyPromiseReject(e)}}instantiateAsync(wasmBinary,wasmBinaryFile,info,receiveInstantiationResult).catch(readyPromiseReject);return{}}var ASM_CONSTS={34604:()=>Module.getRandomValue(),34640:()=>{if(Module.getRandomValue===undefined){try{var window_="object"===typeof window?window:self;var crypto_=typeof window_.crypto!=="undefined"?window_.crypto:window_.msCrypto;var randomValuesStandard=function(){var buf=new Uint32Array(1);crypto_.getRandomValues(buf);return buf[0]>>>0};randomValuesStandard();Module.getRandomValue=randomValuesStandard}catch(e){try{var crypto=require("crypto");var randomValueNodeJS=function(){var buf=crypto["randomBytes"](4);return(buf[0]<<24|buf[1]<<16|buf[2]<<8|buf[3])>>>0};randomValueNodeJS();Module.getRandomValue=randomValueNodeJS}catch(e){throw"No secure random number generator found"}}}}};var callRuntimeCallbacks=callbacks=>{while(callbacks.length>0){callbacks.shift()(Module)}};function getValue_safe(ptr,type="i8"){if(type.endsWith("*"))type="*";switch(type){case"i1":return HEAP8[ptr>>0];case"i8":return HEAP8[ptr>>0];case"i16":return HEAP16[ptr>>1];case"i32":return HEAP32[ptr>>2];case"i64":return HEAP64[ptr>>3];case"float":return HEAPF32[ptr>>2];case"double":return HEAPF64[ptr>>3];case"*":return HEAPU32[ptr>>2];default:abort(`invalid type for getValue: ${type}`)}}var noExitRuntime=Module["noExitRuntime"]||true;var unSign=(value,bits)=>{if(value>=0){return value}return bits<=32?2*Math.abs(1<<bits-1)+value:Math.pow(2,bits)+value};var _abort=()=>{abort("")};var readEmAsmArgsArray=[];var readEmAsmArgs=(sigPtr,buf)=>{readEmAsmArgsArray.length=0;var ch;while(ch=SAFE_HEAP_LOAD(sigPtr++,1,1)){var wide=ch!=105;wide&=ch!=112;buf+=wide&&buf%8?4:0;readEmAsmArgsArray.push(ch==112?SAFE_HEAP_LOAD((buf>>2)*4,4,1):ch==106?HEAP64[buf>>3]:ch==105?SAFE_HEAP_LOAD((buf>>2)*4,4,0):SAFE_HEAP_LOAD_D((buf>>3)*8,8,0));buf+=wide?8:4}return readEmAsmArgsArray};var runEmAsmFunction=(code,sigPtr,argbuf)=>{var args=readEmAsmArgs(sigPtr,argbuf);return ASM_CONSTS[code].apply(null,args)};var _emscripten_asm_const_int=(code,sigPtr,argbuf)=>runEmAsmFunction(code,sigPtr,argbuf);var abortOnCannotGrowMemory=requestedSize=>{abort("OOM")};var _emscripten_resize_heap=requestedSize=>{var oldSize=HEAPU8.length;requestedSize>>>=0;abortOnCannotGrowMemory(requestedSize)};var getCFunc=ident=>{var func=Module["_"+ident];return func};var writeArrayToMemory=(array,buffer)=>{HEAP8.set(array,buffer)};var lengthBytesUTF8=str=>{var len=0;for(var i=0;i<str.length;++i){var c=str.charCodeAt(i);if(c<=127){len++}else if(c<=2047){len+=2}else if(c>=55296&&c<=57343){len+=4;++i}else{len+=3}}return len};var stringToUTF8Array=(str,heap,outIdx,maxBytesToWrite)=>{if(!(maxBytesToWrite>0))return 0;var startIdx=outIdx;var endIdx=outIdx+maxBytesToWrite-1;for(var i=0;i<str.length;++i){var u=str.charCodeAt(i);if(u>=55296&&u<=57343){var u1=str.charCodeAt(++i);u=65536+((u&1023)<<10)|u1&1023}if(u<=127){if(outIdx>=endIdx)break;heap[outIdx++]=u}else if(u<=2047){if(outIdx+1>=endIdx)break;heap[outIdx++]=192|u>>6;heap[outIdx++]=128|u&63}else if(u<=65535){if(outIdx+2>=endIdx)break;heap[outIdx++]=224|u>>12;heap[outIdx++]=128|u>>6&63;heap[outIdx++]=128|u&63}else{if(outIdx+3>=endIdx)break;heap[outIdx++]=240|u>>18;heap[outIdx++]=128|u>>12&63;heap[outIdx++]=128|u>>6&63;heap[outIdx++]=128|u&63}}heap[outIdx]=0;return outIdx-startIdx};var stringToUTF8=(str,outPtr,maxBytesToWrite)=>stringToUTF8Array(str,HEAPU8,outPtr,maxBytesToWrite);var stringToUTF8OnStack=str=>{var size=lengthBytesUTF8(str)+1;var ret=stackAlloc(size);stringToUTF8(str,ret,size);return ret};var UTF8Decoder=typeof TextDecoder!="undefined"?new TextDecoder("utf8"):undefined;var UTF8ArrayToString=(heapOrArray,idx,maxBytesToRead)=>{var endIdx=idx+maxBytesToRead;var endPtr=idx;while(heapOrArray[endPtr]&&!(endPtr>=endIdx))++endPtr;if(endPtr-idx>16&&heapOrArray.buffer&&UTF8Decoder){return UTF8Decoder.decode(heapOrArray.subarray(idx,endPtr))}var str="";while(idx<endPtr){var u0=heapOrArray[idx++];if(!(u0&128)){str+=String.fromCharCode(u0);continue}var u1=heapOrArray[idx++]&63;if((u0&224)==192){str+=String.fromCharCode((u0&31)<<6|u1);continue}var u2=heapOrArray[idx++]&63;if((u0&240)==224){u0=(u0&15)<<12|u1<<6|u2}else{u0=(u0&7)<<18|u1<<12|u2<<6|heapOrArray[idx++]&63}if(u0<65536){str+=String.fromCharCode(u0)}else{var ch=u0-65536;str+=String.fromCharCode(55296|ch>>10,56320|ch&1023)}}return str};var UTF8ToString=(ptr,maxBytesToRead)=>ptr?UTF8ArrayToString(HEAPU8,ptr,maxBytesToRead):"";var ccall=(ident,returnType,argTypes,args,opts)=>{var toC={"string":str=>{var ret=0;if(str!==null&&str!==undefined&&str!==0){ret=stringToUTF8OnStack(str)}return ret},"array":arr=>{var ret=stackAlloc(arr.length);writeArrayToMemory(arr,ret);return ret}};function convertReturnValue(ret){if(returnType==="string"){return UTF8ToString(ret)}if(returnType==="boolean")return Boolean(ret);return ret}var func=getCFunc(ident);var cArgs=[];var stack=0;if(args){for(var i=0;i<args.length;i++){var converter=toC[argTypes[i]];if(converter){if(stack===0)stack=stackSave();cArgs[i]=converter(args[i])}else{cArgs[i]=args[i]}}}var ret=func.apply(null,cArgs);function onDone(ret){if(stack!==0)stackRestore(stack);return convertReturnValue(ret)}ret=onDone(ret);return ret};var wasmImports={e:_abort,b:alignfault,c:_emscripten_asm_const_int,d:_emscripten_resize_heap,a:segfault};var wasmExports=createWasm();var ___wasm_call_ctors=()=>(___wasm_call_ctors=wasmExports["g"])();var ___errno_location=()=>(___errno_location=wasmExports["__errno_location"])();var _free=Module["_free"]=a0=>(_free=Module["_free"]=wasmExports["i"])(a0);var _calloc=Module["_calloc"]=(a0,a1)=>(_calloc=Module["_calloc"]=wasmExports["j"])(a0,a1);var _autograph_authenticate=Module["_autograph_authenticate"]=(a0,a1)=>(_autograph_authenticate=Module["_autograph_authenticate"]=wasmExports["k"])(a0,a1);var _autograph_use_key_pairs=Module["_autograph_use_key_pairs"]=(a0,a1,a2,a3)=>(_autograph_use_key_pairs=Module["_autograph_use_key_pairs"]=wasmExports["l"])(a0,a1,a2,a3);var _autograph_use_public_keys=Module["_autograph_use_public_keys"]=(a0,a1)=>(_autograph_use_public_keys=Module["_autograph_use_public_keys"]=wasmExports["m"])(a0,a1);var _autograph_encrypt_message=Module["_autograph_encrypt_message"]=(a0,a1,a2,a3,a4)=>(_autograph_encrypt_message=Module["_autograph_encrypt_message"]=wasmExports["n"])(a0,a1,a2,a3,a4);var _autograph_ciphertext_size=Module["_autograph_ciphertext_size"]=a0=>(_autograph_ciphertext_size=Module["_autograph_ciphertext_size"]=wasmExports["o"])(a0);var _autograph_plaintext_size=Module["_autograph_plaintext_size"]=a0=>(_autograph_plaintext_size=Module["_autograph_plaintext_size"]=wasmExports["p"])(a0);var _autograph_session_size=Module["_autograph_session_size"]=a0=>(_autograph_session_size=Module["_autograph_session_size"]=wasmExports["q"])(a0);var _autograph_decrypt_message=Module["_autograph_decrypt_message"]=(a0,a1,a2,a3,a4,a5)=>(_autograph_decrypt_message=Module["_autograph_decrypt_message"]=wasmExports["r"])(a0,a1,a2,a3,a4,a5);var _autograph_certify_data=Module["_autograph_certify_data"]=(a0,a1,a2,a3)=>(_autograph_certify_data=Module["_autograph_certify_data"]=wasmExports["s"])(a0,a1,a2,a3);var _autograph_certify_identity=Module["_autograph_certify_identity"]=(a0,a1)=>(_autograph_certify_identity=Module["_autograph_certify_identity"]=wasmExports["t"])(a0,a1);var _autograph_verify_data=Module["_autograph_verify_data"]=(a0,a1,a2,a3,a4)=>(_autograph_verify_data=Module["_autograph_verify_data"]=wasmExports["u"])(a0,a1,a2,a3,a4);var _autograph_verify_identity=Module["_autograph_verify_identity"]=(a0,a1,a2)=>(_autograph_verify_identity=Module["_autograph_verify_identity"]=wasmExports["v"])(a0,a1,a2);var _autograph_close_session=Module["_autograph_close_session"]=(a0,a1,a2)=>(_autograph_close_session=Module["_autograph_close_session"]=wasmExports["w"])(a0,a1,a2);var _autograph_open_session=Module["_autograph_open_session"]=(a0,a1,a2,a3)=>(_autograph_open_session=Module["_autograph_open_session"]=wasmExports["x"])(a0,a1,a2,a3);var _autograph_read_size=Module["_autograph_read_size"]=a0=>(_autograph_read_size=Module["_autograph_read_size"]=wasmExports["y"])(a0);var _autograph_key_exchange=Module["_autograph_key_exchange"]=(a0,a1,a2)=>(_autograph_key_exchange=Module["_autograph_key_exchange"]=wasmExports["z"])(a0,a1,a2);var _autograph_verify_key_exchange=Module["_autograph_verify_key_exchange"]=(a0,a1)=>(_autograph_verify_key_exchange=Module["_autograph_verify_key_exchange"]=wasmExports["A"])(a0,a1);var _autograph_identity_key_pair=Module["_autograph_identity_key_pair"]=a0=>(_autograph_identity_key_pair=Module["_autograph_identity_key_pair"]=wasmExports["B"])(a0);var _autograph_ephemeral_key_pair=Module["_autograph_ephemeral_key_pair"]=a0=>(_autograph_ephemeral_key_pair=Module["_autograph_ephemeral_key_pair"]=wasmExports["C"])(a0);var _autograph_read_index=Module["_autograph_read_index"]=a0=>(_autograph_read_index=Module["_autograph_read_index"]=wasmExports["D"])(a0);var _emscripten_get_sbrk_ptr=()=>(_emscripten_get_sbrk_ptr=wasmExports["emscripten_get_sbrk_ptr"])();var _sbrk=a0=>(_sbrk=wasmExports["E"])(a0);var _emscripten_stack_get_base=()=>(_emscripten_stack_get_base=wasmExports["F"])();var stackSave=()=>(stackSave=wasmExports["G"])();var stackRestore=a0=>(stackRestore=wasmExports["H"])(a0);var stackAlloc=a0=>(stackAlloc=wasmExports["I"])(a0);var ___cxa_is_pointer_type=a0=>(___cxa_is_pointer_type=wasmExports["__cxa_is_pointer_type"])(a0);Module["ccall"]=ccall;var calledRun;dependenciesFulfilled=function runCaller(){if(!calledRun)run();if(!calledRun)dependenciesFulfilled=runCaller};function run(){if(runDependencies>0){return}preRun();if(runDependencies>0){return}function doRun(){if(calledRun)return;calledRun=true;Module["calledRun"]=true;if(ABORT)return;initRuntime();readyPromiseResolve(Module);if(Module["onRuntimeInitialized"])Module["onRuntimeInitialized"]();postRun()}if(Module["setStatus"]){Module["setStatus"]("Running...");setTimeout(function(){setTimeout(function(){Module["setStatus"]("")},1);doRun()},1)}else{doRun()}}if(Module["preInit"]){if(typeof Module["preInit"]=="function")Module["preInit"]=[Module["preInit"]];while(Module["preInit"].length>0){Module["preInit"].pop()()}}run();


  return moduleArg.ready
}
);
})();
;
export default Module;