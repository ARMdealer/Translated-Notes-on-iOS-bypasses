
Foreword

Through the previous article we introduced the principle from the kernel vulnerability to TFP0, and then to the root file system. Similar things that simple-writable rootfs can do is very limited, in order to do more things we often control the Binary binary or distribute their own binary to the system.

In order to ran yourself or others running on iOS, we have to sign this mountain. iOS only contains limited binary and system-level apps, their signature is Hardcode in a static TRUSTCACHE, for our own deployment binary, such as Passwd for modifying passwords, as well as Bash and Dropbear for SSH services. By default, it is unable to start, it will be directly killed by AMFID.
CODESIGN CHAIN

In iOS, when running a binary, the system will check the code signature from multiple angles in a responsible chain mode. After IOS 12, the entire code signature mainly contains three parts:

    Trustcache: A binary cdhash cache is divided into two parts: static cache and Dynamic Cache, and release directly when binary cdhash hits;
    Coretrust: the legitimacy check for the binary signature based on the apple root certificate;
    AMFI: MobileFileIntegrity, which is comparable to whether cdhash and binary actual CDHASH stored in the binary signature.

Trustcache

TrustCache is essentially a linear table of CDHASH. When the binary is executed, the system first calculates the binary CDHASH, then the TrustCache is subsequently lookup, if the hit is released. A static TrustCache is included in the iMage Image for accelerating system binary.

In addition to static TrustCache, the system also maintains a dynamic TrustCache for processing Xcode's signature issues for the Binary, which must be debugged. [1]. This is actually a simple solution for our BYPASS CODESIGN.
Coretrust

It mainly guarantees the legality of the binary signature, that is, the certificate used by the signature is issued by the Apple root certificate, which makes illegal signatures and non-signed binary not pass the check.
AMFI

If binary is not hysterer, after the Coretrust check (here does not consider Coretrust Cache), the message is sent to the real CODESIGN check, the core here is verified by the MISVALIDATESIGNATUREANDCOPYINFO method to verify the CDHASH in the actual CDHASH in the signature. .
Bypassing ideas

By discussing the above, we know the three main three rings of the entire CoDesign's responsible chain:
Plain

Trustcache (Static + Dynamic Cache Lookup) →
Coretrust (Deny Fake Signs, Must Sign With Certs from Apple) →
AMFI (CDHASH CHECK)

Trustcache Poisoning

The simplest solution is to tamper with Dynamic Trustcache, we first positioned the global variable of Dynamic Trustcache through XREF, which is a linked list, and each node of the linked list stores one or more binary cdhash, and these CDHASH is in dictionary Ascending arranging (for supporting two-point lookup).

We only need to find the global variable of Dynamic Cache, add a node for this linked list. This is discussed and code in the RootlessJB Write-Up [1] and various open source Jailbreak, the main start point is in PMAP_LOOKUP_IN_LOADED_TRUST_CACHES, this article does not expand.
Coretrust Bypass

In the RootlessJB Write-Up, it is mentioned in the Coretrust check in the Coretrust, but the process based on the Generation Count, but in order to construct a legitimate cache may require the process of constructing CS_BLOB in an analog XNU, then set a legal generation count. Although this approach skips AMFI, it is more complicated and compatible with backward compatibility.
AMFI BYPASS

AMFI provides service support for CODesign in the form of Mach Service. Since it is a C / S architecture, then a simple method is to fake a legal response. Since we already have TFP0, a very direct idea is to hijack AMFI related logic And return the signature legitimate message.

This article will mainly introduce the analysis process of AMFI BYPASS and implementation means.
How to debug amfi

After IOS 11, simply check Platform-Application, task_for_pid-allow and com.apple.system-task-ports are still unable attach to system binary, so we cannot debug AMFID by default.

In order to debug system binary, we must add TF_PLATFORM FLAG for its Task when spawn debugserver, followed by the breakpoint to work properly, we need to add CS_Debugged flag for its Proc:
c

Static Bool Patch_Proc (uint64_t proc) {
    Printf ("[*] Patch Proc 0x% LLX", Proc);
    UINT64_T OUR_TASK = RK64 (Proc + 0x10);
    Printf ("[*] Find Our Task AT 0x% LLX \ N", OUR_TASK);
    
    UINT32_T OUR_FLAGS = RK32 (OUR_TASK + 0x3b8);
    WK32 (Our_Task + 0x3b8, Our_Flags | 0x00000400);
    Printf ("[+] Give US TF_PLATFORM \ N");

    UINT32_T OUR_CSFLAGS = RK32 (Proc + 0x298);
    OUR_CSFLAGS = OUR_CSFLAGS | CS_DEBUGGED | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW;
    OUR_CSFLAGS = OUR_CSFLAGS & ~ (CS_HARD | CS_KILL | CS_RESTRICT);
    WK32 (Proc + 0x298, Our_CSFLAGS);
    Printf ("[+] Give US CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW \ N");
    Printf ("[+] Unrestrict Our PROC \ N");
    Return True;
}

This technology is included herein, which is included in the Qilin Toolkit but no open source, lacks support for iOS 13, we can turn it with Jakeajames Open source in rootlessjb [3]:
c

Int launchasplatform (Char * binary, char * arg1, char * arg2, char * arg3, char * arg4, char * arg5, char * arg6, char ** env) {
    PID_T PD;
    Const char * args [] = {binary, arg1, arg2, arg3, arg4, arg5, arg6, null}
    
    POSIX_SPAWNATTR_T ATTR;
    POSIX_SPAWNATTR_INIT (& ATTR);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    INT RV = POSIX_SPAWN (& PD, Binary, Null, & Attr, (Char **) & Args, ENV);
    
    Platformize (PD);
    
    Kill (PD, Sigcont); // Continue
    
    IF (! rv) {
        INT A;
        WaitPid (PD, & A, 0);
    }
    
    Return RV;
}

AMFI analysis

The author here is analyzed by iOS 13.1.1 iPad Air 2, we can find AMFID Binary from the iOS device / usr / libexec / amfid, after the anti-compilation, we started from Main:
c
void __fastcall __noreturn start(int a1, char **a2)
{
  char **argv; // x19
  int argc; // w20
  signed int v4; // w8
  signed int v5; // w22
  int hasDFlag; // w0
  __int64 v7; // x0
  void *v8; // x8
  int v9; // w1
  int v10; // w21
  int *v11; // x0
  char *v12; // x0
  const char *v13; // x1
  mach_port_t server_port; // [xsp+14h] [xbp-2Ch]
  struct dispatch_source_s *context; // [xsp+18h] [xbp-28h]
  dispatch_object_t v16; // 0:x0.8
  dispatch_object_t v17; // 0:x0.8

  argv = a2;
  argc = a1;
  v4 = 0;
  context = (struct dispatch_source_s *)-6148914691236517206LL;
  do
  {
    v5 = v4;
    hasDFlag = getopt(argc, argv, "d");
    v4 = 1;
  }
  while ( hasDFlag == 100 );
  if ( hasDFlag == -1 )
  {
    v7 = os_log_create("com.apple.MobileFileIntegrity", "amfid");
    v8 = &_os_log_default;
    if ( v7 )
      v8 = (void *)v7;
    amfi_logger = v8;
    if ( v5 )
      v9 = 33;
    else
      v9 = 1;
    if ( v5 )
      v10 = 255;
    else
      v10 = 63;
    openlog("amfid", v9, 24);
    setlogmask(v10);
    syslog(6, "starting");
    server_port = 0;
    if ( bootstrap_check_in(bootstrap_port, "com.apple.MobileFileIntegrity", &server_port) )
    {
      v11 = __error();
      v12 = strerror(*v11);
      syslog(3, "unable to checkin with launchd: %s", v12);
    }
    if ( server_port )
    {
      v16._do = dispatch_source_create(
                  (dispatch_source_type_t)&_dispatch_source_type_mach_recv,
                  server_port,
                  0LL,
                  (dispatch_queue_t)&_dispatch_main_q);
      context = v16._do;
      if ( v16._do )
      {
        dispatch_set_context(v16, &context);
        dispatch_source_set_event_handler_f(context, (dispatch_function_t)amfi_server_port_event_handler);
        v17._do = context;
        dispatch_resume(v17);
        dispatch_main();
      }
      v13 = "could not create mig source";
    }
    else
    {
      v13 = "could not get mach port";
    }
    syslog(3, v13);
    exit(1);
  }
  fprintf(__stderrp, "unrecognized argument '%c'\n", (unsigned int)optopt);
  exit(1);
}
This is a standard operation of LaunchDaemon. Get your own service port through bootstrap_port and listen. Focus on this sentence:
c

dispatch_source_set_event_handler_f(context, (dispatch_function_t)amfi_server_port_event_handler);

Here we get the handler of the server port, and we jump to the handler for analysis:

__int64 __fastcall amfi_server_port_event_handler(_QWORD *a1)
{
  _QWORD *v1; // x20
  __int64 v2; // x19
  __int64 v3; // x0

  v1 = a1;
  syslog(7, "%s: enter", "mig_source_handler");
  v2 = os_transaction_create("amfid mig server");
  v3 = dispatch_mig_server(*v1, 4184LL, amfi_mig_server_handler);
  if ( (_DWORD)v3 )
    syslog(3, "%s: dispatch_mig_server returned %d", "mig_source_handler", v3);
  syslog(7, "%s: exit", "mig_source_handler");
  return _os_release(v2);


  You can see that a mig server handler is included here, and we continue to analyze it down:
  signed __int64 __fastcall amfi_mig_server_handler(_DWORD *a1, __int64 a2)
{
  int v2; // w8
  int v3; // w8
  unsigned int some_index; // w8
  void (__cdecl *v5)(_DWORD *, __int64); // x8
  signed __int64 result; // x0

  *(_DWORD *)a2 = *a1 & 0x1F;
  v2 = a1[2];
  *(_DWORD *)(a2 + 4) = 36;
  *(_DWORD *)(a2 + 8) = v2;
  v3 = a1[5] + 100;
  *(_DWORD *)(a2 + 16) = 0;
  *(_DWORD *)(a2 + 20) = v3;
  *(_DWORD *)(a2 + 12) = 0;
  some_index = a1[5] - 1000;
  if ( some_index <= 4
    && (v5 = (void (__cdecl *)(_DWORD *, __int64))*(&off_100004090 + 5 * (signed int)some_index + 5)) != 0LL )
  {
    v5(a1, a2);
    result = 1LL;
  }
  else
  {
    result = 0LL;
    *(NDR_record_t *)(a2 + 24) = NDR_record;
    *(_DWORD *)(a2 + 32) = -303;
  }
  return result;
}

A dispatch table is included here, and off_100004090 is the head of the jump table:

some_index = a1[5] - 1000;
if ( some_index <= 4
&& (v5 = (void (__cdecl *)(_DWORD *, __int64))*(&off_100004090 + 5 * (signed int)some_index + 5)) != 0LL )
{
v5(a1, a2);
result = 1LL;
}

Lets take a look at the content of off_100004090:
__const:0000000100004090 off_100004090   DCQ mig_server_handler_inner_1
__const:0000000100004090                                         ; DATA XREF: mig_server_handler_inner_1+1C↑o
__const:0000000100004090                                         ; amfi_mig_server_handler+38↑o
// ...
__const:00000001000040B8                 DCQ mig_server_handler_inner_2
// ...
__const:00000001000040E0                 DCQ mig_server_handler_inner_3

We can see that there are 3 function pointers here, and different handlers will be selected to process the xpc message based on different indexes.

Here we can take dynamic debugging to find the handler that was actually called:

Here we can see that the actual handler used is located at 0x00000001000032c8, which is the mig_server_handler_inner_2 discussed above.

Next, follow the analysis of mig_server_handler_inner_2, which is a wrapper. The key parts are as follows:

__n128 __fastcall mig_server_handler_inner_2(NDR_record_t *ndr, __int64 a2) {
    // ...
    ret = amfi_verify_codesign(
        a1 = ndr[1].int_rep,     // via w0
        a2 = &ndr[5],            // via x1 = binpath
        a3 = ndr[8].int_rep,     // via x2
        a4 = ndr[9].int_rep,     // via w3
        a5 = ndr[10].mig_vers,   // via w4
        a6 = ndr[10].int_rep,    // via w5
        a7 = arg1 + 0x24,        // via x6
        a8 = arg1 + 0x28,        // via x7, switch keypoint
        a9 = arg1 + 0x2c,        // via x10
        a10 = arg1 + 0x30,       // via x9
        a11 = arg1 + 0x34,       // via x11
        a12 = arg1 + 0x38,       // via x12
        a13 = arg1 + 0x44,       // via x20, return cdhash
        a14 = &sp_cdhash_bytes,  // via x8
        a15 = &ndr[13].int_rep   // via x8-prev
    );
// ...
}

Continue to follow up amfi_verify_codesign, here is the key code:
uint64_t __fastcall amfi_verify_codesign(__int64 a1, __int64 a2, __int64 a3, char a4, __int64 a5, __int64 a6, _DWORD *a7, _DWORD *a8, _DWORD *a9, _DWORD *res_back_48, _DWORD *a11, _DWORD *a12, __int64 a13, __int64 cdhash_bytes, unsigned int *a15)
{
  _DWORD *res_back_40; // x19
  char v16; // w20
  __int64 bin_path; // x23
  uint64_t return_val; // x0
  uint64_t v19; // x25
  uint64_t binary_path; // x21
  __int64 cfdict; // x0
  uint64_t dict; // x22
  __int64 true_value; // x26
  uint64_t longnum_v; // x25
  __int64 error; // x0
  __int64 v26; // x25
  __int64 v27; // x0
  __int64 v28; // x24
  __int64 v29; // x23
  __int64 cdhash; // x23
  __int64 res_dict; // x25
  uint64_t singer_type; // x0
  __int64 cs_res_dict; // [xsp+50h] [xbp-170h]
  __int64 ndr_5_plus_reversed; // [xsp+58h] [xbp-168h]
  __int128 valuePtr; // [xsp+60h] [xbp-160h]
  __int128 v36; // [xsp+70h] [xbp-150h]
  __int128 v37; // [xsp+80h] [xbp-140h]
  __int128 v38; // [xsp+90h] [xbp-130h]
  __int128 v39; // [xsp+A0h] [xbp-120h]
  __int128 v40; // [xsp+B0h] [xbp-110h]
  __int128 v41; // [xsp+C0h] [xbp-100h]
  __int128 v42; // [xsp+D0h] [xbp-F0h]
  __int128 v43; // [xsp+E0h] [xbp-E0h]
  __int128 v44; // [xsp+F0h] [xbp-D0h]
  __int128 v45; // [xsp+100h] [xbp-C0h]
  __int128 v46; // [xsp+110h] [xbp-B0h]
  __int128 v47; // [xsp+120h] [xbp-A0h]
  __int128 v48; // [xsp+130h] [xbp-90h]
  __int128 v49; // [xsp+140h] [xbp-80h]
  __int128 v50; // [xsp+150h] [xbp-70h]
  __int64 v51; // [xsp+168h] [xbp-58h]

  res_back_40 = a8;
  v16 = a4;
  bin_path = a2;
  ndr_5_plus_reversed = a3;
  *a7 = 0;
  *a8 = 0;
  *res_back_48 = 0;
  *a11 = 0;
  *a12 = 0;
  *a9 = 0;
  *(_OWORD *)cdhash_bytes = 0uLL;               // x24 = cdhash_bytes out
  *(_DWORD *)(cdhash_bytes + 16) = 0;
  if ( !memcmp(a15, &unk_100003BB8, 0x20uLL) )
  {
    v19 = kCFAllocatorDefault;
    t
    if ( return_val )
    {
      binary_path = return_val;
      cfdict = CFDictionaryCreateMutable(v19, 0LL, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
      if ( cfdict )
      {
        dict = cfdict;
        true_value = kCFBooleanTrue;
        CFDictionarySetValue(cfdict, kMISValidationOptionValidateSignatureOnly, kCFBooleanTrue);
        CFDictionarySetValue(dict, kMISValidationOptionRespectUppTrustAndAuthorization, true_value);
        longnum_v = CFNumberCreate(v19, 0xBuLL, &ndr_5_plus_reversed);
        CFDictionarySetValue(dict, kMISValidationOptionUniversalFileOffset, longnum_v);
        CFRelease(longnum_v);
        cs_res_dict = 0LL;
        error = MISValidateSignatureAndCopyInfo(binary_path, dict, (uint64_t)&cs_res_dict);
        if ( (_DWORD)error )
        {
          // error
        }
        else if ( cs_res_dict
               && (v29 = CFGetTypeID(), v29 == CFDictionaryGetTypeID())
               && (cdhash = CFDictionaryGetValue(cs_res_dict, kMISValidationInfoCdHash)) != 0
               && (res_dict = CFGetTypeID(), res_dict == CFDataGetTypeID()) )
        {
          CFDataGetBytes(cdhash, 0LL, 20LL, cdhash_bytes);
          singer_type = CFDictionaryGetValue(cs_res_dict, kMISValidationInfoSignerType);
          if ( singer_type )
          {
            *(_QWORD *)&valuePtr = 0LL;
            if ( CFNumberGetValue(singer_type, 0xEuLL, &valuePtr) )
            {
              if ( (_QWORD)valuePtr == 5LL )
                *res_back_48 = 5;
            }
            else if ( (unsigned int)os_log_type_enabled(amfi_logger, 16LL) )
            {
              amfi_log_error_some(binary_path, &cs_res_dict);
            }
          }
          *res_back_40 = 1;
        }
        else
        {
          if ( (unsigned int)os_log_type_enabled(amfi_logger, 17LL) )
            amfi_log_error_some2(binary_path, dict, &cs_res_dict);
            *res_back_40 = 0;
        }
        if ( cs_res_dict )
          CFRelease(cs_res_dict);
        if ( v16 & 1 )
          *res_back_40 = 0;
        CFRelease(dict);
      }
      return_val = CFRelease(binary_path);
    }
  }
  else
  {
    // error
  }
  return return_val;
}

A few key parts here are as follows:

    Through return_val = CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault, bin_path); we can know that a2 is a binary path, which is passed in through ndr[5] and stored in x23;
    The key logic of signature verification is in MISValidateSignatureAndCopyInfo of libmis.dylib, the function must return 0 and a valid dict to continue the subsequent verification;
    Through CFDataGetBytes(cdhash, 0LL, 20LL, cdhash_bytes); completed the copy of binary cdhash, where the address of cdhash_bytes is stored in x24;
    res_back_40 is written with 0 in case of error and 1 in case of success, so it should represent the result of the verification, which is passed in through a8. By analyzing the Caller, it can be seen that the address of a8 is stored in x19.

Based on the above analysis, our main task is to forge res_back_40, but after experiments, it is found that it is not enough to simply forge the true/false of the result. We also need to write the actual cdhash of the binary into the address corresponding to x24 to perfectly simulate amfi_verify_codesign So as to pass the signature verification.
AMFI bypass

With the above analysis, we know that the key is to fake three things in amfi_verify_codesign:

    Calculate the real cdhash of binary and write it to the Caller Stack address corresponding to x24. You can get the binary path through x23 first, call the MIS method to complete the calculation and write it back;
    Hijack MISValidateSignatureAndCopyInfo to return 0;
    Set res_back_40 to 1.

These have very mature open source solutions in jelbrekLib of jakeajames [4]. The core idea is to obtain the task port of amfid, set an exception port for it, and write the address of its MISValidateSignatureAndCopyInfo symbol as an illegal value. When AMFI performs signature verification , we will receive the mach exception message, and then perform the above bypass operation and jump directly to the Epilogue of amfi_verify_codesign. Here are the addresses of several code implementations:

https://github.com/jakeajames/jelbrekLib/blob/master/amfid.m#L188
     https://github.com/coolstar/Chimera13/blob/master/Chimera13/post-exploit/utils/amfidtakeover.swift#L164

Summarize

This article briefly analyzes the codesign mechanism after iOS 12, and then starts with AMFI to analyze the principle and implementation process of the AMFI bypass scheme.


