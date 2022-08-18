foreword

In the previous article, we introduced the process of implementing kexec through IOTrap under non-arm64e. The main factor hindering this process for arm64e is the PAC (Pointer Authentication Code) mitigation, in this article we will describe the process of bypassing the PAC mechanism in Undecimus.

The whole bypass process is very complicated. The main reference of this article is Examining Pointer Authentication on the iPhone XS and the arm64e-related PAC Bypass code in Undecimus.
Some Features of PACs

What is PAC will not be repeated here. In short, it is a signature and verification protection mechanism for return addresses, global pointers, etc. Readers of detailed definitions and mechanisms can refer to the information by themselves. Here is only a simple example. Help understand PAC implementation.

The following code contains a global value variable and a dynamic function call based on the function pointer fptr. Guess which values will be protected by PAC?
// pac.cpp
#include <cstdio>

int g_somedata = 102;

int tram_one(int t) {
    printf("call tramp one %d\n", t);
    return 0;
}

void step_ptr(void *ptr) {
    *reinterpret_cast<void **>(ptr) = (void *)&tram_one;
}

int main(int argc, char **argv) {
    g_somedata += argc;
    void *fptr = NULL;
    step_ptr(fptr);
    (reinterpret_cast<int (*)(int)>(fptr))(g_somedata);
    return 0;
}

Below we use clang to compile and link cpp and generate assembly code under arm64e:
clang -S -arch arm64e -isysroot `xcrun --sdk iphoneos --show-sdk-path` -fno-asynchronous-unwind-tables pac.cpp -o pace.s

The resulting full assembly result is:
	.section	__TEXT,__text,regular,pure_instructions
	.build_version ios, 13, 0	sdk_version 13, 0
	.globl	__Z8tram_onei           ; -- Begin function _Z8tram_onei
	.p2align	2
__Z8tram_onei:                          ; @_Z8tram_onei
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #32             ; =32
	stp	x29, x30, [sp, #16]     ; 16-byte Folded Spill
	add	x29, sp, #16            ; =16
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	stur	w0, [x29, #-4]
	ldur	w0, [x29, #-4]
                                        ; implicit-def: $x1
	mov	x1, x0
	mov	x8, sp
	str	x1, [x8]
	adrp	x0, l_.str@PAGE
	add	x0, x0, l_.str@PAGEOFF
	bl	_printf
	mov	w9, #0
	str	w0, [sp, #8]            ; 4-byte Folded Spill
	mov	x0, x9
	ldp	x29, x30, [sp, #16]     ; 16-byte Folded Reload
	add	sp, sp, #32             ; =32
	retab
	.cfi_endproc
                                        ; -- End function
	.globl	__Z8step_ptrPv          ; -- Begin function _Z8step_ptrPv
	.p2align	2
__Z8step_ptrPv:                         ; @_Z8step_ptrPv
; %bb.0:
	sub	sp, sp, #16             ; =16
	adrp	x8, l__Z8tram_onei$auth_ptr$ia$0@PAGE
	ldr	x8, [x8, l__Z8tram_onei$auth_ptr$ia$0@PAGEOFF]
	str	x0, [sp, #8]
	ldr	x0, [sp, #8]
	str	x8, [x0]
	add	sp, sp, #16             ; =16
	ret
                                        ; -- End function
	.globl	_main                   ; -- Begin function main
	.p2align	2
_main:                                  ; @main
	.cfi_startproc
; %bb.0:
	pacibsp
	sub	sp, sp, #64             ; =64
	stp	x29, x30, [sp, #48]     ; 16-byte Folded Spill
	add	x29, sp, #48            ; =48
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	adrp	x8, _g_somedata@PAGE
	add	x8, x8, _g_somedata@PAGEOFF
	stur	wzr, [x29, #-4]
	stur	w0, [x29, #-8]
	stur	x1, [x29, #-16]
	ldur	w0, [x29, #-8]
	ldr	w9, [x8]
	add	w9, w9, w0
	str	w9, [x8]
	mov	x8, #0
	str	x8, [sp, #24]
	ldr	x0, [sp, #24]
	bl	__Z8step_ptrPv
	adrp	x8, _g_somedata@PAGE
	add	x8, x8, _g_somedata@PAGEOFF
	ldr	x0, [sp, #24]
	ldr	w9, [x8]
	str	x0, [sp, #16]           ; 8-byte Folded Spill
	mov	x0, x9
	ldr	x8, [sp, #16]           ; 8-byte Folded Reload
	blraaz	x8
	mov	w9, #0
	str	w0, [sp, #12]           ; 4-byte Folded Spill
	mov	x0, x9
	ldp	x29, x30, [sp, #48]     ; 16-byte Folded Reload
	add	sp, sp, #64             ; =64
	retab
	.cfi_endproc
                                        ; -- End function
	.section	__DATA,__data
	.globl	_g_somedata             ; @g_somedata
	.p2align	2
_g_somedata:
	.long	102                     ; 0x66

	.section	__TEXT,__cstring,cstring_literals
l_.str:                                 ; @.str
	.asciz	"call tramp one %d\n"


	.section	__DATA,__auth_ptr
	.p2align	3
l__Z8tram_onei$auth_ptr$ia$0:
	.quad	__Z8tram_onei@AUTH(ia,0)

.subsections_via_symbols

Return address protection

There are a few things to note here, the first is that PAC directives are inserted at the beginning and end of each nested call function:
__Z8tram_onei:
    pacibsp
    ; ...
    retab

    Here, the PAC uses Instruction Key B to protect the return address of the function, effectively preventing JOP attacks.

Take another look at the declaration and access of global variables:

.section	__DATA,__data
	.globl	_g_somedata             ; @g_somedata
	.p2align	2
_g_somedata:
	.long	102                     ; 0x66
	
	adrp	x8, _g_somedata@PAGE
	add	x8, x8, _g_somedata@PAGEOFF
	ldr	w9, [x8]

	It can be seen that regular numerical variables are not under the protection of PAC.
pointer protection

Let's take a look at the assignment and calling of function pointers:

int tram_one(int t) {
    printf("call tramp one %d\n", t);
    return 0;
}

void step_ptr(void *ptr) {
    *reinterpret_cast<void **>(ptr) = (void *)&tram_one;
}

int main(int argc, char **argv) {
    // ...
    void *fptr = NULL;
    step_ptr(fptr);
    (reinterpret_cast<int (*)(int)>(fptr))(g_somedata);
    return 0;
}

First of all, you can see that the global symbol of the tram_one function address is protected by PAC:

.section	__DATA,__auth_ptr
	.p2align	3
l__Z8tram_onei$auth_ptr$ia$0:
	.quad	__Z8tram_onei@AUTH(ia,0)

	The corresponding access code in the step_ptr function:

	__Z8step_ptrPv:
    ; ...
	adrp	x8, l__Z8tram_onei$auth_ptr$ia$0@PAGE
	ldr	x8, [x8, l__Z8tram_onei$auth_ptr$ia$0@PAGEOFF]
	; ...

	When executing the (reinterpret_cast<int (*)(int)>(fptr))(g_somedata); call, the instruction with PAC verification is taken:

	_main: 
    ; ...
    ; x8 = l__Z8tram_onei$auth_ptr$ia$0
    blraaz	x8
    Impact of PAC on JOP

In the previous article, the key to implementing kexec is to hijack a virtual function. The addresses modified here are:

     Modify the getTargetAndTrapForIndex pointer of the virtual function table to point to Gadget;
     Constructs an IOTrap with func pointing to the kernel function to execute.

Unfortunately, both addresses are protected by the PAC mechanism [1], so our previous kexec method fails on arm64e. The following code is taken from reference [1]:
loc_FFFFFFF00808FF00
    STR        XZR, [SP,#0x30+var_28]  ;; target = NULL
    LDR        X8, [X19]               ;; x19 = userClient, x8 = ->vtable
    ; 1. vtable is under protection
    AUTDZA     X8                      ;; validate vtable's PAC
    ; ...
    MOV        X0, X19                 ;; x0 = userClient
    ; 2. vtable->getTargetAndTrapForIndex is under protection
    BLRAA      X8, X9                  ;; PAC call ->getTargetAndTrapForIndex
    ; ...
    MOV        X9, #0                  ;; Use context 0 for non-virtual func
    B          loc_FFFFFFF00808FF70
    ; ...
loc_FFFFFFF00808FF70
   ; ... not set x9
   ; 3. trap->func is under protection
   BLRAA      X8, X9                  ;; PAC call func(target, p1, ..., p6)
   ; ...

As can be seen from the above code, in the iOS 12.1.2 kernel code of the arm64e architecture, the virtual function table, virtual function pointer and IOTrap function pointer are all protected by PAC.

It should be noted that the context register X9 used by the trap->func call here is written with 0, that is, BLRAA is equivalent to verifying the address of a PACIZA signature, which is an important breakthrough to realize the first restricted kexec .
Theoretical Analysis of Bypassing PAC
limitation factor

In the write-up of reference [1], a large amount of space is described about the analysis and bypass attempts of PAC from the perspective of software white box and hardware black box, and the following conclusions are obtained:

    The registers that store the PAC Key can only be accessed in EL1 mode, while the user mode is in EL0, and these system registers cannot be accessed directly;
    Even if we can read the PAC Key from the kernel's memory, if we can't reverse the complete encryption and decryption process, we still can't forge the signature;
    Apple uses different PAC Keys in EL0 and EL1, which breaks the Croess-EL PAC Forgeries;
    Apple uses different algorithms when implementing the PACIA, PACIB, PACDA and PACDB instructions, even if they all use the same Key, they will get different results, which breaks the Cross-Key Symmetry;
    Although the PAC Key is hardcoded at the software level, it turns out that the PAC Key changes every time it is started.

Each of these 5 restrictions stings the hearts of people who try to bypass the PAC. It can be seen that Apple has made a lot of perverted protection attempts to completely solve the JOP in this regard. In addition, Apple has also removed details related to PAC in the public XNU code, and prevented hackers from easily finding the available Signing Gadgets in the kernelcache by means of control flow obfuscation.
favorable conditions

I have to admire the skills of these kernel bosses. Even under such heavy protection, Brandon Azad still found some software vulnerabilities in the implementation of PAC:

    When the PAC checks the signature, if it finds that the signature fails, it will insert a 2-bit error code into the 62~61 area of ​​the pointer, which is pointer’s extension bits;
    When the PAC executes the signature, if it finds that the extension bits of the pointer are abnormal, it will still insert the correct signature, but it will invalidate the pointer by flipping the most significant bit (bit 62) of the PAC.

The interesting thing is that if we pass a regular address to the PAC for signature verification (AUT*), it will insert an error code into the extension bits of the pointer to make it abnormal. If the value is then signed (PAC*), the signature will fail due to the existence of the error code, but the correct PAC will still be calculated and inserted, but the 62nd bit of the pointer will be flipped. Therefore, we only need to find a code fragment that first performs AUT* on the value of the pointer, then PAC* and finally writes the value to the fixed memory, which can be used as a Signing Gadget.
PACIZA Signing Gadget

Based on the above theory, Brandon Azad found a code snippet in the arm64e kernelcache that satisfies the above favorable conditions:
void sysctl_unregister_oid(sysctl_oid *oidp)
{
   sysctl_oid *removed_oidp = NULL;
   sysctl_oid *old_oidp = NULL;
   BOOL have_old_oidp;
   void **handler_field;
   void *handler;
   uint64_t context;
   ...
   if ( !(oidp->oid_kind & 0x400000) )         // Don't enter this if
   {
       ...
   }
   if ( oidp->oid_version != 1 )               // Don't enter this if
   {
       ...
   }
   sysctl_oid *first_sibling = oidp->oid_parent->first;
   if ( first_sibling == oidp )                // Enter this if
   {
       removed_oidp = NULL;
       old_oidp = oidp;
       oidp->oid_parent->first = old_oidp->oid_link;
       have_old_oidp = 1;
   }
   else
   {
       ...
   }
   handler_field = &old_oidp->oid_handler;
   handler = old_oidp->oid_handler;
   if ( removed_oidp || !handler )             // Take the else
   {
       ...
   }
   else
   {
       removed_oidp = NULL;
       context = (0x14EF << 48) | ((uint64_t)handler_field & 0xFFFFFFFFFFFF);
       *handler_field = ptrauth_sign_unauthenticated(
               ptrauth_auth_function(handler, ptrauth_key_asia, &context),
               ptrauth_key_asia,
               0);
       ...
   }
   ...
}
It can be seen that there is a nested call of unauth and auth at the bottom of the code. First execute auth, namely AUT*, on the handler, and then immediately execute unauth, namely PAC*, which just satisfies the Signing Gadget condition. Another important condition is that the signature result must be written to stable memory so that we can read it easily and stably. The handler_field written here points to old_oidp->oid_handler, and the analysis shows that it comes from the oidp of the function input parameter.
Find Gadget

The key to the next step is how to trigger sysctl_unregister_oid and control the value of oidp. Fortunately sysctl_oid is held by the global sysctl tree and used to register parameters with the kernel. While there isn't any direct pointer to sysctl_unregister_oid, many kexts register parameters via sysctl at startup and unregister via sysctl_unregister_oid at the end, which is an important clue.

In the end, Brandon Azad found a pair of functions l2tp_domain_module_stop and l2tp_domain_module_start in the kext of com.apple.nke.lttp. When calling the former, it will pass a global variable sysctl__net_ppp_l2tp to achieve anti-registration. Calling the latter can restart the module, and this pair of functions Contains a locatable reference that is signed by the Instruction Key A without Context.

Remember that the address of the non-virtual function mentioned at the beginning of the article is also verified by Instruction Key A and no Context when calling IOTrap->func. Therefore, we only need to locate the function address and global variable address through XREF technology, then we can tamper with old_oidp->oid_handler by modifying sysctl__net_ppp_l2tp, and then we only need to find the method of calling l2tp_domain_module_stop to realize the PACIZA signature of any address.
Trigger Gadget

It seems that finding l2tp_domain_module_stop is as difficult as finding a kexec, but it is actually much simpler than a full kexec because l2tp_domain_module_stop is parameterless. We can still try to exploit IOTrap, but this time we can't hijack the virtual function, so we need to find an existing object that contains the IOTrap call.

Fortunately, Brandon Azad found an IOAudio2DeviceUserClient class in the kernelcache, which implements getTargetAndTrapForIndex by default and provides an IOTrap:

IOExternalTrap *IOAudio2DeviceUserClient::getTargetAndTrapForIndex(
       IOAudio2DeviceUserClient *this, IOService **target, unsigned int index)
{
   ...
   *target = (IOService *)this;
   return &this->IOAudio2DeviceUserClient.traps[index];
}

IOAudio2DeviceUserClient::initializeExternalTrapTable() {
    // ...
    this->IOAudio2DeviceUserClient.trap_count = 1;
    this->IOAudio2DeviceUserClient.traps = IOMalloc(sizeof(IOExternalTrap));
    // ...
}

The getTargetAndTrapForIndex here specifies target as itself, which makes the implicit parameters of the trap->func call unmodifiable, that is, arg0 cannot be passed in this way, and the parameterless function or code block can only be realized by tampering with trap->func call.

Based on the above discussion, the construction and invocation process of the entire PACIZA Signing Gadget is as follows:

    Start an IOAudio2DeviceService through the userland interface of IOKit, and obtain the mach_port handle of IOAudio2DeviceUserClient;
    Find its ipc_port through the handle, and its ip_kobject pointer points to the real IOAudio2DeviceUserClient object. First record the object address, and then find the traps address on the object. Since IOAudio2DeviceUserClient only declares one trap, the first address of the traps is the address of the IOTrap we want to modify;
    Locate the addresses of l2tp_domain_module_start, l2tp_domain_module_stop and sysctl__net_ppp_l2tp through String XREF technology, first cache the original sysctl_oid, then construct the sysctl_oid to satisfy the specific execution path of sysctl_unregister_oid, and finally assign sysctl_oid->oid_handler to the address that needs to be signed;
    Modify the trap found in step 2, point its func to l2tp_domain_module_stop, and trigger the IOTrap->func call of the IOAudio2DeviceUserClient object through IOConnectTrap6. Here, the call to l2tp_domain_module_stop is implemented, and then it will be executed to sysctl_unregister_oid, and the result of the signature failure will be written into sysctl__net_ppp_l2tp->oid_handler, at this point we can read the result and flip the 62nd bit to get the correct signature;
    The last step is to restart the service through l2tp_domain_module_start, but here you need to pass a new sysctl_oid as an input parameter, which cannot be done through the above Primitives.

clean up the environment

Since the IOTrap call of IOAudio2DeviceUserClient can only implement kexec without parameters, we cannot restart the IOAudio2DeviceUserClient service after completing the PACIZA signature, which will make the Signing Gadget lose idempotency, or leave other hidden dangers, so we must find a way to call kexec with parameters way to restart the service.

The crux of the problem is that arg0 points to this when IOTrap->func is called, so arg0 cannot be modified in a single call, we can try multiple jumps here. Fortunately, there is such a piece of code in kernelcache:

MOV         X0, X4
BR          X5

Since we can control x1 ~ x6 through IOConnectTrap6, we can indirectly control x0 through x4, and x5 is the address of the next hop. We first let IOTrap->func point to the PACIZA'd address of this segment, and then control arg0 through x4 , x1 ~ x3 controls arg1 ~ arg3, and x5 controls the target address of JOP, which can realize a 4-parameter kexec.

Therefore, we only need to use the above no-parameter call to sign the address of the above code block, and then use it as the address of IOTrap->func, and then control x1 ~ x5 through the input parameters of IOConnectTrap6 to realize the call to l2tp_domain_module_start with parameters, What is passed here is the previously backed up sysctl_oid, which perfectly restores the scene.

At this point, a perfect PACIZA Signing Gadget is achieved, and we also get the PACIZA signature of a very useful code snippet:
MOV         X0, X4
BR          X5

We call it G1, and this is an important gadget for follow-up work.
PACIA & PACDA Signing Gadget

Unfortunately, many call sites (such as virtual functions) are called with a Context, such as the snippet mentioned above:

context = (0x14EF << 48) | ((uint64_t)handler_field & 0xFFFFFFFFFFFF);
*handler_field = ptrauth_sign_unauthenticated(
       ptrauth_auth_function(handler, ptrauth_key_asia, &context),
       ptrauth_key_asia,
       0);


This requires us to find the code block that contains PACIA and PACDA, and they want to write the signed result to stable memory. Fortunately, such gadgets also exist:

; sub_FFFFFFF007B66C48
; ...
PACIA       X9, X10
STR         X9, [X2,#0x100]
; ...
PACDA       X9, X10
STR         X9, [X2,#0xF8]
; ...
PACIBSP
STP         X20, X19, [SP,#var_20]!
...         ;; Function body (mostly harmless)
LDP         X20, X19, [SP+0x20+var_20],#0x20
AUTIBSP
MOV         W0, #0
RET

This piece of code contains both PACIA and PACDA, and is subsequently written to memory through STR. The only downside is that there is still a long way to go from RET after executing the statement, and the current entry point is in the middle of the function. Fortunately, the real opening line of the function is after these instructions:

PACIBSP
STP         X20, X19, [SP,#var_20]!
; ...

So it seems that we will not have too many adverse effects by entering the function from the middle. Here we only need to control x9 as the pointer, x10 as the context, and x2 to control the written memory area, to achieve a PACIA & PACDA signature forgery.

However, based on the IOConnectTrap6 of IOAudio2DeviceUserClient, we can only control x1 ~ x6, and cannot directly control x9 and x10. Here we need to find more Gadgets to implement combined calls to control x9 and x10.

Brandon Azad then searched for several available Gadgets in the kernelcache, so far we have a total of 3 available Gadgets:


; G1
MOV         X0, X4
BR          X5

; G2
MOV         X9, X0
BR          X1

; G3
MOV         X10, X3
BR          X6

G1 allows us to control x0 via x4, then via G2 to write x0 to x9, and finally via G3 to write x3 to x10, G1 -> G2 via X5 pointing to G2, G2 -> G3 via X1 pointing to G3, and finally via x6 can jump to the Gadget containing PACIA & PACDA. At this time, x2, x9, and x10 have been filled with appropriate parameters indirectly, so a PACIA & PACDA Forgery can be completed.

The above calls are interlocked, and there cannot be any overlap on the registers, otherwise the parameters will not be able to be prepared effectively. We can hardly imagine how much energy it took to find such a set of Gadget, and I pay tribute to the big guy here. Based on the above discussion, we take G1 as the entry point of IOTrap->func and prepare the parameters of IOConnectTrap6 as follows:

trap->func = paciza(G1);
arg1 = x1 = G3;
arg2 = x2 = buffer_to_save_pacxad_pointer;
arg3 = x3 = context;
arg4 = x4 = pointer;
arg5 = x5 = G2;
arg6 = x6 = sub_FFFFFFF007B66C48_PACXA_ENTRY

This forms a chain of calls with the following control flow:

MOV         X0, X4 
BR          X5  
MOV         X9, X0
BR          X1
MOV         X10, X3
BR          X6
PACIA       X9, X10
STR         X9, [X2,#0x100]
; ...
PACDA       X9, X10
STR         X9, [X2,#0xF8]
; ...

So far, we have implemented Forgery of PACIA & PACDA through a series of Gadget and IOConnectTrap6.
perfect kexec

At this point, we can forge any signature of Key A, but we still have not achieved perfect kexec. At this time, we can only implement kexec with 4 parameters. The fundamental reason is that we rely on the default implementation of getTargetAndTrapForIndex by IOAudio2DeviceUserClient. Unfortunately, In this implementation, the target is set to this so that we cannot directly control arg0. After turning to Gadget, we will encounter the limitation of 4 parameters:

IOExternalTrap *IOAudio2DeviceUserClient::getTargetAndTrapForIndex(
       IOAudio2DeviceUserClient *this, IOService **target, unsigned int index)
{
   ...
   *target = (IOService *)this;
   return &this->IOAudio2DeviceUserClient.traps[index];
}

In order to achieve a perfect kexec, the best way is still to hijack virtual functions. Although PAC signs the virtual function table and virtual function pointer, it is done through Key A. Here we have been able to forge these signatures, thus Implement the hijacking of virtual functions again.
Modify getTargetAndTrapForIndex to be the default implementation

The overridden getTargetAndTrapForIndex implemented by IOAudio2DeviceUserClient gives us trouble, here we can modify it to the default implementation of the parent class:

IOExternalTrap * IOUserClient::
getTargetAndTrapForIndex(IOService ** targetP, UInt32 index)
{
      IOExternalTrap *trap = getExternalTrapForIndex(index);

      if (trap) {
              *targetP = trap->object;
      }

      return trap;
}

Since the traps of IOAudio2DeviceUserClient are not obtained through getExternalTrapForIndex, here we need to continue to modify the getExternalTrapForIndex method so that it can return a constructed IOTrap. One problem encountered here is that the default implementation of the parent class returns a null value:

IOExternalTrap * IOUserClient::
getExternalTrapForIndex(UInt32 index)
{
    return NULL;
}

This requires us to find a suitable function and member variable on IOUserClient, so that the function returns a member variable or a reference to a member variable, so that we can indirectly return a specific IOTrap by controlling the member variable. Fortunately, IOUserClient indirectly inherits the superclass IORegistryEntry, which contains a reserved member and a member function that returns this member:

class IORegistryEntry : public OSObject
{
// ...
protected:
/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

public:
    uint64_t IORegistryEntry::getRegistryEntryID( void )
    {
        if (reserved)
    	return (reserved->fRegistryEntryID);
        else
    	return (0);
    }

    It can be seen that we only need to point getExternalTrapForIndex in the virtual function table to IORegistryEntry::getRegistryEntryID, and then modify the reversed of the UserClient instance to make reserved->fRegistryEntryID point to the IOTrap we constructed.

Through the above transformation, we once again obtained a perfect kexec that supports 7 input parameters, which is easy to analyze theoretically, but it is very complicated to implement this process, because the sign context used by each virtual function is different, this It is required to dump all sign contexts before processing.
Code Guide for Bypassing PAC

After theoretical analysis, I believe that readers have an overall understanding of the whole bypassing process. Because the whole process is too complicated, theoretical analysis alone will inevitably make people confused. Combining the above theoretical analysis with reading the code in Undecimus can be very good. deepening understanding.

This part of the code is located in the two functions init_kexec and kexec mentioned in the previous article, and uses a completely different approach for the arm64e architecture. In view of the fact that the theoretical analysis part of this article has involved a large number of codes, the analysis is no longer complete here, and only a few things that are not fully mentioned in the theoretical analysis are mentioned. Please read the complete code in combination with the above theoretical analysis. I believe you will gain a lot.

After the above analysis, I believe readers can easily understand stage1_kernel_call_init and stage2_kernel_call_init in kernel_call_init. These two stages are mainly to complete the startup of UserClient and the signature of G1. It should be noted that a buffer is created at the end of stage2_kernel_call_init->stage1_init_kernel_pacxa_forging, Used to store the new vtable and the signed result of PACIA & PACDA:

static void
stage1_init_kernel_pacxa_forging() {
    // ...
    kernel_pacxa_buffer = stage1_get_kernel_buffer();
}
In addition, the PAC mechanism of A12 in iOS 12.1.2 also allows the userland to directly restore a signed pointer through the XPAC instruction, which brings great convenience to us copying the virtual function table. This code is located in stage3_kernel_call_init:

uint64_t
kernel_xpacd(uint64_t pointer) {
#if __arm64e__
	return xpacd(pointer);
#else
	return pointer;
#endif
}

static uint64_t *
stage2_copyout_user_client_vtable() {
	// Get the address of the vtable.
	original_vtable = kernel_read64(user_client);
	uint64_t original_vtable_xpac = kernel_xpacd(original_vtable);
	// Read the contents of the vtable to local buffer.
	uint64_t *vtable_contents = malloc(max_vtable_size);
	assert(vtable_contents != NULL);
	kernel_read(original_vtable_xpac, vtable_contents, max_vtable_size);
	return vtable_contents;
}

When patching the virtual function table, each function has its specific context, so the PAC Code dumped corresponding to each virtual function is used here. This code is located in stage2_patch_user_client_vtable:

static size_t
stage2_patch_user_client_vtable(uint64_t *vtable) {
// ...
#if __arm64e__
	assert(count < VTABLE_PAC_CODES(IOAudio2DeviceUserClient).count);
	vmethod = kernel_xpaci(vmethod);
	uint64_t vmethod_address = kernel_buffer + count * sizeof(*vtable);
	vtable[count] = kernel_forge_pacia_with_type(vmethod, vmethod_address,
			VTABLE_PAC_CODES(IOAudio2DeviceUserClient).codes[count]);
#endif // __arm64e__
	}
	return count;
}

Here, different PAC Codes are used for each virtual function. The dumped PAC Codes are stored in static variables and accessed with the help of the macro VTABLE_PAC_CODES. The length of each context here is only 16 bits:

static void
pac__iphone11_8__16C50() {
    INIT_VTABLE_PAC_CODES(IOAudio2DeviceUserClient,
    	0x3771, 0x56b7, 0xbaa2, 0x3607, 0x2e4a, 0x3a87, 0x89a9, 0xfffc,
    	0xfc74, 0x5635, 0xbe60, 0x32e5, 0x4a6a, 0xedc5, 0x5c68, 0x6a10,
    	0x7a2a, 0xaf75, 0x137e, 0x0655, 0x43aa, 0x12e9, 0x4578, 0x4275,
    	0xff53, 0x1814, 0x122e, 0x13f6, 0x1d35, 0xacb1, 0x7eb0, 0x1262,
    	0x82eb, 0x164e, 0x37a5, 0xb659, 0x6c51, 0xa20f, 0xb3b6, 0x6bcb,
    	0x5a20, 0x5062, 0x00d7, 0x7c85, 0x8a26, 0x3539, 0x688b, 0x1e60,
    	0x1955, 0x0689, 0xc256, 0xa383, 0xf021, 0x1f0a, 0xb4bb, 0x8ffc,
    	0xb5b9, 0x8764, 0x5d96, 0x80d9, 0x0c9c, 0x5d0a, 0xcbcc, 0x617d
    	// ...
    );
}

Other parts have basically been mentioned in the theoretical analysis, and will not be repeated here.
Summarize

This article describes the characteristics of the PAC mitigation and the bypass method for iOS 12.1.2 on the A12, and the whole process can be said to be breathtaking. By studying the entire bypass process, we not only have a deeper understanding of the PAC mechanism, but also learned a lot of JOP's tricky operations.
