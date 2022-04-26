foreword

In the previous article, we introduced the codesign mechanism of amfid and its bypass. amfid is a daemon of codesign logic in userland, representing the Server in the C/S architecture. This article will introduce amfi.kext on the kernel side, which is the client of amfid and is loaded and registered in the Kernel in the form of Kernel Extension.
Kernel Extension
definition

XNU is a feature-rich kernel that includes necessary services such as scheduling, memory management, I/O, etc., but it is still difficult to directly adapt to a vast array of hardware and peripherals, and even the macro kernel cannot fully do this [1] ].

Just like dylib is often included in user mode application, there are also kernel modules as extensions in kernel mode, which are called kernel extensions in XNU, abbreviated as kext[1].
Pre-Linking

From a conventional perspective, the operating system should boot the kernel first, and then load the kexts. In iOS, the kernel and its extensions do not exist as separate files, but the kernel and kexts are combined into a kernelcache file that is directly loaded by the boot loader.

Kernelcache brings two benefits, one is that kexts do not have to be dynamically linked like dylib, which saves the process of external symbol address resolution and speeds up the loading speed; the other is that kernelcache can be completely signed to reduce kext tampering risk [1].
Analyze AppleMobileFileIntegrity.kext
Detach from kernelcache

Since amfi.kext is prelinked into the kernelcache, its Info.plist and binary are directly included in the huge kernelcache. For the convenience of analysis, we can separate them from the kernelcache.
Separating kext binary via joker

Using joker (http://www.newosxbook.com/tools/joker.html) can separate out kexts and do partial symbolication:
# Specify output directory
> cd /tmp/kext
> export JOKER_DIR=/tmp/kext

# get readykernelcache
> ls .
kernelcache

# extract amfi.kext
> joker -K com.apple.driver.AppleMobileFileIntegrity kernelcache
Writing kext out to /tmp/kext/com.apple.driver.AppleMobileFileIntegrity.kext
Symbolicated stubs to /tmp/kext/com.apple.driver.AppleMobileFileIntegrity.kext.ARM64.E815A4DD-90E7-3A38-A4BA-EFA2425BC543

# view result
> ls .
com.apple.driver.AppleMobileFileIntegrity.kext
com.apple.driver.AppleMobileFileIntegrity.kext.ARM64.E815A4DD-90E7-3A38-A4BA-EFA2425BC543
kernelcache


It can be seen that we got the binary of kext and a symbol table. Since kext is separated from the kernel, similar to the separation of dylib from dyld_shared_cache, there are a large number of external addresses that cannot be parsed normally. They can be located through the symbol table or in the kernelcache. can help determine the meaning and content of these addresses.
Detach PRELINK_INFO with jtool

Similar to App describing key information through Info.plist, kext also has its Info.plist to describe various information of kext, which includes key information such as identifier, load address, etc. In order to facilitate analysis, we also need to separate amfi from kernelcache Info.plist. Here we use jtool (http://www.newosxbook.com/tools/jtool.html) to complete the separation:
# Specify output directory
export JTOOLDIR=/tmp/kext

# detach PRELINK_INFO
> jtool -e __PRELINK_INFO kernelcache
Requested segment found at offset 1e10000!
Extracting __PRELINK_INFO at 31522816, 2342912 (23c000) bytes into kernelcache.__PRELINK_INFO

# View product
> ls .
com.apple.driver.AppleMobileFileIntegrity.kext
com.apple.driver.AppleMobileFileIntegrity.kext.ARM64.E815A4DD-90E7-3A38-A4BA-EFA2425BC543
kernelcache
kernelcache.__PRELINK_INFO

Open kernelcache.__PRELINK_INFO and you can see that it contains a lot of information about the kexts that have been prelinked into the kernelcache, and a lot of base64-encoded Data Blobs are also mixed into them.
Find key information in PRELINK_INFO

Search for <key>_PrelinkBundlePath</key><string>/System/Library/Extensions/AppleMobileFileIntegrity.kext</string> in kernelcache.__PRELINK_INFO to locate the Info.plist of amfi.kext, which contains some of amfi.kext Key Information:
<dict>
  <key>BuildMachineOSBuild</key>
  <string>18A391011</string>
  <key>_PrelinkExecutableLoadAddr</key>
  <integer ID="32" size="64">0xfffffff005ab1980</integer>
  <key>CFBundlePackageType</key>
  <string>KEXT</string>
  <key>_PrelinkExecutableSourceAddr</key>
  <integer IDREF="32"/>
  <key>CFBundleDevelopmentRegion</key>
  <string>English</string>
  <key>MinimumOSVersion</key>
  <string>13.1</string>
  <key>CFBundleVersion</key>
  <string>1.0.5</string>
  <key>DTXcodeBuild</key>
  <string>11L374m</string>
  <key>DTPlatformBuild</key>
  <string ID="33"/>
  <key>_PrelinkBundlePath</key>
  <string>/System/Library/Extensions/AppleMobileFileIntegrity.kext</string>
  <key>_PrelinkExecutableSize</key>
  <integer size="64">0x5211</integer>
  <key>_PrelinkKmodInfo</key>
  <integer size="64">0xfffffff0077e51c8</integer>
  <key>UIDeviceFamily</key>
  <array>
    <integer IDREF="10"/>
  </array>
  <key>OSBundleRequired</key>
  <string>Root</string>
  <key>CFBundleIdentifier</key>
  <string>com.apple.driver.AppleMobileFileIntegrity</string>
  <key>DTXcode</key>
  <string>1100</string>
  <key>CFBundleExecutable</key>
  <string IDREF="31"/>
</dict>

The fields starting with _Prelink are very important:

<dict>
  <key>_PrelinkExecutableLoadAddr</key>
  <integer ID="32" size="64">0xfffffff005ab1980</integer>
  <key>_PrelinkExecutableSourceAddr</key>
  <integer ID="32" size="64">0xfffffff005ab1980</integer>
  <key>_PrelinkBundlePath</key>
  <string>/System/Library/Extensions/AppleMobileFileIntegrity.kext</string>
  <key>_PrelinkExecutableSize</key>
  <integer size="64">0x5211</integer>
  <key>_PrelinkKmodInfo</key>
  <integer size="64">0xfffffff0077e51c8</integer>
  <key>CFBundleIdentifier</key>
  <string>com.apple.driver.AppleMobileFileIntegrity</string>
</dict>

The meanings of these fields are as follows [1]:

     _PrelinkExecutableSourceAddr: The starting address of the kext, that is, the Mach-O Header address of the kext;
     _PrelinkExecutableLoadAddr: The load address of kext in memory. For prelink kext, this value is generally equal to _PrelinkExecutableSourceAddr;
     _PrelinkKmodInfo: The object model of the kext in the Mach layer.

Let's take a general look at the contents of these addresses. The first is _PrelinkExecutableSourceAddr, which is the starting point of kext loading. You can see that this is a standard Mach-O Header structure:

Next is _PrelinkKmodInfo, which is a kmod_info_t structure:
typedef struct kmod_info {
    struct kmod_info  * next;
    int32_t             info_version;       // version of this structure
    uint32_t            id;
    char                name[KMOD_MAX_NAME];
    char                version[KMOD_MAX_NAME];
    int32_t             reference_count;    // # linkage refs to this
    kmod_reference_t  * reference_list;     // who this refs (links on)
    vm_address_t        address;            // starting address
    vm_size_t           size;               // total size
    vm_size_t           hdr_size;           // unwired hdr size
    kmod_start_func_t * start;
    kmod_stop_func_t  * stop;
} kmod_info_t;

Guess how modules are loaded

From the experience of user mode, the Mach-O Header here may contain a structure similar to LC_MAIN to identify the Entry Point, or the start and stop functions in kmod_info may contain the key logic of registration.

Unfortunately, there is no Entry Point in the Mach-O Header of amfi.kext, and the start and stop functions in kmod_info are empty implementations, which means that there must be other loading methods for this kind of prelink kext to be explored.
Registration of AppleMobileFileIntegrity.kext

After some analysis and research I found that the loading logic about kext has been gradually moved to libkern. The key logic for maintaining kext is located in libkern/c++/OSKext.cpp, and at the same time in user mode, the interaction with kext can be completed through I/O Kit [1].

I/O Kit-based kexts are mounted in the IO device tree as drivers, and kext operations can be implemented through Mach messages, such as OSKextLoadKextWithIdentifier to load a kext:
kern_return_t
OSKextLoadKextWithIdentifier(const char * bundle_id)
{
    return OSKext::loadKextWithIdentifier(bundle_id);
}

The key logic here is to find the corresponding OSKext object in a global registry sKextsByID and perform the load operation, then the key to the problem is how the kext is added to sKextsByID.

We mentioned earlier that prelink kexts records information through PRELINK_INFO. When initializing the I/O Kit in the boot phase of the kernel, _start -> _start_first_cpu -> arm_init -> machine_startup -> kernel_bootstrap -> kernel_bootstrap_thread -> PE_init_iokit -> StartIOKit -> bootstrapRecordStartupExtensions - > KLDBootstrap::readStartupExtensions -> readPrelinkedExtensions -> OSKext::withPrelinkedInfoDict -> OSKext::initWithPrelinkedInfoDict to load prelinked kexts one by one according to the Info in PRELINK_INFO.
From launch to registration

Let's start with the OSKext::initWithPrelinkedInfoDict method to study the loading method of kexts:
bool
OSKext::initWithPrelinkedInfoDict(
	OSDictionary * anInfoDict,
	bool doCoalesedSlides) {
    // ...
    addressNum = OSDynamicCast(OSNumber, anInfoDict->getObject("_PrelinkKmodInfo"));
    if (addressNum->unsigned64BitValue() != 0) {
        kmod_info = (kmod_info_t *) ml_static_slide((intptr_t) (addressNum->unsigned64BitValue()));
        kmod_info->address = ml_static_slide(kmod_info->address);
    }
    
    // ...
    flags.prelinked = true;
    sPrelinkBoot = true;
    result = registerIdentifier();
    
    // ...
    return result;
}

Here is mainly the processing of Info.plist corresponding to kext, including initializing kmod_info, setting binary of kext and setting kext flags, etc. The most critical step here is to add yourself to the global registry through registerIdentifier:
bool
OSKext::registerIdentifier(void)
{
    // ...
    /* If we don't have an existing kext with this identifier,
     * just record the new kext and we're done!
     */
    existingKext = OSDynamicCast(OSKext, sKextsByID->getObject(bundleID));
    if (!existingKext) {
    	sKextsByID->setObject(bundleID, this);
    	result = true;
    	goto finish;
    }
    
    // ...
    return true;
}

The first registration logic here is very simple, which is to add the kext to the global registry sKextsByID with the bundleID as the key. The version resolution logic of the second registration of the same kext is omitted here.
Loading of AppleMobileFileIntegrity.kext

After registration, let's take a look at the loading of prelinked kext. At the beginning, the author always thought that amfi.kext was loaded based on libKern's kext_request, and I failed to find cross-references between codes and bundleIDs in many places. I found that prelinked kext loading was also hidden in the startup process, and the bridge between loading and registration was global registration. Table sKextsByID.
Loader injection

We mentioned earlier in the registration process that there is a call from StartIOKit -> bootstrapRecordStartupExtensions, and the corresponding code in StartIOKit is:

void (*record_startup_extensions_function)(void) = NULL;

void
StartIOKit( void * p1, void * p2, void * p3, void * p4 ) {
    // ...
    /* If the bootstrap segment set up a function to record startup
     * extensions, call it now.
     */
    if (record_startup_extensions_function) {
    	record_startup_extensions_function();
    }
    // ...
}

Here record_startup_extensions_function is injected in the constructor of KLDBootstrap:

/*********************************************************************
* Set the function pointers for the entry points into the bootstrap
* segment upon C++ static constructor invocation.
*********************************************************************/
KLDBootstrap::KLDBootstrap(void)
{
    if (this != &sBootstrapObject) {
    	panic("Attempt to access bootstrap segment.");
    }
    record_startup_extensions_function = &bootstrapRecordStartupExtensions;
    load_security_extensions_function = &bootstrapLoadSecurityExtensions;
}

The implementation of record_startup_extensions_function called by StartIOKit is bootstrapRecordStartupExtensions in the registration process. In addition, bootstrapLoadSecurityExtensions is injected as implementation for load_security_extensions_function. The bootstrapLoadSecurityExtensions here is the loading logic of the kext, which corresponds to the registration logic bootstrapRecordStartupExtensions.
Loader's Caller

So who is responsible for calling bootstrapLoadSecurityExtensions to load these kexts? By searching the code we can find the logic located in the MAC:
/* Function pointer set up for loading security extensions.
 * It is set to an actual function after OSlibkernInit()
 * has been called, and is set back to 0 by OSKextRemoveKextBootstrap()
 * after bsd_init().
 */
void (*load_security_extensions_function)(void) = 0;

/*
 * Init after early Mach startup, but before BSD
 */
void
mac_policy_initmach(void)
{
    /*
     * For the purposes of modules that want to know if they were
     * loaded "early", set the mac_late flag once we've processed
     * modules either linked into the kernel, or loaded before the
     * kernel startup.
     */
    
    if (load_security_extensions_function) {
    	load_security_extensions_function();
    }
    mac_late = 1;
}

The full name of MAC here is Mandatory Access Control, which is a more fine-grained operating system security model based on Trusted BSD to provide object-level security control. And the Caller of mac_policy_initmach is kernel_bootstrap_thread:

/*
 * Now running in a thread.  Kick off other services,
 * invoke user bootstrap, enter pageout loop.
 */
static void
kernel_bootstrap_thread(void)
{
    // ...
#ifdef  IOKIT
    kernel_bootstrap_log("PE_init_iokit");
    PE_init_iokit();
#endif

    // ...
#if CONFIG_MACF
    kernel_bootstrap_log("mac_policy_initmach");
    mac_policy_initmach();
    // ...
}

It can be seen that the registration of PE_init_iokit and the loading of mac_policy_initmach are called successively, so as to ensure that the registered Security Kexts can be obtained when mac_policy_initmach is executed.
load logic

The loading logic mentioned earlier is located in bootstrapLoadSecurityExtensions:
static void
bootstrapLoadSecurityExtensions(void)
{
    sBootstrapObject.loadSecurityExtensions();
    return;
}

void
KLDBootstrap::loadSecurityExtensions(void)
{
    // ...
    // OSKext::copyKexts()
    extensionsDict = OSDynamicCast(OSDictionary, sKextsByID->copyCollection());
    // ...
    keyIterator = OSCollectionIterator::withCollection(extensionsDict);
    // ...
    while ((bundleID = OSDynamicCast(OSString, keyIterator->getNextObject()))) {
        const char * bundle_id = bundleID->getCStringNoCopy();
        
        /* Skip extensions whose bundle IDs don't start with "com.apple.".
         */
        if (!bundle_id ||
            (strncmp(bundle_id, "com.apple.", CONST_STRLEN("com.apple.")) != 0)) {
        	continue;
        }
        
        theKext = OSDynamicCast(OSKext, extensionsDict->getObject(bundleID));
        if (!theKext) {
    	    continue;
        }
        
        if (kOSBooleanTrue == theKext->getPropertyForHostArch(kAppleSecurityExtensionKey)) {
    	    OSKext::loadKextWithIdentifier(bundleID->getCStringNoCopy(),
        	    /* allowDefer */ false);
        }
    }
    // ...
}
Here, the loadKextWithIdentifier method is executed by traversing sKextsByID, and OSKext::load -> OSKext::loadExecutable (register kmod_info) and OSKext::start -> OSRuntimeInitializeCPP will be executed later.

Among them, OSKext::load contains registration to IOKit, and OSRuntimeInitializeCPP completes some C++ environment initialization of libkern.
AppleMobileFileIntegrity.kext is registered with IOKit
Register and start the service

Let's look at the load phase first. The OSKext::load function contains such a piece of logic at the end:

/* If not excluding matching, send the personalities to the kernel.
 * This never affects the result of the load operation.
 * This is a bit of a hack, because we shouldn't be handling
 * personalities within the load function.
 */
OSReturn
OSKext::load(
	OSKextExcludeLevel   startOpt,
	OSKextExcludeLevel   startMatchingOpt,
	OSArray            * personalityNames) 
{
    // ...
    if (result == kOSReturnSuccess && startMatchingOpt == kOSKextExcludeNone) {
        result = sendPersonalitiesToCatalog(true, personalityNames);
    }
    // ...
}

The so-called Personalities are IOKitPersonalities, which are used to describe the characteristics of the driver so that IOKit can correctly load and match services.

OSKext::sendPersonalitiesToCatalog will then call gIOCatalogue->addDrivers(personalitiesToSend, startMatching), where gIOCatalogue is a global IOCatalogue object, which is a database of all IOKIt-driven personalities, through which IOKit matches related services [2].

gIOCatalogue->addDrivers will then call IOService::catalogNewDrivers -> IOService::startMatching -> IOService::doServiceMatch:

void
IOService::doServiceMatch( IOOptionBits options )
{
    // ...
    while (keepGuessing) {
    	matches = gIOCatalogue->findDrivers( this, &catalogGeneration );
        // the matches list should always be created by findDrivers()
        if (matches) {
            if (0 == (__state[0] & kIOServiceFirstPublishState)) {
                getMetaClass()->addInstance(this);
                // ...
            }
            
            if (keepGuessing && matches->getCount() && (kIOReturnSuccess == getResources())) {
                if ((this == gIOResources) || (this == gIOUserResources)) {
                    if (resourceKeys) {
                        resourceKeys->release();
                    }
                    resourceKeys = copyPropertyKeys();
                }
                probeCandidates( matches );
            }
            // ...
        }
    }
    // ...
}

Here getMetaClass()->addInstance(this) and probeCandidates( matches ) are two key calls, let's look at the former first:
/* Class global data */
OSObject::MetaClass OSObject::gMetaClass;

const OSMetaClass *
OSObject::getMetaClass() const
{
    return &gMetaClass;
}

Here gMetaClass is a global object of Class dimension, addInstance adds the IOService instance of kext to the list of this Class dimension to associate all IOService instances associated with the class object:
void
OSMetaClass::addInstance(const OSObject * instance, bool super) const
{
    if (!super) {
        IOLockLock(sInstancesLock);
    }
    
    if (!reserved->instances) {
        reserved->instances = OSOrderedSet::withCapacity(16);
        if (superClassLink) {
            superClassLink->addInstance(reserved->instances, true);
        }
    }
    reserved->instances->setLastObject(instance);
    
    if (!super) {
        IOLockUnlock(sInstancesLock);
    }
}

Here gMetaClass->reserved->instances will be used to obtain the IOService instance corresponding to amfi during Service Matching.

Next, take a look at the call probeCandidates( matches ), which will call IOService::startCandidate -> IOService::start to complete amfi's IOService startup.
AMFI boot process

In amfi.kext we can find the IOService::start start method:
bool __cdecl AMFI::start_IOService(uint64_t *a1)
{
  uint64_t *v1; // x19

  v1 = a1;
  if ( !(*((unsigned int (**)(void))IORegistryEntry::gMetaClass + 88))() )
    ((void (*)(void))loc_FFFFFFF006075D18)();
  initializeAppleMobileFileIntegrity();
  if ( *(_DWORD *)cs_debug )
    IOLog("%s: built %s %s\n", "virtual bool AppleMobileFileIntegrity::start(IOService *)", "Sep  3 2019", "22:15:18");
  (*(void (__fastcall **)(uint64_t *, _QWORD))(*v1 + 672))(v1, 0LL);
  return 1;
}

The core initialization method here is initializeAppleMobileFileIntegrity, which includes the registration of codesign-related MAC Policy Modules and Handlers. These Handlers verify specific system calls in the form of aspects, such as mpo_vnode_check_signature using in-kernel signature cache and amfid for file verification Code signature verification. The specific logic of initializeAppleMobileFileIntegrity and how it interacts with amfid will be described in detail in the next article.

Initialize libkern C++ environment

kern_return_t
OSRuntimeInitializeCPP(
	OSKext                   * theKext)
{
    // ...
    /* Tell the meta class system that we are starting the load
	 */
    metaHandle = OSMetaClass::preModLoad(kmodInfo->name);
    
    // ...
    /* Scan the header for all constructor sections, in any
	 * segment, and invoke the constructors within those sections.
	 */
    for (segment = firstsegfromheader(header);
        segment != NULL && load_success;
        segment = nextsegfromheader(header, segment)) {
    	/* Record the current segment in the event of a failure.
    	 */
    	failure_segment = segment;
    	load_success = OSRuntimeCallStructorsInSection(
    		theKext, kmodInfo, metaHandle, segment,
    		sectionNames[kOSSectionNameInitializer],
    		textStart, textEnd);
    } /* for (segment...) */
    
    // ...
    /* Now, regardless of success so far, do the post-init registration
     * and cleanup. If we had to call the unloadCPP function, static
     * destructors have removed classes from the stalled list so no
     * metaclasses will actually be registered.
     */
    result = OSMetaClass::postModLoad(metaHandle);
    // ...
}

Pre stage

The loading here mainly consists of 3 stages, of which the pre stage is mainly to prepare the loading context of the Main Class of the kext. The context here is saved by a global variable, and a serial queue is guaranteed by a lock:
/*
 * While loading a kext and running all its constructors to register
 * all OSMetaClass classes, the classes are queued up here. Only one
 * kext can be in flight at a time, guarded by sStalledClassesLock
 */
static struct StalledData {
    const char   * kextIdentifier;
    OSReturn       result;
    unsigned int   capacity;
    unsigned int   count;
    OSMetaClass ** classes;
} * sStalled;
IOLock * sStalledClassesLock = NULL;

void *
OSMetaClass::preModLoad(const char * kextIdentifier)
{
    IOLockLock(sStalledClassesLock);
    
    assert(sStalled == NULL);
    sStalled = (StalledData *)kalloc_tag(sizeof(*sStalled), VM_KERN_MEMORY_OSKEXT);
    if (sStalled) {
    	sStalled->classes = (OSMetaClass **)kalloc_tag(kKModCapacityIncrement * sizeof(OSMetaClass *), VM_KERN_MEMORY_OSKEXT);
    	if (!sStalled->classes) {
            kfree(sStalled, sizeof(*sStalled));
            return NULL;
    	}
    	OSMETA_ACCUMSIZE((kKModCapacityIncrement * sizeof(OSMetaClass *)) +
    	    sizeof(*sStalled));
    
    	sStalled->result   = kOSReturnSuccess;
    	sStalled->capacity = kKModCapacityIncrement;
    	sStalled->count    = 0;
    	sStalled->kextIdentifier = kextIdentifier;
    	bzero(sStalled->classes, kKModCapacityIncrement * sizeof(OSMetaClass *));
    }
    
    // keep sStalledClassesLock locked until postModLoad
    
    return sStalled;
}

In stage

The subsequent code scans all __mod_init_func sections in the kext through OSRuntimeCallStructorsInSection and calls these initialization functions, here we can open IDA to see which initialization functions __mod_init_func contains:
__mod_init_func:FFFFFFF006DF41A0 ; Segment type: Pure data
__mod_init_func:FFFFFFF006DF41A0   AREA __mod_init_func, DATA, ALIGN=3
__mod_init_func:FFFFFFF006DF41A0 ; ORG 0xFFFFFFF006DF41A0
__mod_init_func:FFFFFFF006DF41A0   DCQ InitFunc_0
__mod_init_func:FFFFFFF006DF41A8   DCQ InitFunc_1
__mod_init_func:FFFFFFF006DF41B0   DCQ InitFunc_2
__mod_init_func:FFFFFFF006DF41B0 ; __mod_init_func ends

It can be seen that there are 3 initialization functions in amfi.kext, of which InitFunc_1 is the initialization function of some global variables, InitFunc_0 and InitFunc_2 are the initialization functions of some Main Classes of AMFI, we will focus on InitFunc_2 here:
_QWORD *InitFunc_2()
{
    _QWORD *result; // x0
    result = (_QWORD *)OSMetaClass::OSMetaClass(&some_this, "AppleMobileFileIntegrity", some_inSuperClass, 136LL);
    *result = some_vtable;
    return result;
}

The OSMetaClass::OSMetaClass here is the core constructor of the class. It actually adds the class to the OSMetaClass global context sStalled->classes for use in the post process. The Grow logic of the class list is omitted here:

/*********************************************************************
* The core constructor for a MetaClass (defined with this name always
* but within the scope of its represented class).
*
* MetaClass constructors are invoked in OSRuntimeInitializeCPP(),
* in between calls to OSMetaClass::preModLoad(), which sets up for
* registration, and OSMetaClass::postModLoad(), which actually
* records all the class/kext relationships of the new MetaClasses.
*********************************************************************/

OSMetaClass::OSMetaClass(
	const char        * inClassName,
	const OSMetaClass * inSuperClass,
	unsigned int        inClassSize)
{
    // ...
    sStalled->classes[sStalled->count++] = this;
    // ...
}

Post stage

The post phase is mainly to maintain the relationship between kext and classes:
OSReturn
OSMetaClass::postModLoad(void * loadHandle)
{
    // ...
    // static OSDictionary * sAllClassesDict;
    sAllClassesDict = OSDictionary::withCapacity(kClassCapacityIncrement);
    sAllClassesDict->setOptions(OSCollection::kSort, OSCollection::kSort);
    myKextName = const_cast<OSSymbol *>(OSSymbol::withCStringNoCopy(
				    sStalled->kextIdentifier));
    myKext = OSKext::lookupKextWithIdentifier(myKextName);
    
    /* First pass checking classes aren't already loaded. If any already
     * exist, we don't register any, and so we don't technically have
     * to do any C++ teardown.
     *
     * Hack alert: me->className has been a C string until now.
     * We only release the OSSymbol if we store the kext.
     */
    IOLockLock(sAllClassesLock);
    for (unsigned int i = 0; i < sStalled->count; i++) {
        const OSMetaClass * me = sStalled->classes[i];
        
        unsigned int depth = 1;
        while ((me = me->superClassLink)) {
            depth++;
        }
        
        // static unsigned int sDeepestClass;
        if (depth > sDeepestClass) {
            sDeepestClass = depth;
        }
    }
    IOLockUnlock(sAllClassesLock);
    
    IOLockLock(sAllClassesLock);
    for (unsigned int i = 0; i < sStalled->count; i++) {
        const OSMetaClass * me = sStalled->classes[i];
        OSMetaClass * me = sStalled->classes[i];
        me->className = OSSymbol::withCStringNoCopy((const char *)me->className);
        sAllClassesDict->setObject(me->className, me);
        me->reserved->kext = myKext;
        myKext->addClass(me, sStalled->count);
    }
    IOLockLock(sAllClassesLock);
    
    sBootstrapState = kCompletedBootstrap;
    sStalled = NULL;
    return kOSReturnSuccess;
}

After the post process is completed, all OSMetaClass instances of kext are recorded in the global registry sAllClassesDict in the form of name2instance, and each OSMetaClass instance also maintains the corresponding relationship of instance2kext (me->reserved->kext = myKext), Each kext also maintains all the instances that belong to him (myKext->addClass(me, sStalled->count)). This ensures that the instance can be found through the class name, and the corresponding OSKext object can be found through the instance, and all the OSMetaClass instances belonging to it can also be obtained through the OSKext object.
Get the AppleMobileFileIntegrity.kext service

We searched the kernelcache for a cross-reference of the "AppleMobileFileIntegrity" string to find the code that accesses the AMFI service via IOService, such as initAMFI in com.apple.security.sandbox:
__int64 initAMFI()
{
  OSDictionary *matchDict_1; // x0
  OSDictionary *v1; // x19
  IOService *v2; // x0
  __int64 v4; // x0
  __int64 matchDict; // [xsp+8h] [xbp-18h]

  matchDict = 0LL;
  matchDict_1 = (OSDictionary *)IOService::nameMatching("AppleMobileFileIntegrity", 0LL);
  // ...
  v1 = matchDict_1;
  v2 = IOService::waitForMatchingService(matchDict_1, 0xFFFFFFFFFFFFFFFFLL);
  matchDict = OSMetaClassBase::safeMetaCast(v2, *(_QWORD *)qword_FFFFFFF006F9D038);
  // ...
}

Here we first use IOService::nameMatching to construct an OSDictionary:
{
    "IONameMatch": "AppleMobileFileIntegrity"
}

Then match the service through IOService::waitForMatchingService, and the core logic is as follows:
IOService *
IOService::waitForMatchingService( OSDictionary * matching,
    uint64_t timeout) {
    // ...
    do {
    	result = (IOService *) copyExistingServices( matching,
    	    kIOServiceMatchedState, kIONotifyOnce );
    	// ...
}

OSObject *
IOService::copyExistingServices( OSDictionary * matching,
    IOOptionBits inState, IOOptionBits options ) {
    // ...
    IOServiceMatchContext ctx;
    ctx.table   = matching;
    ctx.state   = inState;
    ctx.count   = 0;
    ctx.done    = 0;
    ctx.options = options;
    ctx.result  = NULL;
    
    IOService::gMetaClass.applyToInstances(instanceMatch, &ctx);
    // ...
}

void
OSMetaClass::applyToInstances(OSMetaClassInstanceApplierFunction applier,
    void * context) const
{
    IOLockLock(sInstancesLock);
    if (reserved->instances) {
        applyToInstances(reserved->instances, applier, context);
    }
    IOLockUnlock(sInstancesLock);
}

It can be seen that the match is achieved by traversing all IOService instances in IOService::gMetaClass.reserved->instances, and IOService::gMetaClass.reserved->instances happens to be our OSKext::load -> OSKext::sendPersonalitiesToCatalog stage registered.
Summarize

At this point, the registration, loading, startup and acquisition process of the entire Prelinked Kext is finished. In order to better study the code signing mechanism, the author first analyzed the working mechanism of amfid, then analyzed the interaction logic between AMFI.kext and amfid, and then to the loading of AMFI.kext. It took a lot of time to analyze the entire loading mechanism, and this article is a review. In the next article, we will focus on analyzing the MAC Policy Module registered by AMFI and its working mechanism, which will involve more complex logic.


