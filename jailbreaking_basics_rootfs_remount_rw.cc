Foreword

In previous articles, we introduced the principle of iOS 12 to get TFP0 and the implementation of KEXEC based on TFP0. From this article, we have begun to analyze the principles of Jailbreak's environmental layout after TFP0 and KEXEC, mainly including the start and writing and persistence of ROOTFS, the implementation of remote services such as SSH, the execution of illegal signature code, and the Hook system. We mainly introduce the principles of reading and writing and persistence of rootfs.
What is rootfs

Each file system in the UNIX-Like operating system needs to be loaded by mount point. Among them, rootfs refers to the file system that is mounted to the root directory / in the startup [1].

In iOS, Rootfs is a file system mounted from/dev/disk0S1S1 or System-Snapshot, which contains the operating system (/System/library/caches/com.apple.kernelcacher), basic App (/applications/), etc. Information, and the default is read only in the modern iOS operating system.

The user information is mounted to the directory of /private /var and other directory through other file systems. We can view the mount information on the DF -H on the jailbreak iOS device:
iPad-2:~ root# df -h
Filesystem       Size   Used  Avail Capacity iused      ifree %iused  Mounted on
/dev/disk0s1s1   60Gi  4.6Gi  2.0Gi    71%  177766  624821794    0%   /
devfs            56Ki   56Ki    0Bi   100%     194          0  100%   /dev
/dev/disk0s1s2   60Gi   53Gi  2.0Gi    97%  194854  624804706    0%   /private/var
/dev/disk0s1s3   60Gi  6.8Mi  2.0Gi     1%     185  624999375    0%   /private/var/MobileSoftwareUpdate
/dev/disk4       30Mi   14Mi   16Mi    47%     337 4294966942    0%   /Developer

Why is rootfs read-only?
VNode & Mount object

Before you describe why Rootfs is read-only, we must first introduce the file system of the IOS. In a UNIX-Like operating system, each file (including the directory) allocates unique vNode in the system, including various information of the file in VNODE [2]:

struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;         /* vnodes for mount point */
    // ...
    mount_t v_mount;                        /* ptr to vfs we are in */
    // ...
};

V_mount member of VNODE records the file system and its properties mounted by the current file, where the flag in the mnt_flag can set the rootfs identity and read-only properties:

struct mount {
    TAILQ_ENTRY(mount)      mnt_list;                   /* mount list */
    int32_t                 mnt_count;                  /* reference on the mount */
    // ...
    uint32_t                mnt_flag;                   /* flags */
    // ,,,
};

Mount Flags

For rootfs, its node-> v_mount-> mnt_flag's MNT_ROOTFS and MNT_RDONLY are set. These two markers represent the following relief measures:

    When a SANDBOX APP tries to access a file system, if the system finds that its vNode contains the mnt_rootfs attribute, it will fail directly;
    A file system containing MNT_RDONLY is read-only.

The solution is also very simple, we only need to get the rootfs vnode, read MNT_FLAG through KREAD, write the mnt_rootfs and mnt_rdonly position 0, and then redistribute the file system to refresh the state.
APFS Snapshots

After iOS 11.3, Apple took more extreme measures, they no longer mounted / dev / disk0s1s1 to /, but as the system firmware upgrade to the device APFS SNAPSHOT, prioritize Snapshot at each time startup arrive/. This means that even if we modify rootfs through the above Flags Patch, the system will then load the file system from the APFS Snapshot, which will cause the content we write to rootfs and is not mounted, everything is returned to the past [3] .
Realize rootfs r / w and persistence

Through the discussion above, we know that there are two key points to implement rootfs r / w:

    Find rootfs vnode;
    Modify the vNode data of rootfs to implement R / W;
    Bypass the APFS Snapshot loading mechanism makes it mounts real file system / dev / disk0s1s1s1.

Precautions

    The discussion and experiment of the author is based on iOS 13.1.1 (17A854), and the reference code comes from UNC0VER and ChIMERA13;
    Remount involves multiple system calls, need to be executed after the proposal (SetUID (0)), and the code for the proposal can be referred to the Getroot in Chimera13, which is not discussed in this article.

0x01 found rootfs vnode

There are two ideas to find the vNode of rootfs:

    Locate Rootvnode global variables in the kernel through the XREF scheme;
    Find a system process, find its vNode via the P_TextVP of the Proc object, and then back to the rootfs vNode through the vNode list.

Here we use the second solution, we first look at the VNODE information data on the Proc object:
struct  proc {
    LIST_ENTRY(proc) p_list;                /* List of all processes. */
    
    void *          task;                   /* corresponding task (static)*/
    struct  proc *  p_pptr;                 /* Pointer to parent process.(LL) */
    pid_t           p_ppid;   
    // ...
    struct  vnode *p_textvp;        /* Vnode of executable. */
    // ...
};

Therefore, we can get the VNODE corresponding to the executable files through Proc-> P_TextVP, and then let's look at the key data of the backtracking in vNode:

struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;    
    // ...  
    vnode_t v_parent;                       /* pointer to parent vnode */
    // ...
    const char *v_name;                     /* name component of the vnode */
    // ...
};

Here we can determine the name of the VNODE node (file / directory name) through v_parent, and instead of finding a named system's vNode indicating that we have returned to the root directory, that is, the current vNode is rootfs vNode. Rootvnode).

For example, here we choose the system process Launchd as the starting point, first we look at the directory where Launchd is located:
iPad-2:~ root# which launchd
/sbin/launchd

Then theoretically retro 2 times, so we only need to do Proc Iteration through TFP0, find the Launch's Proc object, and then go back to RootvNode:
uint64_t findRootVnode(uint64_t launchd_proc) {
    uint64_t textvp = rk64(launchd_proc + 0x238); // proc_text_vp
    uint64_t nameptr = rk64(textvp + 0xb8); // vnode.name
    uint8_t name[20] = {0};
    kread(nameptr, &name, 20);
    printf("[+] found vnode: %s\n", name);
    
    uint64_t sbin = rk64(textvp + 0xc0); // vnode.parent
    nameptr = rk64(sbin + 0xb8); // vnode.name
    kread(nameptr, &name, 20);
    printf("[+] found vnode (should be sbin): %s\n", name);
    
    uint64_t rootvnode = rk64(sbin + 0xc0); // vnode.parent
    nameptr = rk64(rootvnode + 0xb8); // vnode.name
    kread(nameptr, &name, 20);
    printf("[+] found vnode (should be System): %s\n", name);
    return rootvnode;
}

The corresponding output is as follows. It can be seen that the theoretical assumptions are conforming to the theory. We successfully found the rootvnode:

[+] found vnode: launchd
[+] found vnode (should be sbin): sbin
[+] found vnode (should be System): System
0x02 Remove rootfs APFS Snapshot

In the previous discussion, if the iOS system is started if there is a rootfs, it is found, it is preferentially loaded instead of / dev / disk0s1s1, so only the Snapshot that removes rootfs can ensure that the real rootfs is mounted when starting.

Apple limits the use of FS_SNAPHOST_DELETE, but does not limit FS_SNAPSHOT_RENAME, so we can rename by rename the rootfs' boot snapshot. Another benefit of rename instead of the delete is we can recover rootfs through Rename Back.

It should be noted that we need to modify the real system disk / dev / disk0s1s1 while performing the above operation, but rootfs has been mounted by the system, so we need to mount it to another location, such as use in Chimera13. Var / rootfsmnt. The whole process is approximately as follows:
There are several attention points here:
Question 1: iOS does not allow Device to be mounted multiple times

We need to find the specinfo of rootvnode, clean up the mount information recorded in its Si_Flags. Otherwise, when we try to mount / dev / disk0s1s1, the Kernel PANIC is triggered. (There is a question here that the system is not really mount / dev / disk0s1s1, but is mounted on its SNAPSHOT, whether it will set the / dev / disk0s1s1 Si_Mounted, so you need to clean it here.
	struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;         /* vnodes for mount point */
    // ...
    union {
    	// ...
        struct specinfo *vu_specinfo;   /* device (VCHR, VBLK) */
	// ...
    };
};

/*
 * Flags for specinfo
 */
#define SI_MOUNTEDON    0x0001  /* block special device is mounted on */
#define SI_ALIASED      0x0002  /* multiple active vnodes refer to this device */

struct specinfo {
    struct  vnode **si_hashchain;
    struct  vnode *si_specnext;
    long    si_flags;
    // ...
};

Let's find rootvnode first, then find the device information stored in MOUNT, finalize the FLAG that is cleaned / dev / disk0s1s1, and paveled the mount information to follow:
int mountRealRootFS(uint64_t rootvnode) {
    uint64_t vmount = rk64(rootvnode + 0xd8); // vnode.mount
    uint64_t dev = rk64(vmount + 0x980); // vmount.devvp
    uint64_t nameptr = rk64(dev + 0xb8); // vnode.name
    char name[20] = {0};
    kread(nameptr, &name, 20);
    printf("[+] found vnode: %s\n", name);
    
    uint64_t specinfo = rk64(dev + 0x78); // vnode.specinfo
    uint32_t flags = rk32(specinfo + 0x10); // specinfo.flags
    printf("[+] found dev flags %d\n", flags);
    
    // set specinfo.flags = 0
    wk32(specinfo + 0x10, 0);
    // ...
};
Question 2: It's not enough to mention power

After iOS 11.3 and later, the process except Kernel cannot Mount APFS file system, so we also need to hijack Kernel's UCRED. There is a strange point here in iOS 13 that you do n’t need to do SHENANIGANS PATCH:
// steal kern's ucred
uint64_t kern_ucred = rk64(kern_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
uint64_t my_ucred = rk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
wk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), kern_ucred);

// actions
// ...

// restore
wk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), my_ucred);

Question 3: Nest Snapshot Flags needs to be in front of Rename

Before rename snapshot, you need to Patch / dev / disk0s1s1's boot-snapshot vNode-> v_data-> flags:

bool unsetSnapShotFlag(uint64_t newmnt) {
    uint64_t dev = rk64(newmnt + 0x980); // vnode.devvp
    uint64_t nameptr = rk64(dev + 0xb8); // vnode.name
    char name[20] = {0};
    kread(nameptr, &name, 20);
    printf("[+] found vnode: %s\n", name);
    
    uint64_t specinfo = rk64(dev + 0x78); // vnode.specinfo
    uint32_t flags = rk32(specinfo + 0x10); // specinfo.flags
    printf("[+] found dev flags %d\n", flags);
    
    uint64_t vnodelist = rk64(newmnt + 0x40); // vmount.vnodelist
    
    uint64_t pc_strlen = Find_strlen();
    while (vnodelist != 0) {
        printf("[+] recurse vnode list 0x%llx\n", vnodelist);
        
        uint64_t nameptr = rk64(vnodelist + 0xb8); // vnode.name
        char nameBuf[255] = {0};
        int nameLen = (int)Kernel_Execute(pc_strlen, nameptr, 0, 0, 0, 0, 0, 0);
        kread(nameptr, &nameBuf, nameLen);
        printf("[+] found vnode %s\n", name);
        NSString *name = [NSString stringWithFormat:@"%s", nameBuf];
        if ([name hasPrefix:@"com.apple.os.update-"]) {
            uint64_t vdata = rk64(vnodelist + 0xe0); // vnode.data
            uint32_t flag = rk32(vdata + 0x31); // vnode.data.flag
            printf("[+] found apfs flag: %d\n", flag);
            
            if ((flag & 0x40) != 0) {
                flag = flag & ~0x40;
                printf("[+] need unset snapshot flag to %d\n", flag);
                wk32(vdata + 0x31, flag); // vnode.data.flag
                return true;
            }
        }
        usleep(1000);
        vnodelist = rk64(vnodelist + 0x20); // vnode.next
    }
    return false;
}

This should be related to some of the APFS, but the author has not found the relevant information, I hope that the giant points. After you will follow more about more APFS-related content, add it.
Question 4: Boot-snapshot name is random

Boot-snapshot name format is com.apple.update- <boot-manifest-hash>, where boot-manifest-hash is available through the IOKIT's API query, this hash does not change when restarting, guessing is in firmware Generate and create snapshot and records when updating.

So when you get the name of the boot-snapshot, you need to query the Hash, then spliced the prefix:
NSString* find_boot_snapshot() {
    io_registry_entry_t chosen = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
    CFDataRef data = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    if (!data) {
        return nil;
    }
    IOObjectRelease(chosen);
    
    CFIndex length = CFDataGetLength(data) * 2 + 1;
    char *manifestHash = calloc(length, sizeof(char));
    const uint8_t *hash = CFDataGetBytePtr(data);
    int i = 0;
    for (i = 0; i < CFDataGetLength(data); i++) {
        sprintf(manifestHash + i * 2, "%02X", hash[i]);
    }
    manifestHash[i * 2] = 0;
    
    NSString *systemSnapshot = [NSString stringWithFormat:@"com.apple.os.update-%s", manifestHash];
    printf("[+] find System Snapshot: <%s>\n", systemSnapshot.UTF8String);
    return systemSnapshot;
}


0x03 remount rootfs as r/w
After 0x02, the system will mount /dev /disk0s1s1 to /, so we only need to modify the Mount Flags and then Remount refresh the state to get a persistent R /W Rootfs:
uint64_t vmount = rk64(rootvnode + 0xd8); // vnode.mount
uint32_t vflag = rk32(vmount + 0x70); // vmount.vflag
vflag = vflag & ~(MNT_NOSUID | MNT_RDONLY);
wk32(vmount + 0x70, vflag & ~MNT_ROOTFS);

char * dev_path = strdup("/dev/disk0s1s1");
int ret = mount("apfs", "/", MNT_UPDATE, &dev_path);
free(dev_path);
wk32(vmount + 0x70, vflag);
printf("[+] not rename required remount with status %d\n", ret);
return ret == 0;


0x04 complete process flow

We can query rootfs / existing snapshot through fs_snapshot_list, and before passing this function, you can't query boot-snapshot, don't know if Apple does special treatment here? . After the above treatment, we rename the boot-snapshot and can be queried by the fs_snapshot_list function. In this way, we can determine if the file system has done Snapshot Rename, if we have already processed us Just do the Patch Flags & Remount operation in 0x03.
Summarize

Here we have completed the analysis of IOS 13.1.1 Rootfs Remount, the entire process is not very complicated, but the back of each detail corresponds to a lot of knowledge and exploration. The analysis of the shoulders standing on the giant is easy, but if the information has become gradually closed, it will be difficult to rise when you explore your BYPASS scheme. I hope that everyone who learns and study Jailbreak can have this sense of crisis, holding the attitude of breaking the casserole, going to the XNU into the truth.