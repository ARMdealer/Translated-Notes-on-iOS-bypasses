Foreword

In the previous compilation tutorial series, we explored many principles under the user state. From today, we will analyze the iOS Jailbreak Exploits, and thus in depth in the XNU kernel and learn more about binary security offensive and defense.

Although the Exploit PoC provided by foreign giants has more detailed WRITE-UP, these WRITE-UPs are often based on the POC before, and they do not detail certain specific principles. This leads to a fact that beginners is hard to read. . The author's Jailbreak Priciples series will integrate all related PoCs and Write-Ups and readers are kernels (in fact, the author is also) to assume the assumption, the goal is to create the XNU vulnerability analysis of everyone can read. .
Jailbreak

iOS only provides users with a restricted UNIX environment. Under normal circumstances we can only interact with kernels with legitimate system calls. Conversely, Macos for computers has a high degree of freedom. They are all based on Darwin-XNU, but Apple has put many restrictions on iPhoneos, and the prisoners will release these limits so that we can get the iPhone OOS ROOT permission, which in turn wants to a certain extent.

Apple adopts Sandbox, Signature Checkpoints and other means to protect the system, making it extremely difficult to break through these restrictions.
Jailbreak classification

At present, jailbreak is mainly divided into two categories, and one is Bootrom Exploit based on hardware vulnerabilities, and the other is based on software vulnerability.
Bootrom exploit

Such vulnerabilities are similar to the IC decryption in the single chip microcomputer, discovering the vulnerability of the iPhone itself from the hardware level, making secure boot chain of the entire system becomes unreliable, such vulnerabilities have excellent killing, and can only be solved by updating hardware. The recent Checkm8 and the CHECKRA1N it developed to realize the hardware debugging and jailbreak of iPhone 5S ~ iPhone X series models;
Userland Exploit

Such vulnerabilities are often the code audit for open source Darwin-XNU. Based on these vulnerabilities, we often make us send any executable code to the kernel, and the Sock Port Exploit we will introduce is the XNU SOCKET. A UAF vulnerability of Options.
Send user state data into the kernel

Through the above analysis, we know that an important basis for userland Exploit is to write any data to the kernel's pile area, making it effective in efficient KERNEL data structure, which in turn illegally controlled the kernel from the user state. Unfortunately, we cannot directly operate the kernel's memory data, because the user-state application has no way to get kernel_task, which cannot operate the kernel's stack through functions such as VM_READ and VM_WRITE.

Since we can't do memory directly, we need to consider the way indirect operation memory. In fact, we have a lot of ways to read the data of the kernel, the most common way, Socket, Mach Message and Iosurface, here, there are Socket, Mach Message and Iosurface, here, here we first introduced the best Understanding the Socket method, and then analyzed when the vulnerability of SOCK Port will introduce the combination of these three ways.
Indirect kernel memory reading and writing Based on SOCKET

Since the implementation of the socket is the operating system level, the kernel performs some memory allocation operations when the user state creates SOCK through the Socket function, such as the following user code:

INT SOCK = Socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
Copy code

Create a struct socket structure according to the incoming parameters:
/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
struct socket {
	int	so_zone;		/* zone we were allocated from */
	short	so_type;		/* generic type, see socket.h */
	u_short	so_error;		/* error affecting connection */
	u_int32_t so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* internal state flags SS_*, below */
	void	*so_pcb;		/* protocol control block */
	// ...
}

Here we can indirect and restricted control of the memory in the parameter of the socket, but because the system will only return the SOCK handle (handle) to us, we cannot directly read the kernel memory content.

To read the kernel memory, we can use the Socket Options related functions provided by the kernel. They can modify some of the configuration of the socket. For example, the following code modify the Maximum Transmission Unit under IPv6:

// set mtu
int minmtu = -1;
setsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &minmtu, sizeof(*minmtu));

// read mtu
getsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &minmtu, sizeof(*minmtu));

In the kernel, the system reads the SO_PCB of the Struct Socket and performs the read -write operation of the user mode. As a result, we read and write part of the content of the socket structure in the kernel through Options related functions.
Use any content of the socket read and write kernel

There is an obvious limit on the above method, that is, we can only read and write memory within the scope of kernel control. In this way, we cannot play moths. Imagine if we can try to allocate a fake socket structure to other sections of the kernel, can we read and write any memory through Setsockopt and Getsockopt?

SOCK PORT is a vulnerability that uses the SOCKET function set to realize the kernel depository read and write. It is mainly based on the loopholes of the Socket Disconnect in the core code of iOS 10.0-12.2 to observe the following kernel code:

if (!(so->so_flags & SOF_PCBCLEARING)) {
	struct ip_moptions *imo;
	struct ip6_moptions *im6o;

	inp->inp_vflag = 0;
	if (inp->in6p_options != NULL) {
		m_freem(inp->in6p_options);
		inp->in6p_options = NULL; // <- good
	}
	ip6_freepcbopts(inp->in6p_outputopts); // <- bad
	ROUTE_RELEASE(&inp->in6p_route);
	/* free IPv4 related resources in case of mapped addr */
	if (inp->inp_options != NULL) {
		(void) m_free(inp->inp_options); 
		inp->inp_options = NULL; // <- good
	}
	// ...
}

You can see that IN6P_OUTPUTOPTS is only released when cleaning Options, and the address of the In6P_OutputOPTS pointer is not cleared, which causes an in6p_outputOpts hanging pointer.

Fortunately, after some settings, we can continue to read this hanging pointer through STSOCKOPT and GetSockOpt after Socket Disconnect. As the system resets this memory, we can still access them through a hanging pointer, so the problem is transformed into how to indirectly control the system's Reallocation.

This type of vulnerability that is released through the hanging pointer operation has been referred to as UAF (UseAfter Free), and the integer control system Reallocation has a Heap Spraming and Heap Feng-shui, the entire SOCK Port The vulnerability is more complicated, and we will gradually explain in the next few articles. Here is just a preliminary understanding of these concepts.
Use instator

Through the above example, we have a preliminary understanding of UAF, now we refer to WebOPedia to give a clear definition:
Use After Free specifically refers to the attempt to access memory after it has been freed, which can cause a program to crash or, in the case of a Use-After-Free flaw, can potentially result in the execution of arbitrary code or even enable full remote code execution capabilities.

That is, trying to access the release of memory, which will cause the program to collapse, or the potential code execution, and even obtain complete remote control capabilities.

One of the keys to UAF is to obtain the memory address of the release area. Generally, the vertical pointer is implemented, and the vertical pointer is released by the memory area pointed by the pointer, but the pointer is not cleared. The code written by knowledge developers is common.

In the case of cross -process, only the vertical pointer cannot read and write the memory, and you need to cooperate with some IPC functions that can indirectly read the hanging pointer. For example, the Setsockopt and GetsockOpts mentioned above. In addition, in order to effectively control the Reality of Reality Related technologies that need to be combined with indirect operations.
Heap spraying

Below we refer to the definition of Heap Spraying:
Heap spraying is a technique used to aid the exploitation of vulnerabilities in computer systems. It is called "spraying the heap" because it involves writing a series of bytes at various places in the heap. The heap is a large pool of memory that is allocated for use by programs. The basic idea is similar to spray painting a wall to make it all the same color. Like a wall, the heap is "sprayed" so that its "color" (the bytes it contains) is uniformly distributed over its entire memory "surface."

That is, in the different regions of the user, the user is allocated to the different regions of the kernel, if the kernel's stack is used as a wall, the stack jet is splashing the same color paint (the same byte) in a large amount of allocation memory. On the heap, this will result in a uniform distribution of its color (the same byte) across the entire memory plane, that is, the area that is previously released is almost the same by the Reallocation.

In short,, for example, we alloc has an area of ​​8B, then release it, then you will have multiplexed the previous area when you execute Alloc, and if you just occupy it, you will reach content control. Purpose. Through this technique, we can indirectly control the Reallocation content on the heap.

Obviously if we have the opportunity to assign forged content to Socket Options, we can implement full control of kernel stack memory through Socket Options to Socket Options.
UAF & HEAP Spraying example of a pure user state

Comprehensive theory discussion, we have a preliminary understanding of the reading and writing of the stack memory. Therefore, this article does not disclose the content of the specific vulnerability, but in the user-mocking scenarios, everyone will make you first recognize these two concepts from the project.
Hypothesis

Imagine Xiaoming is a primary page, he wants to develop a task execution system, the system performs tasks according to the priority order of the task, depending on the user's VIP level, the VIP level is recorded in the Task Options:

struct secret_options {
    bool isVIP;
    int vipLevel;
};

struct secret_task {
    int tid;
    bool valid;
    struct secret_options *options;
};

Xiao Ming refers to the design concept of Mach Message, maintains Task's memory structure internally, only exposes TASK handle (TID), users can create tasks through CREATE_SECRET_TASK, the default of the task is no VIP level:

std::map<task_t, struct secret_task *> taskTable;

task_t create_secret_task() {
    struct secret_task *task = (struct secret_task *)calloc(1, sizeof(struct secret_task));
    task->tid = arc4random();
    while (taskTable.find(task->tid = arc4random()) != taskTable.end());
    taskTable[task->tid] = task;
    struct secret_options *options = (struct secret_options *)calloc(1, sizeof(struct secret_options));
    task->options = options;
    options->isVIP = false;
    options->vipLevel = 0;
    return task->tid;
}


In addition to the system, users can do just create tasks, get VIP information, and get task priority:

typedef int task_t;
#define SecretTaskOptIsVIP 0
#define SecretTaskOptVipLevel 1
#define SecretTaskVipLevelMAX 9

int get_task_priority(task_t task_id) {
    struct secret_task *task = get_task(task_id);
    if (!task) {
        return (~0U);
    }
    return task->options->isVIP ? (SecretTaskVipLevelMAX - task->options->vipLevel) : (~0U);
}

bool secret_get_options(task_t task_id, int optkey, void *ret) {
    struct secret_task *task = get_task(task_id);
    if (!task) {
        return false;
    }
    switch (optkey) {
        case SecretTaskOptIsVIP:
            *(reinterpret_cast<bool *>(ret)) = task->options->isVIP;
            break;
        case SecretTaskOptVipLevel:
            *(reinterpret_cast<int *>(ret)) = task->options->vipLevel;
            break;
        default:
            break;
    }
    return true;
}


Ideally, it is not considering the way of reverse engineering, we can only get the task handle and cannot obtain the Task address, so you cannot modify the VIP information any.

Xiao Ming also provided the user with the API of the logout task. He only released the Options of the task, and the task tagged as Invalid, and he forgot to clean up the Options pointer for the system, which introduced a UAF Exploit for the system

bool free_task(task_t task_id) {
    struct secret_task *task = get_task(task_id);
    if (!task) {
        return false;
    }
    free(task->options);
    task->valid = false;
    return true;
}


Assumption attack scene

Under normal circumstances, we can only access the system through the public API:

// create task
task_t task = create_secret_task();

// read options
int vipLevel;
secret_get_options(task, SecretTaskOptVipLevel, &vipLevel);

// get priority
int priority = get_task_priority(leaked_task);

// release task
free_task(task);


Since Task is default non-VIP, we can only get the lowest priority Intmax. Here we pass the Task-> Options UAF to fake Task's VIP level, the method is as follows:

     Create a task and release it through the Free_TASK function, which constructs a Task-> Options hanging pointer;
     Constantly assigning the Struct Secret_Options of Task-> Options, until the area of the Task-> Options slope pointer points to the REALLOCATION into our new application memory, verification mode can forgect specific data, then read authentication via secret_get_options;
     At this point, Struct Secret_Options already points to our newly requested area, which can be modified to Task Options by modifying the area.
 struct faked_secret_options {
    bool isVIP;
    int vipLevel;
};
struct faked_secret_options *sprayPayload = nullptr;
task_t leaked_task = -1;

for (int i = 0; i < 100; i++) {
    // create task
    task_t task = create_secret_task();
    // free to make dangling options
    free_task(task);
    
    // alloc to spraying
    struct faked_secret_options *fakedOptions = (struct faked_secret_options *)calloc(1, sizeof(struct faked_secret_options));
    fakedOptions->isVIP = true;
    // to verify
    fakedOptions->vipLevel = 0x123456;
    
    // check by vipLevel
    int vipLevel;
    secret_get_options(task, SecretTaskOptVipLevel, &vipLevel);
    if (vipLevel == 0x123456) {
        printf("spray succeeded at %d!!!\n", i);
        sprayPayload = fakedOptions;
        leaked_task = task;
        break;
    }
}

// modify
if (sprayPayload) {
    sprayPayload->vipLevel = 9;
}


Since it is a pure user state, the synchronization operation within the same thread is extremely high. Of course, this way can only make everyone have a general understanding of uaf and heap spraying. In fact, such vulnerabilities are cross-processes, requires very complex operations, often need to use Mach Message and iOsurface, and PayLoad constructs are very complex .
Next day notice

In the next chapter, we will start to analyze the source code from the Sock Port, understand the Kalloc series and principles from the Ian Beer's big 佬 and use iOSurface for HEAP Spraming. The Kalloc series functions need to have an in-depth understanding of Mach Message, so we will also analyze the design of Mach Port from the XNU source angle.

