/*
 * linux/ipc/msg.c
 * Copyright (C) 1992 Krishna Balasubramanian 
 *
 * Removed all the remaining kerneld mess
 * Catch the -EFAULT stuff properly
 * Use GFP_KERNEL for messages as in 1.2
 * Fixed up the unchecked user space derefs
 * Copyright (C) 1998 Alan Cox & Andi Kleen
 *
 * /proc/sysvipc/msg support (c) 1999 Dragos Acostachioaie <dragos@iname.com>
 *
 * mostly rewritten, threaded and wake-one semantics added
 * MSGMAX limit removed, sysctl's added
 * (c) 1999 Manfred Spraul <manfreds@colorfullife.com>
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/msg.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include "util.h"

//消息队列是由存放在内核中的消息组成的链表，由IPC id标识。消息队列允许一个或多个进程写消息，一个或多个进程读取消息。 Linux 维护了一系列消息队列的 msgque 向量表。其中的每一个单元都指向一个 msqid_ds 的数据结构，完整描述这个消息队列。当创建消息队列的时候，从系统内存中分配一个新的 msqid_ds 的数据结构并插入到向量表中 每一个 msqid_ds 数据结构都包括一个 ipc_perm 的数据结构和进入这个队列的消息的指针。另外， Linux 保留队列的改动时间，例如上次队列写的时间等。 
//Msqid_ds队列也包括两个等待队列：一个用于向消息队列写，另一个用于读。每一次一个进程试图向写队列写消息，它的有效用户和组的标识符就要和队列的 ipc_perm 数据结构的模式比较。如果进程可以想这个队列写，则消息会从进程的地址空间写到 msg 数据结构，放到消息队列的最后。每一个消息都带有进程间约定的，应用程序指定类型的标记。但是因为Linux限制了可以写的消息的数量和长度，可能会没有空间容纳消息。这时，进程会被放到消息队列的写等待队列，然后调用调度程序选择一个新的进程运行。当一个或多个消息从这个消息队列中读出去的时候会被唤醒。 
//从队列中读是一个相似的过程。进程的访问权限一样被检查。一个读进程可以选择是不管消息的类型从队列中读取第一条消息还是选择特殊类型的消息。如果没有符合条件的消息，读进程会被加到消息队列的读等待进程，然后运行调度程序。当一个新的消息写到队列的时候，这个进程会被唤醒，继续运行。

/* sysctl: */
int msg_ctlmax = MSGMAX;//单个消息的最大size。在某些操作系统例如BSD中，你不必设置这个。BSD自动设置它为MSGSSZ * MSGSEG。其他操作系统中，你也许需要改变这个参数的默认值，你可以设置它与MSGMNB相同
int msg_ctlmnb = MSGMNB;//每个消息队列的最大字节限制
int msg_ctlmni = MSGMNI;//整个系统的最大数量的消息队列

/* one msg_receiver structure for each sleeping receiver */
//一个为每个休眠中的接受者的消息接受结构,表示被阻塞的接收消息进程，及接收消息的属性
struct msg_receiver {
	struct list_head r_list; //链表头
	struct task_struct* r_tsk; //任务结构体

	int r_mode;
	long r_msgtype;
	long r_maxsize;

	struct msg_msg* volatile r_msg;//volatile 易变性变量 防止编译器对代码进行优化，被设计用来修饰被不同线程访问和修改的变量,该变量作用为，当有消息发送时，且消息满足接收消息要求时，直接将消息通过r_msg发送给接收进程，而不需要放入消息队列中。
};

/* one msg_sender for each sleeping sender */
//一个为每个休眠中的发送者的消息发送器
struct msg_sender {//消息发送方
	struct list_head list;
	struct task_struct* tsk;
};

//内核保存消息队列的格式
//一个msg_msg对应一条消息；一条消息由next组成的内存链表组成，第一个结点由msg_msg与数据组成，其它结点由msg_msgseg与数据组成；除最后一个结点外其它的结点大小均为PAGE_SIZE大小，最后一个结点大小取决于消息长度。
struct msg_msgseg {
	struct msg_msgseg* next;
	/* the next part of the message follows immediately 
		紧接着是消息的下一部分*/
};
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list; 
	long  m_type;       //类型      
	int m_ts;           /* message text size消息文本的大小 */
	struct msg_msgseg* next;
	/* the actual message follows immediately
		实际的信息紧跟在后面*/
};

#define DATALEN_MSG	(PAGE_SIZE-sizeof(struct msg_msg))
#define DATALEN_SEG	(PAGE_SIZE-sizeof(struct msg_msgseg))

/* one msq_queue structure for each present queue on the system 		   对于每一个存在的队列系统的一个msq_queue结构*/
struct msg_queue { //消息队列
	struct kern_ipc_perm q_perm;
	time_t q_stime;			/* last msgsnd time 上一个消息发送时间*/
	time_t q_rtime;			/* last msgrcv time 上一个消息接受时间*/
	time_t q_ctime;			/* last change time 上一个改变时间*/
	unsigned long q_cbytes;		/* current number of bytes on queue 当前队列上的字节数*/
	unsigned long q_qnum;		/* number of messages in queue 队列上的消息数*/
	unsigned long q_qbytes;		/* max number of bytes on queue 队列上的最大字节数*/
	pid_t q_lspid;			/* pid of last msgsnd 上个消息发送者的pid*/
	pid_t q_lrpid;			/* last receive pid 上个消息接受者的pid*/

	struct list_head q_messages;//消息进程链表
	struct list_head q_receivers;//被阻塞的接受者进程链表
	struct list_head q_senders;//被阻塞的发送者进程链表
};

#define SEARCH_ANY		1
#define SEARCH_EQUAL		2
#define SEARCH_NOTEQUAL		3
#define SEARCH_LESSEQUAL	4

//原子操作量 常用于计数
static atomic_t msg_bytes = ATOMIC_INIT(0);
static atomic_t msg_hdrs = ATOMIC_INIT(0);

//全局数据结构struct ipc_ids msg_ids 可以访问到每个消息队列头的第一个成员：struct kern_ipc_perm；而每个struct kern_ipc_perm能够与具体的消息队列对应起来是因为在该结构中，有一个key_t类型成员key，而key则唯一确定一个消息队列。
/*
kern_ipc_perm结构如下：
struct kern_ipc_perm{ //内核中记录消息队列的全局数据结构msg_ids能够访问到该结构；
	key_t key; //该键值则唯一对应一个消息队列
	uid_t uid;
	gid_t gid;
	uid_t cuid;
	gid_t cgid;
	mode_t mode;
	unsigned long seq;
}*/
static struct ipc_ids msg_ids;

#define msg_lock(id)	((struct msg_queue*)ipc_lock(&msg_ids,id))
#define msg_unlock(id)	ipc_unlock(&msg_ids,id)
#define msg_rmid(id)	((struct msg_queue*)ipc_rmid(&msg_ids,id))
#define msg_checkid(msq, msgid)	\
	ipc_checkid(&msg_ids,&msq->q_perm,msgid)
#define msg_buildid(id, seq) \
	ipc_buildid(&msg_ids, id, seq)

static void freeque (int id);
static int newque (key_t key, int msgflg);
#ifdef CONFIG_PROC_FS
static int sysvipc_msg_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data);
#endif

//初始化消息
void __init msg_init (void)
{
	//设置序列范围使用IPC标识符的范围（低于ipcmni）然后初始化IDS IDR
	ipc_init_ids(&msg_ids,msg_ctlmni);

#ifdef CONFIG_PROC_FS
	//创建消息文件 
	create_proc_read_entry("sysvipc/msg", 0, 0, sysvipc_msg_read_proc, NULL);
#endif
}

//消息队列由newque创建
static int newque (key_t key, int msgflg)
{
	int id;
	struct msg_queue *msq;//创建msg_queue结构

	//将msg_queue添加到消息队列基数树中，并取回基数树id
	msq  = (struct msg_queue *) kmalloc (sizeof (*msq), GFP_KERNEL);
	if (!msq) 
		return -ENOMEM;
	id = ipc_addid(&msg_ids, &msq->q_perm, msg_ctlmni);//分配一个标识号
	if(id == -1) {
		kfree(msq);
		return -ENOSPC;
	}
	//以下是消息队列头初始化
	msq->q_perm.mode = (msgflg & S_IRWXUGO);
	msq->q_perm.key = key;

	msq->q_stime = msq->q_rtime = 0;
	msq->q_ctime = CURRENT_TIME;
	msq->q_cbytes = msq->q_qnum = 0;
	msq->q_qbytes = msg_ctlmnb;
	msq->q_lspid = msq->q_lrpid = 0;
	
	//初始化msg_queue结构，如初始化消息链表、被阻塞接收进程链表等
	INIT_LIST_HEAD(&msq->q_messages);
	INIT_LIST_HEAD(&msq->q_receivers);
	INIT_LIST_HEAD(&msq->q_senders);
	msg_unlock(id);

	//将标识号转换为一个一体化的标识号,因为实际分配的id实际是数组下标会重复使用
	return msg_buildid(id,msq->q_perm.seq);
}


//free_msg用于释放消息所使用的内核slab内存
static void free_msg(struct msg_msg* msg)
{
	struct msg_msgseg* seg;
	seg = msg->next;
	kfree(msg);
	//释放消息队列每个元素
	while(seg != NULL) {
		struct msg_msgseg* tmp = seg->next;
		kfree(seg);
		seg = tmp;
	}
}

//load_msg用于将用户空间的信息数据复制到内核内存中
//一条消息是由内存链表组成，每个结点内存从通用slab中获取；
//每个结点均由管理信息与数据组成，第一个结点由msg_msg管理，其它由msg_msgseg管理；
//除最后一个结点外，其它结点大小均为PAGE_SIZE大小；不直接取页帧是因为如果有很多小消息（远小于PAGE_SIZE）的话会浪费内存
static struct msg_msg* load_msg(void* src, int len)
{
	struct msg_msg* msg;
	struct msg_msgseg** pseg;
	int err;
	int alen;

	alen = len;
	if(alen > DATALEN_MSG)//一页减去msg结构大小
		alen = DATALEN_MSG;

	//申请一个消息的头大小的内核内存
	msg = (struct msg_msg *) kmalloc (sizeof(*msg) + alen, GFP_KERNEL);
	//消息为空时，返回内存不足
	if(msg==NULL)
		return ERR_PTR(-ENOMEM);

	msg->next = NULL;

	//从用户空间拷贝数据到内核空间
	if (copy_from_user(msg+1, src, alen)) {//从msg的尾部开始拷贝
		err = -EFAULT;
		goto out_err;
	}

	len -= alen;//剩余长度
	src = ((char*)src)+alen;//剩余源头
	pseg = &msg->next;//指向下一个页
	//循环将剩余长度消息队列从用户空间拷贝数据到内核空间
	while(len > 0) {
		struct msg_msgseg* seg;
		alen = len;
		if(alen > DATALEN_SEG)//是否超过page-msgseg
			alen = DATALEN_SEG;
		seg = (struct msg_msgseg *) kmalloc (sizeof(*seg) + alen, GFP_KERNEL);//获取一页
		if(seg==NULL) {
			err=-ENOMEM;//Out of memory 内存不足
			goto out_err;
		}
		*pseg = seg;//链接
		seg->next = NULL;
		if(copy_from_user (seg+1, src, alen)) {//继续拷贝
			err = -EFAULT;//Bad address 地址错误
			goto out_err;
		}
		pseg = &seg->next;
		len -= alen;
		src = ((char*)src)+alen;
	}
	return msg;

//发生错误时，将消息释放，并返回产生错误地址
out_err:
	free_msg(msg);

	return ERR_PTR(err);
}

//store_msg用于将消息数据从内核内存中复制到进程用户空间中
static int store_msg(void* dest, struct msg_msg* msg, int len)
{
	int alen;
	struct msg_msgseg *seg;

	alen = len;
	if(alen > DATALEN_MSG)//一页减去msg结构大小
		alen = DATALEN_MSG;
	if(copy_to_user (dest, msg+1, alen))
		return -1;

	len -= alen;
	dest = ((char*)dest)+alen;
	seg = msg->next;
	//循环将剩余长度消息队列从用户空间拷贝数据到内核空间
	while(len > 0) {
		alen = len;
		if(alen > DATALEN_SEG)//是否超过page-msgseg
			alen = DATALEN_SEG;
		if(copy_to_user (dest, seg+1, alen))
			return -1;
		len -= alen;
		dest = ((char*)dest)+alen;
		seg=seg->next;
	}
	return 0;
}

//挂载到消息队列q_sender链,这样可以通过此链找到休眠正在等待发送的进程
static inline void ss_add(struct msg_queue* msq, struct msg_sender* mss)
{
	mss->tsk=current;//获取当前队列的进程运行的进程
	current->state=TASK_INTERRUPTIBLE;//设置为可中断睡眠状态
	list_add_tail(&mss->list,&msq->q_senders);//添加到队尾
}

static inline void ss_del(struct msg_sender* mss)
{
	if(mss->list.next != NULL)
		list_del(&mss->list);
}

//消息队列的移除过程
//1.唤醒所有被阻塞的消息接收进程，并通知消息队列被移除EIDRM
//2.唤醒所有被阻塞的消息发送进程
//3.将消息队列从消息队列基数树中移除
//4.释放消息队列中消息所使用的内存
//5.将消息队列的消息长度计数从系统消息长度计数中删除
//6.删除msg_queue

//唤醒队列中所有进程，并同时杀死对应进程
static void ss_wakeup(struct list_head* h, int kill)
{
	struct list_head *tmp;

	tmp = h->next;
	while (tmp != h) {
		struct msg_sender* mss;
		
		mss = list_entry(tmp,struct msg_sender,list);
		tmp = tmp->next;
		if(kill)//杀死对应进程
			mss->list.next=NULL;
		wake_up_process(mss->tsk);
	}
}

//唤醒所有被阻塞的消息接收进程，并通知消息队列执行res
static void expunge_all(struct msg_queue* msq, int res)
{
	struct list_head *tmp;

	tmp = msq->q_receivers.next;
	while (tmp != &msq->q_receivers) {
		struct msg_receiver* msr;
		//唤醒所有被阻塞的消息接收进程，并通知消息队列被移除EIDRM 其中res = EIDRM
		msr = list_entry(tmp,struct msg_receiver,r_list);//进入消息接收进程队列，逐个操作
		tmp = tmp->next;
		msr->r_msg = ERR_PTR(res);
		wake_up_process(msr->r_tsk);
	}
}

//消息队列的移除，将所有正在等待的发送还是接收的进程全部唤醒,让其出错返回
static void freeque (int id)
{
	struct msg_queue *msq;
	struct list_head *tmp;//表头指针

	msq = msg_rmid(id);

	expunge_all(msq,-EIDRM);//将所有读写的从链表脱链,让其出错返回
	ss_wakeup(&msq->q_senders,1);//唤醒所有被阻塞的消息发送进程
	msg_unlock(id);
		
	//链表逐节点释放消息空间操作
	tmp = msq->q_messages.next;
	while(tmp != &msq->q_messages) {//将所有报文释放
		struct msg_msg* msg = list_entry(tmp,struct msg_msg,m_list);
		tmp = tmp->next;
		atomic_dec(&msg_hdrs);
		free_msg(msg);
	}
	//将消息队列的消息长度计数从系统消息长度计数中删除
	atomic_sub(msq->q_cbytes, &msg_bytes);
	kfree(msq);
}

//获得消息队列，可以用于2个目的,通过给定的key创建队列或通过给定的key查找已存在队列
asmlinkage long sys_msgget (key_t key, int msgflg)
{
	int id, ret = -EPERM;
	struct msg_queue *msq;//队列
	
	down(&msg_ids.sem);
	if (key == IPC_PRIVATE) //自己私用,无条件创建一个报文队列
		ret = newque(key, msgflg);
	else if ((id = ipc_findkey(&msg_ids, key)) == -1) { /* key not used key没有找到*/
		if (!(msgflg & IPC_CREAT))//没找到,但没设定IPC_CREAT那就返回错误
			ret = -ENOENT; //No such file or directory
		else //设定了就创建报文队列
			ret = newque(key, msgflg);
	} else if (msgflg & IPC_CREAT && msgflg & IPC_EXCL) {//同时设定了IPC_CREAT与IPC_EXCL返回错误
		ret = -EEXIST; /* File exists */
	} else {
		msq = msg_lock(id);
		if(msq==NULL)
			BUG();
		if (ipcperms(&msq->q_perm, msgflg))//检查访问权限是否符合规则
			ret = -EACCES;
		else
			ret = msg_buildid(id, msq->q_perm.seq);//将数组下标转换一体化的标识号
		msg_unlock(id);
	}
	up(&msg_ids.sem);
	return ret;
}

//完成用户空间到内核空间的复制
static inline unsigned long copy_msqid_to_user(void *buf, struct msqid64_ds *in, int version)
{
	switch(version) {//区分64位及较低版本
	case IPC_64:
		return copy_to_user (buf, in, sizeof(*in));
	case IPC_OLD:
	    {
		struct msqid_ds out;

		memset(&out,0,sizeof(out));

		ipc64_perm_to_ipc_perm(&in->msg_perm, &out.msg_perm);

		out.msg_stime		= in->msg_stime;
		out.msg_rtime		= in->msg_rtime;
		out.msg_ctime		= in->msg_ctime;

		if(in->msg_cbytes > USHRT_MAX)
			out.msg_cbytes	= USHRT_MAX;
		else
			out.msg_cbytes	= in->msg_cbytes;
		out.msg_lcbytes		= in->msg_cbytes;

		if(in->msg_qnum > USHRT_MAX)
			out.msg_qnum	= USHRT_MAX;
		else
			out.msg_qnum	= in->msg_qnum;

		if(in->msg_qbytes > USHRT_MAX)
			out.msg_qbytes	= USHRT_MAX;
		else
			out.msg_qbytes	= in->msg_qbytes;
		out.msg_lqbytes		= in->msg_qbytes;

		out.msg_lspid		= in->msg_lspid;
		out.msg_lrpid		= in->msg_lrpid;

		return copy_to_user (buf, &out, sizeof(out));
	    }
	default:
		return -EINVAL;
	}
}

struct msq_setbuf {
	unsigned long	qbytes;
	uid_t		uid;
	gid_t		gid;
	mode_t		mode;
};

//完成内核空间到用户空间的复制
static inline unsigned long copy_msqid_from_user(struct msq_setbuf *out, void *buf, int version)
{
	switch(version) {//区分64位及较低版本
	case IPC_64:
	    {
		struct msqid64_ds tbuf;

		if (copy_from_user (&tbuf, buf, sizeof (tbuf)))
			return -EFAULT;

		out->qbytes		= tbuf.msg_qbytes;
		out->uid		= tbuf.msg_perm.uid;
		out->gid		= tbuf.msg_perm.gid;
		out->mode		= tbuf.msg_perm.mode;

		return 0;
	    }
	case IPC_OLD:
	    {
		struct msqid_ds tbuf_old;

		if (copy_from_user (&tbuf_old, buf, sizeof (tbuf_old)))
			return -EFAULT;

		out->uid		= tbuf_old.msg_perm.uid;
		out->gid		= tbuf_old.msg_perm.gid;
		out->mode		= tbuf_old.msg_perm.mode;

		if(tbuf_old.msg_qbytes == 0)
			out->qbytes	= tbuf_old.msg_lqbytes;
		else
			out->qbytes	= tbuf_old.msg_qbytes;

		return 0;
	    }
	default:
		return -EINVAL;
	}
}

//报文机制的控制与设置sys_msgctl，该系统调用对由msqid标识的消息队列执行cmd操作
/*	
	IPC_STAT：该命令用来获取消息队列信息，返回的信息存贮在buf指向的msqid结构中；
	IPC_SET：该命令用来设置消息队列的属性，要设置的属性存储在buf指向的msqid结构中；可设置属性包括：msg_perm.uid、msg_perm.gid、msg_perm.mode以及msg_qbytes，同时，也影响msg_ctime成员。
	
	IPC_RMID：删除msqid标识的消息队列。
	
	以上命令码并不是专门为报文队列设置,也适用于sysv ipc的其他两种机制,对于具体的机制还可能补充其他专用命令
	#define MSG_STAT 11
	#define MSG_INFO 12
*/ 

//buf是指向msgid_ds结构的指针，它指向消息队列模式和访问权限的结构。
asmlinkage long sys_msgctl (int msqid, int cmd, struct msqid_ds *buf)
{
	int err, version;
	struct msg_queue *msq;
	struct msq_setbuf setbuf;
	struct kern_ipc_perm *ipcp;
	
	if (msqid < 0 || cmd < 0)
		return -EINVAL;//Invalid argument 无效的参数

	version = ipc_parse_version(&cmd);//判断是64位版本还是32位版本

	switch (cmd) {//根据不同类型选择不同操作
	//二者合在一起操作，表示兼容
	case IPC_INFO: 
	case MSG_INFO: 
	{ 
		struct msginfo msginfo;
		int max_id;
		if (!buf)
			return -EFAULT;
		/* We must not return kernel stack data.
		 * due to padding, it's not enough
		 * to set all member fields.
		 我们不能返回内核堆栈数据。 由于填充，设置所有成员字段是不够的。
		 */
		//初始化消息的属性信息
		memset(&msginfo,0,sizeof(msginfo));	
		msginfo.msgmni = msg_ctlmni;
		msginfo.msgmax = msg_ctlmax;
		msginfo.msgmnb = msg_ctlmnb;
		msginfo.msgssz = MSGSSZ;
		msginfo.msgseg = MSGSEG;
		down(&msg_ids.sem);
		//假如cmd是MSG_INFO而不是IPC_INFO时，还要包括一些额外信息
		if (cmd == MSG_INFO) {
			msginfo.msgpool = msg_ids.in_use;
			msginfo.msgmap = atomic_read(&msg_hdrs);
			msginfo.msgtql = atomic_read(&msg_bytes);
		} else {
			msginfo.msgmap = MSGMAP;
			msginfo.msgpool = MSGPOOL;
			msginfo.msgtql = MSGTQL;
		}
		max_id = msg_ids.max_id;
		up(&msg_ids.sem);
		if (copy_to_user (buf, &msginfo, sizeof(struct msginfo)))//从内核拷贝到用户空间
			return -EFAULT;
		return (max_id < 0) ? 0: max_id;
	}
	//状态操作，返回所需要的统计信息—它的当前和最大容量、它的最近的读者和写者的 PID，等等
	case MSG_STAT:
	case IPC_STAT:
	{
		struct msqid64_ds tbuf;
		int success_return;
		if (!buf)
			return -EFAULT;
		//判断id和cmd是否合法
		if(cmd == MSG_STAT && msqid >= msg_ids.size)
			return -EINVAL;

		//内存空间初始化
		memset(&tbuf,0,sizeof(tbuf));

		msq = msg_lock(msqid);
		if (msq == NULL)
			return -EINVAL;

		if(cmd == MSG_STAT) {
			success_return = msg_buildid(msqid, msq->q_perm.seq);
		} else {
			err = -EIDRM;//Identifier removed 标识符被删除
			if (msg_checkid(msq,msqid))//id检查，返回序列编号
				goto out_unlock;
			success_return = 0;
		}
		err = -EACCES;//权限被拒绝
		if (ipcperms (&msq->q_perm, S_IRUGO))//权限判断
			goto out_unlock;

		//计算序列编号
		kernel_to_ipc64_perm(&msq->q_perm, &tbuf.msg_perm);
		tbuf.msg_stime  = msq->q_stime;
		tbuf.msg_rtime  = msq->q_rtime;
		tbuf.msg_ctime  = msq->q_ctime;
		tbuf.msg_cbytes = msq->q_cbytes;
		tbuf.msg_qnum   = msq->q_qnum;
		tbuf.msg_qbytes = msq->q_qbytes;
		tbuf.msg_lspid  = msq->q_lspid;
		tbuf.msg_lrpid  = msq->q_lrpid;
		msg_unlock(msqid);
		if (copy_msqid_to_user(buf, &tbuf, version))//从内核拷贝到用户
			return -EFAULT;//错误地址
		return success_return;
	}
	//set命令操作
	case IPC_SET: 
		if (!buf)
			return -EFAULT;
		if (copy_msqid_from_user (&setbuf, buf, version))
			return -EFAULT;
		break;
	case IPC_RMID:
		break;
	default:
		return  -EINVAL;
	}

	down(&msg_ids.sem);//该函数用于获得信号量sem，他会导致睡眠，因此不能在中断上下文（包括IRQ上下文和softirq上下文）使用该函数。该函数将把sem的值减1，如果信号量sem的值非负，就直接返回，否则调用者将被挂起，直到别的任务释放该信号量才能继续运行。 
	msq = msg_lock(msqid);//挂起该进程
	err=-EINVAL;
	if (msq == NULL)
		goto out_up;

	err = -EIDRM;
	if (msg_checkid(msq,msqid))
		goto out_unlock_up;
	ipcp = &msq->q_perm;
	err = -EPERM;
	if (current->euid != ipcp->cuid && 
	    current->euid != ipcp->uid && !capable(CAP_SYS_ADMIN))
	    /* We _could_ check for CAP_CHOWN above, but we don't 
		上面我们可以检查cap_chown，但我们没有*/
		goto out_unlock_up;

	switch (cmd) {
	case IPC_SET:
	{
		if (setbuf.qbytes > msg_ctlmnb && !capable(CAP_SYS_RESOURCE))
			goto out_unlock_up;
		msq->q_qbytes = setbuf.qbytes;

		//设置ipcp的属性
		ipcp->uid = setbuf.uid;
		ipcp->gid = setbuf.gid;
		ipcp->mode = (ipcp->mode & ~S_IRWXUGO) | 
			(S_IRWXUGO & setbuf.mode);
		msq->q_ctime = CURRENT_TIME;
		/* sleeping receivers might be excluded by
		 * stricter permissions.
		 睡眠接收器可能被更严格的许可排除在外。
		 */
		expunge_all(msq,-EAGAIN);//使所有正在等待此队列接收报文的进程都出错返回
		/* sleeping senders might be able to send
		 * due to a larger queue size.
		 由于较大的队列大小，睡眠发送者可能会发送。
		 */
		ss_wakeup(&msq->q_senders,0);//将所有正在等待此队列发送报文的进程都唤醒,进行新一轮尝试
		msg_unlock(msqid);
		break;
	}
	case IPC_RMID:
		freeque (msqid); //将所有正在等待的发送还是接收的进程全部唤醒,让其出错返回
		break;
	}
	err = 0;
out_up:
	up(&msg_ids.sem);//该函数释放信号量sem，即把sem的值加1，如果sem的值为非正数，表明有任务等待该信号量，因此唤醒这些等待者
	return err;
out_unlock_up:
	msg_unlock(msqid);
	goto out_up;
out_unlock:
	msg_unlock(msqid);
	return err;
}

static int testmsg(struct msg_msg* msg,long type,int mode)
{
	switch(mode)
	{
		case SEARCH_ANY:
			return 1;
		case SEARCH_LESSEQUAL:
			if(msg->m_type <=type)
				return 1;
			break;
		case SEARCH_EQUAL:
			if(msg->m_type == type)
				return 1;
			break;
		case SEARCH_NOTEQUAL:
			if(msg->m_type != type)
				return 1;
			break;
	}
	return 0;
}

//流水管道发送
int inline pipelined_send(struct msg_queue* msq, struct msg_msg* msg)
{
	struct list_head* tmp;

	tmp = msq->q_receivers.next;//聚集正在睡眠等待接收的读进程
	while (tmp != &msq->q_receivers) {//表示有
		struct msg_receiver* msr;
		msr = list_entry(tmp,struct msg_receiver,r_list);
		tmp = tmp->next;
		if(testmsg(msg,msr->r_msgtype,msr->r_mode)) {//类型是否匹配
			list_del(&msr->r_list);
			if(msr->r_maxsize < msg->m_ts) {//读的缓冲区是否够用
				msr->r_msg = ERR_PTR(-E2BIG);
				wake_up_process(msr->r_tsk);//不够用则将进程唤醒,让其出错返回
			} else {
				msr->r_msg = msg;//有的话,直接读取
				msq->q_lrpid = msr->r_tsk->pid;
				msq->q_rtime = CURRENT_TIME;
				wake_up_process(msr->r_tsk);
				return 1;
			}
		}
	}
	return 0;
}

//发送消息过程
// 1.参数检查
// 2.分配消息内存，并将消息复制到内核内存中
// 3.权限检查
// 4.检查消息队列是否已满
// 		A.如果消息队列已满 a.如果IPC_NOWAIT置位，返回EAGAIN通知用户进程再次尝试发送；b.如果IPC_NOWAIT未置位，阻塞发送进程。c.阻塞进程被唤醒时检查消息队列是否被删除，如果被删除返回EIDRM通知用户进程消息队列被删除，否则继续检查消息队列是否已满。
// 		B.如果消息队列未满 a.如果有被阻塞的接收进程，且消息满足接收要求，则将消息直接发送给被阻塞的接收进程。b.否则，将消息排入消息队列尾

//向msgid代表的消息队列发送一个消息，即将发送的消息存储在msgp指向的msgbuf结构中，消息的大小由msgze指定。
//对发送消息来说，有意义的msgflg标志为IPC_NOWAIT，指明在消息队列没有足够空间容纳要发送的消息时，msgsnd是否等待。造成msgsnd()等待的条件有两种：
//1.当前消息的大小与当前消息队列中的字节数之和超过了消息队列的总容量；
//2.当前消息队列的消息数（单位"个"）不小于消息队列的总容量（单位"字节数"），此时，虽然消息队列中的消息数目很多，但基本上都只有一个字节。
//msgsnd()解除阻塞的条件有三个：
// 1.不满足上述两个条件，即消息队列中有容纳该消息的空间；
// 2.msqid代表的消息队列被删除；
// 3.调用msgsnd（）的进程被信号中断；
// 调用返回：成功返回0，否则返回-1。
asmlinkage long sys_msgsnd (int msqid, struct msgbuf *msgp, size_t msgsz, int msgflg)
{
	struct msg_queue *msq;//队列头
	struct msg_msg *msg;//内核保存信息的格式
	long mtype;
	int err;
	//消息不可以超过msg_ctlmax
	if (msgsz > msg_ctlmax || (long) msgsz < 0 || msqid < 0)
		return -EINVAL;
	if (get_user(mtype, &msgp->mtype))//从用户空间拷贝到内核
		return -EFAULT; 
	if (mtype < 1)//判断类型
		return -EINVAL;

	msg = load_msg(msgp->mtext, msgsz);//分配缓冲区保存消息(从用户拷贝到内核)
	if(IS_ERR(msg))//判断消息分配缓存区时是否出错
		return PTR_ERR(msg);

	msg->m_type = mtype;//消息类型
	msg->m_ts = msgsz;//消息大小

	msq = msg_lock(msqid);//根据给定的标号msg_msg找到相应的消息队列,将其数据结构上锁
	err=-EINVAL;
	if(msq==NULL)
		goto out_free;
retry:
	err= -EIDRM;
	if (msg_checkid(msq,msqid))//验证下id号
		goto out_unlock_free;

	err=-EACCES;
	if (ipcperms(&msq->q_perm, S_IWUGO)) //检查是否有权限向这个队列发送消息
		goto out_unlock_free;

	if(msgsz + msq->q_cbytes > msq->q_qbytes ||
		1 + msq->q_qnum > msq->q_qbytes) {//当前消息大小+当前队列统计的字节数超过了消息队列的总容量.或者消息的个数超过了限制,那就不可以发送了
		struct msg_sender s;

		if(msgflg&IPC_NOWAIT) {//是否等待,不等待直接退出
			err=-EAGAIN;
			goto out_unlock_free;
		}
		ss_add(msq, &s);//挂载到消息队列q_sender链,这样可以通过此链找到休眠正在等待发送的进程
		msg_unlock(msqid);
		schedule();//调度
		current->state= TASK_RUNNING;

		msq = msg_lock(msqid);
		err = -EIDRM;
		if(msq==NULL)
			goto out_free;
		ss_del(&s);//删除
		
		if (signal_pending(current)) {
			err=-EINTR;
			goto out_unlock_free;
		}
		goto retry;//重新运行一遍
	}

	msq->q_lspid = current->pid;
	msq->q_stime = CURRENT_TIME;

	if(!pipelined_send(msq,msg)) {
		/* noone is waiting for this message, enqueue it 如果有相关进程正在读这个消息就不用放入队列了*/
		list_add_tail(&msg->m_list,&msq->q_messages);//链入队列
		msq->q_cbytes += msgsz;//总数+1
		msq->q_qnum++;//数目+1
		atomic_add(msgsz,&msg_bytes);
		atomic_inc(&msg_hdrs);
	}
	
	err = 0;
	msg = NULL;

out_unlock_free:
	msg_unlock(msqid);
out_free:
	if(msg!=NULL)
		free_msg(msg);
	return err;
}


//寻找正确类型的消息
int inline convert_mode(long* msgtyp, int msgflg)
{
	/* 
	 *  find message of correct type.
	 *  msgtyp = 0 => get first.
	 *  msgtyp > 0 => get first message of matching type.获取匹配类型的第一个消息。
	 *  msgtyp < 0 => get message with least type must be < abs(msgtype). 
		得到最少的类型信息必须 ＜ ABS（msgtype）	 
	 */
	if(*msgtyp==0)
		return SEARCH_ANY;
	if(*msgtyp<0) {
		*msgtyp=-(*msgtyp);
		return SEARCH_LESSEQUAL;
	}
	if(msgflg & MSG_EXCEPT)
		return SEARCH_NOTEQUAL;
	return SEARCH_EQUAL;
}

//接收消息
//该系统调用从msgid代表的消息队列中读取一个消息，并把消息存储在msgp指向的msgbuf结构中
// 1.参数检查及权限检查
// 2.如果有满足接收要求的消息（消息队列中有消息，且类型、长度都满足要求）
// a.将消息从消息队列中取出，并复制到用户地址空间 b.释放消息所占用的内核内存 c.尝试唤醒被阻塞的第一个消息发送进程
// 3.如果没有满足接收要求的消息
// A.如果IPC_NOWAIT置位，返回ENOMSG通知用户进程没有消息
// B.如果IPC_NOWAIT未置位，阻塞消息接收进程
// C.阻塞进程被唤醒
    // a.如果因有满足接收要求的消息发送，同2的a和b的处理；
    // b.如果因为信号发送，则先做信号处理；再自动重新调用msgsnd
    // c.否则接收进程继续被阻塞

//msgrcv手册中详细给出了消息类型取不同值时(>0;<0;=0)调用将返回消息队列中的哪个消息。
//msgrcv()解除阻塞的条件有三个：1.消息队列中有了满足条件的消息；2.msqid代表的消息队列被删除；3.调用msgrcv（）的进程被信号中断；
//调用返回：成功返回读出消息的实际字节数，否则返回-1。
asmlinkage long sys_msgrcv (int msqid, struct msgbuf *msgp, size_t msgsz,
			    long msgtyp, int msgflg)
{
	struct msg_queue *msq;//队列头
	struct msg_receiver msr_d;//接收的需要睡眠的进程
	struct list_head* tmp;
	struct msg_msg* msg, *found_msg;
	int err;
	int mode;

	if (msqid < 0 || (long) msgsz < 0)
		return -EINVAL;
	mode = convert_mode(&msgtyp,msgflg);

	msq = msg_lock(msqid);//根据报文队列标识号,找到具体队列
	if(msq==NULL)
		return -EINVAL;
retry:
	err = -EIDRM;
	if (msg_checkid(msq,msqid))
		goto out_unlock;

	err=-EACCES;
	if (ipcperms (&msq->q_perm, S_IRUGO))//检测是否具有权限
		goto out_unlock;

	tmp = msq->q_messages.next;
	found_msg=NULL;
	while (tmp != &msq->q_messages) {//遍历
		msg = list_entry(tmp,struct msg_msg,m_list);//根据队列当前项找到其指针
		if(testmsg(msg,msgtyp,mode)) {
			found_msg = msg;//查找到了消息
			if(mode == SEARCH_LESSEQUAL && msg->m_type != 1) {
				found_msg=msg;
				msgtyp=msg->m_type-1;//将type减到比这个报文的类型值更小,看能否找到更小的
			} else {
				found_msg=msg;
				break;
			}
		}
		tmp = tmp->next;
	}
	if(found_msg) {
		msg=found_msg;
		if ((msgsz < msg->m_ts) && !(msgflg & MSG_NOERROR)) {//如果接收大小小于报文大小,出错
			err=-E2BIG;//Argument list too long 参数列表太长
			goto out_unlock;
		}
		list_del(&msg->m_list);//否则将该报文从队列脱链
		msq->q_qnum--;
		msq->q_rtime = CURRENT_TIME;
		msq->q_lrpid = current->pid;
		msq->q_cbytes -= msg->m_ts;
		atomic_sub(msg->m_ts,&msg_bytes);
		atomic_dec(&msg_hdrs);
		ss_wakeup(&msq->q_senders,0);//将发送的睡眠等待进程全部唤醒,因为拿出了一个报文
		msg_unlock(msqid);
out_success:
		msgsz = (msgsz > msg->m_ts) ? msg->m_ts : msgsz;
		if (put_user (msg->m_type, &msgp->mtype) ||//实际接收的报文类型,通过put_user送回用户空间
		    store_msg(msgp->mtext, msg, msgsz)) {//将实际接收到的复制到用户空间
			    msgsz = -EFAULT;
		}
		free_msg(msg);//释放内核缓存
		return msgsz;
	} else //报文队列还没有报文可供接收
	{
		struct msg_queue *t;
		/* no message waiting. Prepare for pipelined
		 * receive.
		 无消息等待。准备流水线接收。
		 */
		if (msgflg & IPC_NOWAIT) {//不等待则直接返回错误
			err=-ENOMSG;
			goto out_unlock;
		}
		list_add_tail(&msr_d.r_list,&msq->q_receivers);//链入等待接收队列进程
		//保存msr_d的信息
		msr_d.r_tsk = current;
		msr_d.r_msgtype = msgtyp;
		msr_d.r_mode = mode;
		
		if(msgflg & MSG_NOERROR)
			msr_d.r_maxsize = INT_MAX;
		 else
		 	msr_d.r_maxsize = msgsz;
		msr_d.r_msg = ERR_PTR(-EAGAIN);
		current->state = TASK_INTERRUPTIBLE;
		msg_unlock(msqid);//解锁并调度
		//当前进程一旦睡眠,以下需要等待进程通过pipelined_send()向其发送报文,并且选择这个进程作为接收进程才会被唤醒
		schedule();
		current->state = TASK_RUNNING;

		msg = (struct msg_msg*) msr_d.r_msg;
		if(!IS_ERR(msg)) //表示已经成功接收
			goto out_success;
		//以下是因为缓冲区太小,唤醒了睡眠进程依旧无法接收,而是被信号唤醒的错误处理
		t = msg_lock(msqid);
		if(t==NULL)
			msqid=-1;
		msg = (struct msg_msg*)msr_d.r_msg;
		if(!IS_ERR(msg)) {//在锁住队列之前,还有可能接收到其他进程pipelined_send发来的报文，所以还需要检查下是否成功接收到报文
			/* our message arived while we waited for
			 * the spinlock. Process it.
			 在我们在等待自旋锁时信息到达。执行它。
			 */
			if(msqid!=-1)
				msg_unlock(msqid);
			goto out_success;
		}
		err = PTR_ERR(msg);
		if(err == -EAGAIN) {// EAGAIN = Try again //要将本进程的msg_receiver结构脱链,并且看是否有信号处理
			if(msqid==-1)
				BUG();//一些内核调用可以用来方便标记bug，提供断言并输出信息。
			list_del(&msr_d.r_list);
			if (signal_pending(current))//如果没有信号处理,则跳转到retry重新开始
				err=-EINTR;//Interrupted system call 中断的系统调用
			 else
				goto retry;
		}
	}
out_unlock:
	if(msqid!=-1)
		msg_unlock(msqid);
	return err;
}

//系统ipc的消息读取进程
#ifdef CONFIG_PROC_FS
static int sysvipc_msg_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int i, len = 0;

	//互斥锁
	down(&msg_ids.sem);
	len += sprintf(buffer, "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n");

	//遍历消息队列，读取消息的内部属性
	for(i = 0; i <= msg_ids.max_id; i++) {
		struct msg_queue * msq;
		msq = msg_lock(i);
		if(msq != NULL) {
			len += sprintf(buffer + len, "%10d %10d  %4o  %10lu %10lu %5u %5u %5u %5u %5u %5u %10lu %10lu %10lu\n",
				msq->q_perm.key,
				msg_buildid(i,msq->q_perm.seq),
				msq->q_perm.mode,
				msq->q_cbytes,
				msq->q_qnum,
				msq->q_lspid,
				msq->q_lrpid,
				msq->q_perm.uid,
				msq->q_perm.gid,
				msq->q_perm.cuid,
				msq->q_perm.cgid,
				msq->q_stime,
				msq->q_rtime,
				msq->q_ctime);
			msg_unlock(i);

			pos += len;
			if(pos < offset) {
				len = 0;
				begin = pos;
			}
			if(pos > offset + length)
				goto done;
		}

	}
	*eof = 1;
done:
//互斥锁
	up(&msg_ids.sem);
	//计算新的起始地址和长度
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if(len > length)
		len = length;
	if(len < 0)
		len = 0;
	return len;
}
#endif

/* 消息队列与管道以及有名管道相比，具有更大的灵活性，首先，它提供有格式字节流，有利于减少开发人员的工作量；其次，消息具有类型，在实际应用中，可作为优先级使用。这两点是管道以及有名管道所不能比的。同样，消息队列可以在几个进程间复用，而不管这几个进程是否具有亲缘关系，这一点与有名管道很相似；但消息队列是随内核持续的，与有名管道（随进程持续）相比，生命力更强，应用空间更大。
*/

