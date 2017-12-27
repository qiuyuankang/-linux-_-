/*
 * linux/ipc/sem.c
 * Copyright (C) 1992 Krishna Balasubramanian
 * Copyright (C) 1995 Eric Schenk, Bruno Haible
 *
 * IMPLEMENTATION NOTES ON CODE REWRITE (Eric Schenk, January 1995):
 * This code underwent a massive rewrite in order to solve some problems
 * with the original code. In particular the original code failed to
 * wake up processes that were waiting for semval to go to 0 if the
 * value went to 0 and was then incremented rapidly enough. In solving
 * this problem I have also modified the implementation so that it
 * processes pending operations in a FIFO manner, thus give a guarantee
 * that processes waiting for a lock on the semaphore won't starve
 * unless another locking process fails to unlock.
 * In addition the following two changes in behavior have been introduced:
 * - The original implementation of semop returned the value
 *   last semaphore element examined on success. This does not
 *   match the manual page specifications, and effectively
 *   allows the user to read the semaphore even if they do not
 *   have read permissions. The implementation now returns 0
 *   on success as stated in the manual page.
 * - There is some confusion over whether the set of undo adjustments
 *   to be performed at exit should be done in an atomic manner.
 *   That is, if we are attempting to decrement the semval should we queue
 *   up and wait until we can do so legally?
 *   The original implementation attempted to do this.
 *   The current implementation does not do so. This is because I don't
 *   think it is the right thing (TM) to do, and because I couldn't
 *   see a clean way to get the old behavior with the new design.
 *   The POSIX standard and SVID should be consulted to determine
 *   what behavior is mandated.
 *
 * Further notes on refinement (Christoph Rohland, December 1998):
 * - The POSIX standard says, that the undo adjustments simply should
 *   redo. So the current implementation is o.K.
 * - The previous code had two flaws:
 *   1) It actively gave the semaphore to the next waiting process
 *      sleeping on the semaphore. Since this process did not have the
 *      cpu this led to many unnecessary context switches and bad
 *      performance. Now we only check which process should be able to
 *      get the semaphore and if this process wants to reduce some
 *      semaphore value we simply wake it up without doing the
 *      operation. So it has to try to get it later. Thus e.g. the
 *      running process may reacquire the semaphore during the current
 *      time slice. If it only waits for zero or increases the semaphore,
 *      we do the operation in advance and wake it up.
 *   2) It did not wake up all zero waiting processes. We try to do
 *      better but only get the semops right which only wait for zero or
 *      increase. If there are decrement operations in the operations
 *      array we do the same as before.
 *
 * /proc/sysvipc/sem support (c) 1999 Dragos Acostachioaie <dragos@iname.com>
 *
 * SMP-threaded, sysctl's added
 * (c) 1999 Manfred Spraul <manfreds@colorfullife.com>
 * Enforced range limit on SEM_UNDO
 * (c) 2001 Red Hat Inc <alan@redhat.com>
 */
/*
在重写代码实现注意事项（EricSchenk，1995年1月）：
为了解决一些问题，这段代码进行了大量的重写。与原始代码。
尤其是原始代码未能唤醒过程，等待semval去变为0，如果值达到0，它将迅速增加。
在解决这个问题我也修改了实现使它以FIFO方式处理未决操作，
从而提供保证等待信号量锁定的进程不会饿死。
除非另一个锁定进程无法解锁。

此外，还介绍了以下两种行为变化： 
-SEMOP原执行的返回值成功检查最后信号量元素。
这不匹配手册页规格，并有效允许用户读取信号量，即使他们没有读取权限。
现在实现返回0。关于手册页所述的成功。对撤销调整集是否有一些混淆。
在出口处执行的工作应以原子方式进行。
即，如果我们试图减少semval要排队等等，直到我们可以合法地这么做？
最初的实现试图做到这一点。
但是目前的执行情况并非如此，这是因为我没有认为这是正确的事（TM）做，
因为我不能通过新的设计看到一个整洁的方式来获得旧的行为。

POSIX标准和SVID应确定授权的行为是什么？
在进一步细化笔记（Christoph Rohland，1998年12月）：

-POSIX标准说，那个撤消调整简单应重做。所以目前的实施是好的。以前的代码有两个缺陷：
1）主动给下一个信号量休眠的等待过程发出信号量。
因为这个过程没有CPU，这导致许多不必要的上下文切换和坏性能。
现在我们只检查哪个进程应该能够获取信号量，如果这个过程想减少一些信号量值，
我们只是在无操作的情况下叫醒它。因此，它必须设法得到它以后。
因如运行过程中可能获取信号量时的电流时间片。如果它只等待零或增加信号量，
我们提前做操作并唤醒它。
2）它没有唤醒所有零等待进程。
我们尽力去做但只有SEMOPS权利，只能等待零或增加。
如果操作中有递减操作数组，我们做的和以前一样。
*/

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "util.h"

// 一．什么是信号量
// 信号量的使用主要是用来保护共享资源，使得资源在一个时刻只有一个进程（线程）
// 所拥有。
// 信号量的值为正的时候，说明它空闲。所测试的线程可以锁定而使用它。若为0，说明
// 它被占用，测试的线程要进入睡眠队列中，等待被唤醒。
// 二．信号量的分类
// 在学习信号量之前，我们必须先知道——Linux提供两种信号量：
// （1） 内核信号量，由内核控制路径使用
// （2） 用户态进程使用的信号量，这种信号量又分为POSIX信号量和SYSTEM
// V信号量。
// POSIX信号量又分为有名信号量和无名信号量。
// 有名信号量，其值保存在文件中, 所以它可以用于线程也可以用于进程间的同步。无名
// 信号量，其值保存在内存中。
/*
 * SLAB caches for signal bits.  SLAB是信号位缓存 
 */

#define sem_lock(id)	((struct sem_array*)ipc_lock(&sem_ids,id))
#define sem_unlock(id)	ipc_unlock(&sem_ids,id)
#define sem_rmid(id)	((struct sem_array*)ipc_rmid(&sem_ids,id))
#define sem_checkid(sma, semid)	\
	ipc_checkid(&sem_ids,&sma->sem_perm,semid)
#define sem_buildid(id, seq) \
	ipc_buildid(&sem_ids, id, seq)
static struct ipc_ids sem_ids;

static int newary (key_t, int, int);
static void freeary (int id);
#ifdef CONFIG_PROC_FS
static int sysvipc_sem_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data);
#endif

#define SEMMSL_FAST	256 /* 512 bytes on stack */
#define SEMOPM_FAST	64  /* ~ 372 bytes on stack */

/*
 * linked list protection:
 *	sem_undo.id_next,
 *	sem_array.sem_pending{,last},
 *	sem_array.sem_undo: sem_lock() for read/write
 *	sem_undo.proc_next: only "current" is allowed to read/write that field.
 *	
 */
 
 /*
 进程描述符中的数据结构：
struct sem
{
	int semval;     // current value 现在的值
	int sempid      // pid of last operation 上一操作的pid
};
 系统中每个因为信号量而睡眠的进程，都对应一个sem_queue结构
 struct sem_queue {
  struct sem_queue *  next;     // next entry in the queue 队列中的下一个条目
  struct sem_queue **  prev;  // previous entry in the queue, *(q->prev) == q 
  struct task_struct*  sleeper;   // this process 当前进程
  struct sem_undo *  undo;     //undo structure 撤消结构
  int   pid;             // process id of requesting process 
  int   status;           // completion status of operation 
  struct sem_array *  sma;       //semaphore array for operations 
  int  id;               // internal sem id 内部的sem id
  struct sembuf *  sops;       // array of pending operations 
  int  nsops;             // number of operations 
  int  alter;             // operation will alter semaphore 
};

struct sem_undo { 
	struct sem_undo * proc_next; //下一个进程入口
    struct sem_undo * id_next;  //该信号量队列的下一个节点
	int    semid;  //信号量结合的标识符
    short *   semadj;  //调整用数组，每个信号量一个
}; 

struct ipc_ids {
      int in_use;
      unsigned short seq;
      unsigned short seq_max;
      struct rw_semaphorerw_mutex;
      struct idr ipcs_idr;
};
从上图可以看出，全局数据结构struct ipc_ids sem_ids可以访问到struct kern_ipc_perm的第一个成员：struct kern_ipc_perm；而每个struct kern_ipc_perm能够与具体的信号量对应起来是因为在该结构中，有一个key_t类型成员key，而key则唯一确定一个信号量集；同时，结构struct kern_ipc_perm的最后一个成员sem_nsems确定了该信号量在信号量集中的顺序，这样内核就能够记录每个信号量的信息了。
 */

int sem_ctls[4] = {SEMMSL, SEMMNS, SEMOPM, SEMMNI};
#define sc_semmsl	(sem_ctls[0])//每个信号量集的最大信号
#define sc_semmns	(sem_ctls[1])//在所有信号量集合semapho数目的一个系统宽度限制
#define sc_semopm	(sem_ctls[2])//可以在一个信号量操作规定的最大数量的操作
#define sc_semmni	(sem_ctls[3])//对信号量标识符的最大数量的全系统限制。

static int used_sems;

//sem_init() 初始化一个定位在 sem_ids 的匿名信号量。
void __init sem_init (void)
{
	used_sems = 0;
	ipc_init_ids(&sem_ids,sc_semmni);

#ifdef CONFIG_PROC_FS
//在"sysvipc/sem"目录下创建进程读取的信号量文件
	create_proc_read_entry("sysvipc/sem", 0, 0, sysvipc_sem_read_proc, NULL);
#endif
}

//创建一个新的信号量集 
static int newary (key_t key, int nsems, int semflg)
{
	int id;
	struct sem_array *sma;
/*
	系统中的每一个信号量集都对应一个struct sem_array结构，该结构记录了信号量集的各种信息，存在于系统空间。
struct sem_array {
  struct kern_ipc_perm  sem_perm;    // permissions .. see ipc.h 权限
  time_t      sem_otime;      // last semop time 上次操作时间
  time_t      sem_ctime;      // last change time 上次改变时间
  struct sem    *sem_base;      // ptr to first semaphore in array PTR在数组集的第一信号
  struct sem_queue  *sem_pending;    // pending operations to be processed 待处理的作业
  struct sem_queue  **sem_pending_last;   // last pending operation 最后一个挂起的操作
  struct sem_undo    *undo;      // undo requests on this array 撤消对该数组集的要求
  unsigned long    sem_nsems;    // no. of semaphores in array 数组集中信号量的标号
};
*/
	int size;

	if (!nsems)//判断数量是否有效
		return -EINVAL;//无效的参数
	if (used_sems + nsems > sc_semmns)//计算信号量资源的总数量是否超过最大存储范围
		return -ENOSPC;//磁盘空间不足

	size = sizeof (*sma) + nsems * sizeof (struct sem);//计算空间大小
	sma = (struct sem_array *) ipc_alloc(size);//申请空间
	if (!sma) {
		return -ENOMEM;//内存溢出
	}
	memset (sma, 0, size);
	//加入IPC标识符,参数 sem_ids：IPC标识符集 sma->sem_perm：新的IPC的权限集 sc_semmni：ID数组的大小限制
	id = ipc_addid(&sem_ids, &sma->sem_perm, sc_semmni);
	//创建失败
	if(id == -1) {
		ipc_free(sma, size);
		return -ENOSPC;//磁盘空间不足
	}
	//创建成功后，在已使用信号量中加入新建信号量大小
	used_sems += nsems;

	sma->sem_perm.mode = (semflg & S_IRWXUGO);//S_IRWXUGO是可读可写权限
	sma->sem_perm.key = key;

	sma->sem_base = (struct sem *) &sma[1];
	/* sma->sem_pending = NULL; */
	sma->sem_pending_last = &sma->sem_pending;
	/* sma->undo = NULL; */
	sma->sem_nsems = nsems;
	sma->sem_ctime = CURRENT_TIME;//系统现在时间
	sem_unlock(id);

	//分配一个新的标识符并返回
	return sem_buildid(id, sma->sem_perm.seq);
}

//信号量的创建
//参数key是一个键值，由ftok获得，唯一标识一个信号量集，用法与msgget()中的key相同； 参数nsems指定打开或者新创建的信号量集中将包含信号量的数目；semflg参数是一些标志位。参数key和semflg的取值，以及何时打开已有信号量集或者创建一个新的信号量集与msgget()中的对应部分相同。 
//该调用返回与键值key相对应的信号量集描述字。 
//调用返回：成功返回信号量集描述字，否则返回-1。 
asmlinkage long sys_semget (key_t key, int nsems, int semflg)
{
	int id, err = -EINVAL;//EINVAL: Invalid argument(非法值，非法争论，非法论点)
	struct sem_array *sma;

	if (nsems < 0 || nsems > sc_semmsl)//包含信号量数目不合法
		return -EINVAL;
	down(&sem_ids.sem);//挂锁
	
	if (key == IPC_PRIVATE) { //自己私用,无条件创建一个信号量集
		err = newary(key, nsems, semflg);
	} else if ((id = ipc_findkey(&sem_ids, key)) == -1) {/* key not used 键值未使用*/
		if (!(semflg & IPC_CREAT))
			err = -ENOENT;//没有对应文件或目录
		else //设定了就创建报文队列
			err = newary(key, nsems, semflg);
	} else if (semflg & IPC_CREAT && semflg & IPC_EXCL) {
		//同时设定了IPC_CREAT与IPC_EXCL返回错误
		err = -EEXIST;//已存在
	} else {
		sma = sem_lock(id);
		if(sma==NULL)
			BUG();
		if (nsems > sma->sem_nsems)//新加入信号量长度过长
			err = -EINVAL;  // EINVAL： Invalid argument
		else if (ipcperms(&sma->sem_perm, semflg))//检查访问权限是否符合规则
			err = -EACCES;
		else
			err = sem_buildid(id, sma->sem_perm.seq);//将数组下标转换一体化的标识号
		sem_unlock(id);
	}
	//增加信号量
	up(&sem_ids.sem);
	return err;
}

/* doesn't acquire the sem_lock on error! 没有获得sem_lock错误*/
//信号量的对比验证
static int sem_revalidate(int semid, struct sem_array* sma, int nsems, short flg)
{
	struct sem_array* smanew;

	smanew = sem_lock(semid);
	if(smanew==NULL)
		return -EIDRM;//标识符丢失
	//检查信号量集，信号量id和数组集中信号量的标号
	if(smanew != sma || sem_checkid(sma,semid) || sma->sem_nsems != nsems) {
		sem_unlock(semid);
		return -EIDRM;//标识符丢失
	}

	if (ipcperms(&sma->sem_perm, flg)) {//对访问者进行访问权限检查
		sem_unlock(semid);
		return -EACCES;//权限被拒绝
	}
	return 0;
}
/* Manage the doubly linked list sma->sem_pending as a FIFO:
 * insert new queue elements at the tail sma->sem_pending_last.
 管理双链表SMA -> sem_pending为FIFO：在SMA -> sem_pending_last尾部插入新的队列元素。
 */
 //队列向后追加信号量
static inline void append_to_queue (struct sem_array * sma,
				    struct sem_queue * q)
{
	//对链表进行操作
	*(q->prev = sma->sem_pending_last) = q;
	*(sma->sem_pending_last = &q->next) = NULL;
}

 //队列向前追加信号量
static inline void prepend_to_queue (struct sem_array * sma,
				     struct sem_queue * q)
{
	q->next = sma->sem_pending;
	*(q->prev = &sma->sem_pending) = q;
	if (q->next)
		q->next->prev = &q->next;
	else /* sma->sem_pending_last == &sma->sem_pending */
		sma->sem_pending_last = &q->next;
}

//从队列中移除信号量
static inline void remove_from_queue (struct sem_array * sma,
				      struct sem_queue * q)
{
	*(q->prev) = q->next;
	if (q->next)
		q->next->prev = q->prev;
	else /* sma->sem_pending_last == &q->next */
		sma->sem_pending_last = q->prev;
	q->prev = NULL; /* mark as removed 标记为删除 */
}

/*
 * Determine whether a sequence of semaphore operations would succeed
 * all at once. Return 0 if yes, 1 if need to sleep, else return error code.
确定一个原子的信号量操作序列是否成功。如果是，返回0，如果需要睡眠，返回1，否则返回错误代码
 */
//当try_atomic_semop返回非正值时，表示不需要再等待，此时唤醒等待进程
static int try_atomic_semop (struct sem_array * sma, struct sembuf * sops,
			     int nsops, struct sem_undo *un, int pid,
			     int do_undo)
{
	int result, sem_op;
	struct sembuf *sop;
	/*
	struct sembuf {
    unsigned short      sem_num;        //semaphore index in array 在队列中的信号量的序号
    short           sem_op;     //semaphore operation 信号量值在一次操作中的改变量
    short           sem_flg;        //operation flags 操作标志 常取值IPC_NOWAIT,SEM_UNDO
};
	*/
	struct sem * curr;

	for (sop = sops; sop < sops + nsops; sop++) {
		curr = sma->sem_base + sop->sem_num;//定位到sop所指的具体的sem项
		sem_op = sop->sem_op;
		if (!sem_op && curr->semval)//如果没有改变量且现有信号量有值
			goto would_block;

		curr->sempid = (curr->sempid << 16) | pid;
		curr->semval += sem_op;
		if (sop->sem_flg & SEM_UNDO)//撤销条件
//SEM_UNDO用于将修改的信号量值在进程正常退出（调用exit退出或main执行完）或异常退出（如段异常、除0异常、收到KILL信号等）时归还给信号量
		{
			int undo = un->semadj[sop->sem_num] - sem_op;//计算信号量更改范围是否有效
			/*
	 		 *	Exceeding the undo range is an error.
			 超出撤消范围是错误的。
			 */
			if (undo < (-SEMAEM - 1) || undo > SEMAEM)//SEMAEM:可以记录信号量调整的最大值
			{
				/* Don't undo the undo 不要撤消撤销操作*/
				sop->sem_flg &= ~SEM_UNDO;
				goto out_of_range;
			}
			un->semadj[sop->sem_num] = undo;//归还更改值
		}
		if (curr->semval < 0)//信号量的值小于零
			goto would_block;
		if (curr->semval > SEMVMX)//信号量的值超过最大值
			goto out_of_range;
	}

	if (do_undo)
	{
		sop--;
		result = 0;
		goto undo;
	}

	sma->sem_otime = CURRENT_TIME;
	return 0;

out_of_range: //越界操作
	result = -ERANGE;
	goto undo;

//如果sem_op的值为0，则操作将暂时阻塞，直到信号的值变为0
would_block: //指定IPC_NOWAIT，则出错返回EAGAIN
	if (sop->sem_flg & IPC_NOWAIT)
		result = -EAGAIN;
	else
		result = 1;

undo://进程退出时，将修改的值归还给信号量
	while (sop >= sops) {
		curr = sma->sem_base + sop->sem_num;//定位到sop所指的具体的sem项
		curr->semval -= sop->sem_op;//对semval值进行操作
		curr->sempid >>= 16;

		if (sop->sem_flg & SEM_UNDO)
			un->semadj[sop->sem_num] += sop->sem_op;
		sop--;
	}

	return result;
}

/* Go through the pending queue for the indicated semaphore
 * looking for tasks that can be completed.
 为所指示的信号量通过挂起的队列查找可以完成的任务。即处理对应信号量的待决操作列表
 */
static void update_queue (struct sem_array * sma)
{
	int error;
	struct sem_queue * q;

	for (q = sma->sem_pending; q; q = q->next) {//待处理作业
			
		if (q->status == 1)
			continue;	/* this one was woken up before 之前这一次被唤醒了*/

		//确定一个信号量操作序列是否成功
		error = try_atomic_semop(sma, q->sops, q->nsops,
					 q->undo, q->pid, q->alter);

		/* Does q->sleeper still need to sleep? q->sleeper仍需要休眠吗？*/
		if (error <= 0) {
				/* Found one, wake it up 找到一个，唤醒他*/
			wake_up_process(q->sleeper);
			if (error == 0 && q->alter) {
				/* if q-> alter let it self try 如果q-> alter，让他自己尝试*/
				q->status = 1;
				return;
			}
			q->status = error;
			//从队列中移除信号量
			remove_from_queue(sma,q);
		}
	}
}

/* The following counts are associated to each semaphore:
 *   semncnt        number of tasks waiting on semval being nonzero
 *   semzcnt        number of tasks waiting on semval being zero
 * This model assumes that a task waits on exactly one semaphore.
 * Since semaphore operations are to be performed atomically, tasks actually
 * wait on a whole sequence of semaphores simultaneously.
 * The counts we return here are a rough approximation, but still
 * warrant that semncnt+semzcnt>0 if the task is on the pending queue.
 以下计数器与每个信号量相关：
 semncnt 任务在等待semval不为零
 semzcnt 任务在等待semval为零
 该模型假定任务只在一个信号量上等待。由于信号的操作可以自动执行，任务其实同时等待整个序列的信号。这里我们返回的计数是一个粗略的近似，但仍保证如果任务在等待队列时，semncnt + semzcnt > 0。
 成员 semncnt 实际上就是被挂起的等待 semval 增加的进程数量。至于成员 semzcnt 是另一种挂起的进程，它们被唤醒的条件是 semval 变为0。
 */
 
//semncnt计数器
static int count_semncnt (struct sem_array * sma, ushort semnum)
{
	int semncnt;
	struct sem_queue * q;

	semncnt = 0;
	for (q = sma->sem_pending; q; q = q->next) {//遍历链表
		struct sembuf * sops = q->sops;
		int nsops = q->nsops;
		int i;
		for (i = 0; i < nsops; i++)
			//判断被挂起的等待 semval 增加的进程数量
			if (sops[i].sem_num == semnum
			    && (sops[i].sem_op < 0)
			    && !(sops[i].sem_flg & IPC_NOWAIT))
				semncnt++;
	}
	return semncnt;
}
//semzcnt计数器
static int count_semzcnt (struct sem_array * sma, ushort semnum)
{
	int semzcnt;
	struct sem_queue * q;

	semzcnt = 0;
	for (q = sma->sem_pending; q; q = q->next) {
		struct sembuf * sops = q->sops;
		int nsops = q->nsops;
		int i;
		for (i = 0; i < nsops; i++)
			//判断挂起的，被唤醒的条件是 semval 变为0的进程
			if (sops[i].sem_num == semnum
			    && (sops[i].sem_op == 0)
			    && !(sops[i].sem_flg & IPC_NOWAIT))
				semzcnt++;
	}
	return semzcnt;
}

/* Free a semaphore set. 释放信号量组*/
static void freeary (int id)
{
	struct sem_array *sma;
	struct sem_undo *un;
	struct sem_queue *q;
	int size;

	sma = sem_rmid(id);

	/* Invalidate the existing undo structures for this semaphore set.
	 * (They will be freed without any further action in sem_exit()
	 * or during the next semop.
	 使此信号量集的现有撤消结构无效。（他们将被释放，sem_exit()没有任何进一步的行动或下一个信号量操作到来前)
	 */
	for (un = sma->undo; un; un = un->id_next)
		un->semid = -1;

	/* Wake up all pending processes and let them fail with EIDRM. 唤醒所有等待的过程，让他们失败时返回eidrm。*/
	for (q = sma->sem_pending; q; q = q->next) {
		q->status = -EIDRM;//标识符被删除
		q->prev = NULL;
		wake_up_process(q->sleeper); /* doesn't sleep 不休眠*/
	}
	sem_unlock(id);//释放信号量锁

	used_sems -= sma->sem_nsems;//信号量递减
	size = sizeof (*sma) + sma->sem_nsems * sizeof (struct sem);
	ipc_free(sma, size);//释放空间
}

//拷贝消息量的id给用户
static unsigned long copy_semid_to_user(void *buf, struct semid64_ds *in, int version)
{
	switch(version) {
	case IPC_64:
		return copy_to_user(buf, in, sizeof(*in));
	case IPC_OLD:
	    {
		struct semid_ds out;

		ipc64_perm_to_ipc_perm(&in->sem_perm, &out.sem_perm);

		out.sem_otime	= in->sem_otime;
		out.sem_ctime	= in->sem_ctime;
		out.sem_nsems	= in->sem_nsems;

		return copy_to_user(buf, &out, sizeof(out));
	    }
	default:
		return -EINVAL;
	}
}

//semctl无锁的操作
int semctl_nolock(int semid, int semnum, int cmd, int version, union semun arg)
{
	int err = -EINVAL;

	switch(cmd) {
	case IPC_INFO:
	case SEM_INFO:
	{
		struct seminfo seminfo;
		int max_id;

		//初始化seminfo结构体
		memset(&seminfo,0,sizeof(seminfo));
		seminfo.semmni = sc_semmni;
		seminfo.semmns = sc_semmns;
		seminfo.semmsl = sc_semmsl;
		seminfo.semopm = sc_semopm;
		seminfo.semvmx = SEMVMX;
		seminfo.semmnu = SEMMNU;
		seminfo.semmap = SEMMAP;
		seminfo.semume = SEMUME;
		down(&sem_ids.sem);//减少信号量
		if (cmd == SEM_INFO) {
			seminfo.semusz = sem_ids.in_use;//显示信息，已使用信号量
			seminfo.semaem = used_sems;
		} else {
			seminfo.semusz = SEMUSZ;
			seminfo.semaem = SEMAEM;
		}
		max_id = sem_ids.max_id;
		up(&sem_ids.sem);//增加信号量
		if (copy_to_user (arg.__buf, &seminfo, sizeof(struct seminfo))) 
			return -EFAULT;
		//返回sem_ids的max_id
		return (max_id < 0) ? 0: max_id;
	}
	case SEM_STAT:
	{
		struct sem_array *sma;
		struct semid64_ds tbuf;
		int id;

		if(semid >= sem_ids.size)//检查id是否越界
			return -EINVAL;

		memset(&tbuf,0,sizeof(tbuf));

		sma = sem_lock(semid);//对一个信号量类型的IPC资源进行锁定
		if(sma == NULL)
			return -EINVAL;

		err = -EACCES;
		if (ipcperms (&sma->sem_perm, S_IRUGO))//检查读写权限
			goto out_unlock;
		id = sem_buildid(semid, sma->sem_perm.seq);//分配一个新的标识符并返回

		//ipc权限转化，核权限->新型IPC权限,返回用户空间(out)
		kernel_to_ipc64_perm(&sma->sem_perm, &tbuf.sem_perm);
		tbuf.sem_otime  = sma->sem_otime;
		tbuf.sem_ctime  = sma->sem_ctime;
		tbuf.sem_nsems  = sma->sem_nsems;
		sem_unlock(semid);//资源解锁
		if (copy_semid_to_user (arg.buf, &tbuf, version))
			return -EFAULT;
		return id;
	}
	default:
		return -EINVAL;
	}
	return err;
out_unlock:
//对一个信号量类型的IPC资源进行解锁
	sem_unlock(semid);
	return err;
}

//由sys_semctl()调用执行其支持功能，执行下列任何操作之前，semctl_main()加挂全局信号量。它验证信号量集ID和权限。返回前，自旋锁被释放。
int semctl_main(int semid, int semnum, int cmd, int version, union semun arg)
{
	struct sem_array *sma;
	struct sem* curr;
	int err;
	ushort fast_sem_io[SEMMSL_FAST];
	ushort* sem_io = fast_sem_io;
	int nsems;

	sma = sem_lock(semid);//于对一个信号量类型的IPC资源进行锁定
	if(sma==NULL)
		return -EINVAL;

	nsems = sma->sem_nsems;

	err=-EIDRM;
	if (sem_checkid(sma,semid))//用于读取信号量集中的所有信号量的值
		goto out_unlock;

	err = -EACCES;
	if (ipcperms (&sma->sem_perm, (cmd==SETVAL||cmd==SETALL)?S_IWUGO:S_IRUGO))//读写权限
		goto out_unlock;

	switch (cmd) {
	case GETALL://用于读取信号量集中的所有信号量的值
	{
		ushort *array = arg.array;
		int i;

		if(nsems > SEMMSL_FAST) {
			sem_unlock(semid);			
			sem_io = ipc_alloc(sizeof(ushort)*nsems);
			if(sem_io == NULL)
				return -ENOMEM;
			err = sem_revalidate(semid, sma, nsems, S_IRUGO);//验证信号量ID和权限
			if(err)
				goto out_free;
		}

		for (i = 0; i < sma->sem_nsems; i++)
			sem_io[i] = sma->sem_base[i].semval;//读取信号量值
		sem_unlock(semid);
		err = 0;
		if(copy_to_user(array, sem_io, nsems*sizeof(ushort)))
			err = -EFAULT;
		goto out_free;
	}
	case SETALL://用于设置信号量集中的所有信号量的值
	{
		int i;
		struct sem_undo *un;

		sem_unlock(semid);

		if(nsems > SEMMSL_FAST) {
			sem_io = ipc_alloc(sizeof(ushort)*nsems);
			if(sem_io == NULL)
				return -ENOMEM;
		}

		if (copy_from_user (sem_io, arg.array, nsems*sizeof(ushort))) {//复制信号量集给sem_io
			err = -EFAULT;
			goto out_free;
		}

		for (i = 0; i < nsems; i++) {
			if (sem_io[i] > SEMVMX) {//信号量的值超过最大值
				err = -ERANGE;
				goto out_free;
			}
		}
		//验证信号量ID和权限
		err = sem_revalidate(semid, sma, nsems, S_IWUGO);
		if(err)
			goto out_free;

		for (i = 0; i < nsems; i++)
			sma->sem_base[i].semval = sem_io[i];//写入信号量值
		for (un = sma->undo; un; un = un->id_next)
			for (i = 0; i < nsems; i++)
				un->semadj[i] = 0;
		sma->sem_ctime = CURRENT_TIME;
		/* maybe some queued-up processes were waiting for this 也许一些排队等候的进程正在等待它*/
		update_queue(sma);
		err = 0;
		goto out_unlock;
	}
	case IPC_STAT://读取一个信号量集的数据结构semid_ds，并将其存储在semun中的buf参数中
	{
		struct semid64_ds tbuf;
		memset(&tbuf,0,sizeof(tbuf));
		//ipc权限转化，核权限->新型IPC权限,返回用户空间(out)
		kernel_to_ipc64_perm(&sma->sem_perm, &tbuf.sem_perm);
		tbuf.sem_otime  = sma->sem_otime;
		tbuf.sem_ctime  = sma->sem_ctime;
		tbuf.sem_nsems  = sma->sem_nsems;
		sem_unlock(semid);
		if (copy_semid_to_user (arg.buf, &tbuf, version))//存储读取的信息
			return -EFAULT;
		return 0;
	}
	/* GETVAL, GETPID, GETNCTN, GETZCNT, SETVAL: fall-through 落空 */
	}
	err = -EINVAL;
	if(semnum < 0 || semnum >= nsems)
		goto out_unlock;

	curr = &sma->sem_base[semnum];

	switch (cmd) {
	case GETVAL:
		err = curr->semval;
		goto out_unlock;
	case GETPID://获取pid
		err = curr->sempid & 0xffff;
		goto out_unlock;
	case GETNCNT:
		err = count_semncnt(sma,semnum);
		goto out_unlock;
	case GETZCNT:
		err = count_semzcnt(sma,semnum);
		goto out_unlock;
	case SETVAL:
	{
		int val = arg.val;
		struct sem_undo *un;
		err = -ERANGE;
		if (val > SEMVMX || val < 0)//信号量的值超过最大值
			goto out_unlock;

		for (un = sma->undo; un; un = un->id_next)
			un->semadj[semnum] = 0;
		curr->semval = val;
		sma->sem_ctime = CURRENT_TIME;
		/* maybe some queued-up processes were waiting for this 也许一些排队等候的进程正在等待这一点*/
		update_queue(sma);
		err = 0;
		goto out_unlock;
	}
	}
out_unlock:
	sem_unlock(semid);
out_free:
	if(sem_io != fast_sem_io)
		ipc_free(sem_io, sizeof(ushort)*nsems);
	return err;
}

struct sem_setbuf {
	uid_t	uid;
	gid_t	gid;
	mode_t	mode;
};

static inline unsigned long copy_semid_from_user(struct sem_setbuf *out, void *buf, int version)//复制信号量的id
{
	switch(version) {
	case IPC_64:
	    {
		struct semid64_ds tbuf;

		if(copy_from_user(&tbuf, buf, sizeof(tbuf)))
			return -EFAULT;

		out->uid	= tbuf.sem_perm.uid;
		out->gid	= tbuf.sem_perm.gid;
		out->mode	= tbuf.sem_perm.mode;

		return 0;
	    }
	case IPC_OLD:
	    {
		struct semid_ds tbuf_old;

		if(copy_from_user(&tbuf_old, buf, sizeof(tbuf_old)))
			return -EFAULT;

		out->uid	= tbuf_old.sem_perm.uid;
		out->gid	= tbuf_old.sem_perm.gid;
		out->mode	= tbuf_old.sem_perm.mode;

		return 0;
	    }
	default:
		return -EINVAL;
	}
}

int semctl_down(int semid, int semnum, int cmd, int version, union semun arg)
//semctl_down()提供semctl()系统调用中的ipc_rmid和ipc_set操作。验证这些操作之前的信号量集的身份和访问权限，并在任何情况下，全局信号量的自旋锁通过操作控制
{
	struct sem_array *sma;
	int err;
	struct sem_setbuf setbuf;
	struct kern_ipc_perm *ipcp;

	if(cmd == IPC_SET) {
		if(copy_semid_from_user (&setbuf, arg.buf, version))
			return -EFAULT;
	}
	sma = sem_lock(semid);
	if(sma==NULL)
		return -EINVAL;

	if (sem_checkid(sma,semid)) {
		err=-EIDRM;
		goto out_unlock;
	}	
	ipcp = &sma->sem_perm;
	
	if (current->euid != ipcp->cuid && 
	    current->euid != ipcp->uid && !capable(CAP_SYS_ADMIN)) {//允许执行系统管理任务,如挂载/卸载文件系统,设置磁盘配额,开/关交换设备和文件
	    	err=-EPERM;//Operation not permitted 不允许操作
		goto out_unlock;
	}

	switch(cmd){
	case IPC_RMID:
		freeary(semid);//释放信号量组
		err = 0;
		break;
	case IPC_SET:
		ipcp->uid = setbuf.uid;
		ipcp->gid = setbuf.gid;
		ipcp->mode = (ipcp->mode & ~S_IRWXUGO)
				| (setbuf.mode & S_IRWXUGO);
		sma->sem_ctime = CURRENT_TIME;
		sem_unlock(semid);
		err = 0;
		break;
	default:
		sem_unlock(semid);
		err = -EINVAL;
		break;
	}
	return err;

out_unlock:
	sem_unlock(semid);
	return err;
}
/*
该系统调用实现对信号量的各种控制操作，参数semid指定信号量集，参数cmd指定具体的操作类型；参数semnum指定对哪个信号量操作，只对几个特殊的cmd操作有意义；arg用于设置或返回信号量信息。 
*/
asmlinkage long sys_semctl (int semid, int semnum, int cmd, union semun arg)
{
	int err = -EINVAL;
	int version;

	// 判断参数是否合法
	if (semid < 0)
		return -EINVAL;

	version = ipc_parse_version(&cmd);//解析IPC调用版本,对不同的命令采用不同的内部函数进行操作

	switch(cmd) {
	case IPC_INFO:
/*Linux特有命令，返回系统范围内关于信号集的制约和其它参数，并存放在arg.__buf指向的内存区。其结构形态如下：
struct  seminfo {
    int semmap;  // # of entries in semaphore map; unused 
    int semmni;  // Max. # of semaphore sets 
    int semmns;  // Max. # of semaphores in all semaphore sets 
    int semmnu;  // System-wide max. # of undo structures; unused 
    int semmsl;  //Max. # of semaphores in a set 
    int semopm;  // Max. # of operations for semop() 
    int semume;  // Max. # of undo entries per process; unused 
    int semusz;  // size of struct sem_undo 
    int semvmx;  // Maximum semaphore value 
    int semaem;  // Max. value that can be recorded for semaphore adjustment (SEM_UNDO) 
};
*/
	case SEM_INFO://返回和IPC_INFO相同的信息，不同点有：semusz字段包含有当前系统存在的信号集总量。semaem字段包含有系统内所有信号集的信号总量。
	case SEM_STAT://返回和IPC_STAT相同的信息。不过参数semid不是一个信号集标识，而是内核内部维持所有信号集信息的数组索引。
		err = semctl_nolock(semid,semnum,cmd,version,arg);
		return err;
	case GETALL://用于读取信号量集中的所有信号量的值
	case GETVAL://返回信号量集中的一个单个的信号量的值
	case GETPID://返回最后一个执行semop操作的进程的PID
	case GETNCNT://返回正在等待资源的进程数目
	case GETZCNT://返回这在等待完全空闲的资源的进程数目
	case IPC_STAT://读取一个信号量集的数据结构semid_ds，并将其存储在semun中的buf参数中
	case SETVAL://设置信号量集中的一个单独的信号量的值
	case SETALL://设置信号量集中的所有的信号量的值
		err = semctl_main(semid,semnum,cmd,version,arg);
		return err;
	case IPC_RMID://将信号量集从内存中删除
	case IPC_SET://设置信号量集的数据结构semid_ds中的元素ipc_perm，其值取自semun中的buf参数
		down(&sem_ids.sem);
		err = semctl_down(semid,semnum,cmd,version,arg);
		up(&sem_ids.sem);
		return err;
	default:
		return -EINVAL;//EINVAL： Invalid argument
	}
}


static struct sem_undo* freeundos(struct sem_array *sma, struct sem_undo* un)
//遍历过程中所需的撤消结构搜索列表。如果找到，撤消结构将从列表中移除并释放。返回进程列表中的下一个撤消结构的指针
{
	struct sem_undo* u;
	struct sem_undo** up;

	for(up = &current->semundo;(u=*up);up=&u->proc_next) {
		if(un==u) {
			un=u->proc_next;
			*up=un;
			kfree(u);
			return un;
		}
	}
	printk ("freeundos undo list error id=%d\n", un->semid);
	return un->proc_next;
}

/* returns without sem_lock on error! 没有sem_lock错误返回*/
//信号锁解锁，并执行kmalloc()给sem_undo结构，和以每个信号量的设置为值的集合分配足够的内存
static int alloc_undo(struct sem_array *sma, struct sem_undo** unp, int semid, int alter)
{
	int size, nsems, error;
	struct sem_undo *un;

	nsems = sma->sem_nsems;
	size = sizeof(struct sem_undo) + sizeof(short)*nsems;
	sem_unlock(semid);

	un = (struct sem_undo *) kmalloc(size, GFP_KERNEL);//给撤销结构分配内存，GFP_KERNEL：无内存可用时可引起休眠
	if (!un)
		return -ENOMEM;

	memset(un, 0, size);
	//验证信号量ID和权限
	error = sem_revalidate(semid, sma, nsems, alter ? S_IWUGO : S_IRUGO);
	if(error) {
		kfree(un);//出错释放
		return error;
	}

	un->semadj = (short *) &un[1];
	un->semid = semid;
	un->proc_next = current->semundo;
	current->semundo = un;
	un->id_next = sma->undo;
	sma->undo = un;
	*unp = un;
	return 0;
}

/*
调用semop系统调用实现同步互斥控制
int semop(int semid, struct sembuf *sops, unsigned nsops); 
semid是信号量集ID，sops指向数组的每一个sembuf结构都刻画一个在特定信号量上的操作。nsops为sops指向数组的大小。

如果sem_op是负数，那么信号量将减去它的值。这和信号量控制的资源有关。如果没有使用IPC_NOWAIT， 那么调用进程将进入睡眠状态，直到信号 量控制的资源可以使用为止。如果sem_op是正数，则信号量加上 它的值。这也就是进程释放信号量控制的资源。最后，如果sem_op是0，那么调用进程 将调用sleep()， 直到信号量的值为0。这在一个进程等待完全空闲的资源时使用。
调用返回：成功返回0，否则返回-1。
*/
asmlinkage long sys_semop (int semid, struct sembuf *tsops, unsigned nsops)
{
	int error = -EINVAL;//EINVAL： Invalid argument
	struct sem_array *sma;
	struct sembuf fast_sops[SEMOPM_FAST];
	struct sembuf* sops = fast_sops, *sop;
	struct sem_undo *un;
	int undos = 0, decrease = 0, alter = 0;
	struct sem_queue queue;

	if (nsops < 1 || semid < 0)
		return -EINVAL;//信号量集不存在,或者semid无效
	if (nsops > sc_semopm)
		return -E2BIG;//nsops大于最大的ops数目
	if(nsops > SEMOPM_FAST) {//操作数是否超出以分配的数量
		sops = kmalloc(sizeof(*sops)*nsops,GFP_KERNEL);//申请新的信号量集的空间
		if(sops==NULL)
			return -ENOMEM;//使用了SEM_UNDO,但无足够的内存创建所需的数据结构
	}
	if (copy_from_user (sops, tsops, nsops * sizeof(*tsops))) {
		error=-EFAULT;//sops指向的地址无效
		goto out_free;
	}
	//资源上锁
	sma = sem_lock(semid);
	error=-EINVAL;//参数无效
	if(sma==NULL)
		goto out_free;
	error = -EIDRM;//信号量集已经删除
	if (sem_checkid(sma,semid))//检查一个信号量资源标识符是否已被使用
		goto out_unlock_free;
	error = -EFBIG;//文件过大
	for (sop = sops; sop < sops + nsops; sop++) {
		if (sop->sem_num >= sma->sem_nsems)
			goto out_unlock_free;
		if (sop->sem_flg & SEM_UNDO)//判断是否为undo操作
			undos++;
		if (sop->sem_op < 0)//sem_op是负数,信号量将减去它的值
			decrease = 1;
		if (sop->sem_op > 0)//sem_op是正数，则信号量加上它的值
			alter = 1;
	}
	alter |= decrease;

	error = -EACCES;//权限不够
	if (ipcperms(&sma->sem_perm, alter ? S_IWUGO : S_IRUGO))//读写权限检查
		goto out_unlock_free;
	if (undos) {
		/* Make sure we have an undo structure
		 * for this process and this semaphore set.
		 确保这个进程和这个信号量集有一个撤销结构，
		 */
		un=current->semundo;
		while(un != NULL) {//寻找对应id的信号量
			if(un->semid==semid)
				break;
			if(un->semid==-1)
				un=freeundos(sma,un);
			 else
				un=un->proc_next;
		}
		if (!un) {
			error = alloc_undo(sma,&un,semid,alter);//撤销信号量改变
			if(error)
				goto out_free;
		}
	} else
		un = NULL;

	error = try_atomic_semop (sma, sops, nsops, un, current->pid, 0);
	if (error <= 0)
		goto update;

	/* We need to sleep on this operation, so we put the current
	 * task into the pending queue and go to sleep.
	 我们需要这个操作休眠，所以我们把当前任务放到挂起的队列中去休眠
	 */
		
	//初始化队列
	queue.sma = sma;
	queue.sops = sops;
	queue.nsops = nsops;
	queue.undo = un;
	queue.pid = current->pid;
	queue.alter = decrease;
	queue.id = semid;
	if (alter)
		append_to_queue(sma ,&queue);
	else
		prepend_to_queue(sma ,&queue);
	current->semsleeping = &queue;

	for (;;) {
		struct sem_array* tmp;
		queue.status = -EINTR;
		queue.sleeper = current;
		current->state = TASK_INTERRUPTIBLE;//收到信号会被唤醒并处理信号(然后再次进入等待睡眠状态)
		sem_unlock(semid);

		schedule();//调度

		tmp = sem_lock(semid);
		if(tmp==NULL) {//上锁未成功
			if(queue.prev != NULL)
				BUG();
			current->semsleeping = NULL;
			error = -EIDRM;//信号量集已经删除
			goto out_free;
		}
		/*
		 * If queue.status == 1 we where woken up and
		 * have to retry else we simply return.
		 * If an interrupt occurred we have to clean up the
		 * queue
		 *如果queue.status =1 我们处于唤醒状态，我们还简单地返回重试。
		 如果发生中断，我们必须清理队列
		 */
		if (queue.status == 1)
		{
			error = try_atomic_semop (sma, sops, nsops, un,
						  current->pid,0);
			//函数try_atomic_semop决定一系列信号量操作是否成功，如果成功就返回0，返回1表示需要睡眠，其他表示错误。
			if (error <= 0) 
				break;
		} else {
			error = queue.status;
			if (queue.prev) /* got Interrupt 获得中断*/
				break;
			/* Everything done by update_queue 一切由update_queue做好了*/
			current->semsleeping = NULL;
			goto out_unlock_free;
		}
	}
	current->semsleeping = NULL;
	remove_from_queue(sma,&queue);//从队列中删除信号量
update:
	if (alter)
		update_queue (sma);
out_unlock_free:
	sem_unlock(semid);//信号量解锁资源
out_free:
	if(sops != fast_sops)
		kfree(sops);//释放内存
	return error;
}

/*
 * add semadj values to semaphores, free undo structures.
 * undo structures are not freed when semaphore arrays are destroyed
 * so some of them may be out of date.
 * IMPLEMENTATION NOTE: There is some confusion over whether the
 * set of adjustments that needs to be done should be done in an atomic
 * manner or not. That is, if we are attempting to decrement the semval
 * should we queue up and wait until we can do so legally?
 * The original implementation attempted to do this (queue and wait).
 * The current implementation does not do so. The POSIX standard
 * and SVID should be consulted to determine what behavior is mandated.
添加semadj值信号，释放undo结构。
当信号量数组被销毁时，撤消结构不会释放，因此一些数组可能已经过时。
执行说明：在是否需要以原子方式进行的一组调整上有一些混淆。那就是，如果我们试图减少semval，我们是否应该排队等待，这样做合法吗？最初的实现尝试这样做（队列和等待）。目前的实施不这样做。POSIX标准和SVID应确定什么行为是强制的。
 */
/*	
	sem_exit() is called by do_exit(), and is responsible for executing all of the undo adjustments for the exiting task.
	If the current process was blocked on a semaphore, then it is removed from the sem_queue list while holding the global semaphores spinlock.
	The undo list for the current task is then traversed, and the following operations are performed while holding and releasing the the global semaphores spinlock around the processing of each element of the list. The following operations are performed for each of the undo elements:
	The undo structure and the semaphore set ID are validated.
	The undo list of the corresponding semaphore set is searched to find a reference to the same undo structure and to remove it from that list.
	The adjustments indicated in the undo structure are applied to the semaphore set.
	The sem_otime parameter of the semaphore set is updated.
	update_queue() is called to traverse the queue of pending semops and awaken any sleeping tasks that no longer need to be blocked as a result of executing the undo operations.
	The undo structure is freed.
	When the processing of the list is complete, the current->semundo value is cleared.
*/
void sem_exit (void)
{
	struct sem_queue *q;
	struct sem_undo *u, *un = NULL, **up, **unp;
	struct sem_array *sma;
	int nsems, i;

	/* If the current process was sleeping for a semaphore,
	 * remove it from the queue.
	 如果当前进程正在为信号量休眠，则将其从队列中删除
	 */
	if ((q = current->semsleeping)) {
		int semid = q->id;
		sma = sem_lock(semid);
		current->semsleeping = NULL;

		if (q->prev) {
			if(sma==NULL)
				BUG();
			remove_from_queue(q->sma,q);//将当前进程从队列中释放
		}
		if(sma!=NULL)
			sem_unlock(semid);
	}

	for (up = &current->semundo; (u = *up); *up = u->proc_next, kfree(u)) {//逐个释放当前进程的undo结构
		int semid = u->semid;
		if(semid == -1)
			continue;
		sma = sem_lock(semid);
		if (sma == NULL)
			continue;

		if (u->semid == -1)
			goto next_entry;

		if (sem_checkid(sma,u->semid))
			goto next_entry;

		/* remove u from the sma->undo list 将u从sma的撤销列表中移除*/
		for (unp = &sma->undo; (un = *unp); unp = &un->id_next) {
			if (u == un)//找的对应undo结构
				goto found;
		}
		printk ("sem_exit undo list error id=%d\n", u->semid);
		goto next_entry;
found:
		*unp = un->id_next;
		/* perform adjustments registered in u 执行已在U中注册的调整*/
		nsems = sma->sem_nsems;
		for (i = 0; i < nsems; i++) {
			struct sem * sem = &sma->sem_base[i];
			sem->semval += u->semadj[i];//更改信号量的值
			if (sem->semval < 0)
				sem->semval = 0; /* shouldn't happen 不该发生*/
			sem->sempid = current->pid;
		}
		sma->sem_otime = CURRENT_TIME;
		/* maybe some queued-up processes were waiting for this 也许一些排队等候的进程正在等待这个。*/
		update_queue(sma);
next_entry:
		sem_unlock(semid);
	}
	current->semundo = NULL;//清空undo值
}

#ifdef CONFIG_PROC_FS
static int sysvipc_sem_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int i, len = 0;

	len += sprintf(buffer, "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n");
	down(&sem_ids.sem);//减少信号量

	for(i = 0; i <= sem_ids.max_id; i++) {
		struct sem_array *sma;//记录了信号量集的各种信息
		sma = sem_lock(i);//sem_lock对一个信号量类型的IPC资源进行锁定
		if(sma) {
			len += sprintf(buffer + len, "%10d %10d  %4o %10lu %5u %5u %5u %5u %10lu %10lu\n",
				sma->sem_perm.key,
				sem_buildid(i,sma->sem_perm.seq),
				sma->sem_perm.mode,
				sma->sem_nsems,
				sma->sem_perm.uid,
				sma->sem_perm.gid,
				sma->sem_perm.cuid,
				sma->sem_perm.cgid,
				sma->sem_otime,
				sma->sem_ctime);//把格式化的数据写入buffer+len所指字符串缓冲区
			sem_unlock(i);

			//通过检测偏移量地址判断是否写入完成
			pos += len;
			if(pos < offset) {
				len = 0;
	    			begin = pos;
			}
			if(pos > offset + length)
				goto done;
		}
	}
	*eof = 1;//文件终止
done:
	up(&sem_ids.sem);//增加信号量
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if(len > length)
		len = length;
	if(len < 0)
		len = 0;
	return len;//返回数据长度
}
#endif
