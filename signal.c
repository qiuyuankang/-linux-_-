/*
 *  linux/kernel/signal.c
 linux内核/ signal.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 版权(C)1991,1992年Linus Torvalds
 *
 *  1997-11-02  Modified for POSIX.1b signals by Richard Henderson
 1997-11- 02对POSIX进行了修改。理查德·亨德森的1b信号
 */


/*
linux内核/ signal.c 
*
*版权(C)1991,1992年Linus Torvalds
*
* 1997-11- 02对POSIX进行了修改。理查德·亨德森的1b信号
*/
 
 
#include <linux/config.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/sched.h>

#include <asm/uaccess.h>

/*
* SLAB caches for signal bits.
*用于信号位的平板缓存。
*/

#define DEBUG_SIG 0

#if DEBUG_SIG
#define SIG_SLAB_DEBUG	(SLAB_DEBUG_FREE | SLAB_RED_ZONE /* | SLAB_POISON */)
          
#else
#define SIG_SLAB_DEBUG	0
#endif

/* | SLAB_POISON */
/* 分片阻隔 */

static kmem_cache_t *sigqueue_cachep;

atomic_t nr_queued_signals;
int max_queued_signals = 1024;

void __init signals_init(void)
{
	sigqueue_cachep =
		kmem_cache_create("sigqueue",
				  sizeof(struct sigqueue),
				  __alignof__(struct sigqueue),
				  SIG_SLAB_DEBUG, NULL, NULL);
	    /*kmem_cache_create - 创建一个 cache.*/
	if (!sigqueue_cachep)
		panic("signals_init(): cannot create sigqueue SLAB cache");
}



/* Given the mask, find the first available signal that should be serviced. 
	给定掩码，找到应该服务的第一个可用信号。*/
static int
next_signal(struct task_struct *tsk, sigset_t *mask)
{
	unsigned long i, *s, *m, x;
	int sig = 0;
	
	s = tsk->pending.signal.sig;//任务->阻隔->信号
	m = mask->sig;//m =掩码信号;
	switch (_NSIG_WORDS) {
	default:
		for (i = 0; i < _NSIG_WORDS; ++i, ++s, ++m)
			if ((x = *s &~ *m) != 0) {
				sig = ffz(~x) + i*_NSIG_BPW + 1;
				/*ffz
                  在字中查找第一个0
                  unsigned long ffz (unsigned long word);
                  word为要搜索的字。*/
				break;
			}
		break;

	case 2: if ((x = s[0] &~ m[0]) != 0)
			sig = 1;
		else if ((x = s[1] &~ m[1]) != 0)
			sig = _NSIG_BPW + 1;
		else
			break;
		sig += ffz(~x);
		/*ffz:在字中查找第一个0 */
		break;

	case 1: if ((x = *s &~ *m) != 0)
			sig = ffz(~x) + 1;/*ffz:在字中查找第一个0 */
		break;
	}
	
	return sig;
}

static void flush_sigqueue(struct sigpending *queue)//刷新信号队列
{
	struct sigqueue *q, *n; //结构体：信号队列

	sigemptyset(&queue->signal);//设置空信号
	q = queue->head; // q =队列- >头;
	queue->head = NULL; // 队列- >头=空;
	queue->tail = &queue->head; //队列- >尾=队列- >头;

	while (q) { 
		n = q->next; // n指向头结点的下一个
		kmem_cache_free(sigqueue_cachep, q); // 释放cache
		atomic_dec(&nr_queued_signals); // 原子性减少(atomic decrease)
		q = n; //q指向n
	}
}

/*
 * Flush all pending signals for a task.
 */
 /*
 刷新任务的所有等待信号。
 */
 
void
flush_signals(struct task_struct *t)
{
	t->sigpending = 0;
	flush_sigqueue(&t->pending);//刷新信号队列
	//pending待定
}

void exit_sighand(struct task_struct *tsk)
//task:任务
{
	struct signal_struct * sig = tsk->sig;

	spin_lock_irq(&tsk->sigmask_lock);
	//禁止本地中断获取指定的锁
	if (sig) {
		tsk->sig = NULL;
		if (atomic_dec_and_test(&sig->count))
			kmem_cache_free(sigact_cachep, sig);
		    /*这个函数将被释放的对象返还给先前的slab，
			其实就是将cachep中的对象objp标记为空闲而已。*/
	}
	tsk->sigpending = 0;//任务->待定信号=0
	flush_sigqueue(&tsk->pending);//刷新信号队列
	spin_unlock_irq(&tsk->sigmask_lock);
	//释放指定的锁，并激活本地中断
}

/*
 * Flush all handlers for a task.
 */
 /*
   刷新任务的所有处理程序。
 */
/*handler:处理程序*/
void
flush_signal_handlers(struct task_struct *t)
{
	int i;
	struct k_sigaction *ka = &t->sig->action[0];
	//sigaction:信号行为/信号动作
	for (i = _NSIG ; i != 0 ; i--) {
		/*SIG_DFL,SIG_IGN 分别表示无返回值的函数指针，
		指针值分别是0和1
		SIG_DFL：默认信号处理程序
        SIG_IGN：忽略信号的处理程序
		*/
		if (ka->sa.sa_handler != SIG_IGN)
			ka->sa.sa_handler = SIG_DFL;
		//如果不能忽略，那就赋予默认信号
		ka->sa.sa_flags = 0;
		sigemptyset(&ka->sa.sa_mask);
		//sigemptyset用来将参数set信号集初始化并清空。
		ka++;
	}
}

/* Notify the system that a driver wants to block all signals for this
 * process, and wants to be notified if any signals at all were to be
 * sent/acted upon.  If the notifier routine returns non-zero, then the
 * signal will be acted upon after all.  If the notifier routine returns 0,
 * then then signal will be blocked.  Only one block per process is
 * allowed.  priv is a pointer to private data that the notifier routine
 * can use to determine if the signal should be blocked or not.  */
/*通知系统，驱动程序要阻止所有的信号
进程，并希望得到通知，
是否有任何信号将被发出或将被执行。
如果通知程序返回非零值，那么
信号终究会采取行动。如果通知程序返回零，
然后信号将被阻塞。每个进程只有一个块被允许。
priv是一个指向私有数据的指针，通知程序
可以用来判断信号是否应该被阻塞。
*/
 
void
block_all_signals(int (*notifier)(void *priv), void *priv, sigset_t *mask)
{
	unsigned long flags;

	spin_lock_irqsave(&current->sigmask_lock, flags);
	//保存本地中断的状态,禁止本地中断,并获取指定的锁
	/*spin_lock_irqsave在锁返回时，之前开的中断，之后也是开的；
	之前关，之后也是关。
	但是spin_lock_irq则不管之前的开还是关，返回时都是开的*/
	current->notifier_mask = mask;
	current->notifier_data = priv;
	current->notifier = notifier;
	spin_unlock_irqrestore(&current->sigmask_lock, flags);
	//释放指定的锁，并让本地中断恢复到以前状态
}

/* Notify the system that blocking has ended. */
/* 通知系统阻塞已经结束。 */

void
unblock_all_signals(void)
{
	unsigned long flags;

	spin_lock_irqsave(&current->sigmask_lock, flags);
	//保存本地中断的状态,禁止本地中断,并获取指定的锁
	current->notifier = NULL;
	current->notifier_data = NULL;
	recalc_sigpending(current);
	//重新计算_送往进程过程中被阻塞挂起的信号集合
	spin_unlock_irqrestore(&current->sigmask_lock, flags);
	//释放指定的锁，并让本地中断恢复到以前状态
}

static int collect_signal(int sig, struct sigpending *list, siginfo_t *info)
{
	if (sigismember(&list->signal, sig)) {
		/* Collect the siginfo appropriate to this signal.  */  
		/* 收集与此信号相关的siginfo。*/
		struct sigqueue *q, **pp;
		pp = &list->head;//pp指向第一个信号成员的next指针
		while ((q = *pp) != NULL) {
			if (q->info.si_signo == sig)
				goto found_it;
			pp = &q->next;
		}

		/* Ok, it wasn't in the queue.  We must have
		   been out of queue space.  So zero out the
		   info.  */
		
        /* 好吧，它不在队列里。我们必须
		   已经腾出队列空间。
		   所以归零信息。*/

		sigdelset(&list->signal, sig);
		//sigdelset:将参数signum代表的信号从参数set信号集里删除
		info->si_signo = sig;            
		info->si_errno = 0;      
		info->si_code = 0;
		info->si_pid = 0;
		info->si_uid = 0;    
		return 1;

found_it:    // 将找到信号成员从信号队列中删除
		if ((*pp = q->next) == NULL)
			list->tail = pp;

		/* Copy the sigqueue information and free the queue entry */
		/* 复制sigqueue信息并释放队列条目 */
		copy_siginfo(info, &q->info);
		/*一个新的kmem_cache是通过kmem_cache_create()函数来创建的*/
		kmem_cache_free(sigqueue_cachep,q);
		atomic_dec(&nr_queued_signals);

		/* Non-RT signals can exist multiple times.. */
		/* 非RT信号可以存在多次。 */ 
		if (sig >= SIGRTMIN) {
			while ((q = *pp) != NULL) {
				if (q->info.si_signo == sig)
					goto found_another;
				pp = &q->next;
			}
		}

		sigdelset(&list->signal, sig);
		/*sigdelset是一种函数，	功能是用来将参数signum代表的信号从参数set信号集里删除。
		函数执行成功则返回0，
		如果有错误则返回-1。*/
found_another:
		return 1;
	}
	return 0;
}

/*
 * Dequeue a signal and return the element to the caller, which is 
 * expected to free it.
 *
 * All callers must be holding current->sigmask_lock.
 */
 
/*
* Dequeue一个信号并将元素返回给调用者，即
*期望免费。
*
*所有调用者必须持有当前- > sigmask_lock。
*/

int dequeue_signal(sigset_t *mask, siginfo_t *info)
{
	int sig = 0;

#if DEBUG_SIG
printk("SIG dequeue (%s:%d): %d ", current->comm, current->pid,
	signal_pending(current));
#endif //从当前进程的信号集中找出第一个有效的信号数

	sig = next_signal(current, mask);
	if (sig) {
		//在当前进程的信号队列中提取sig信号的info结构
		if (current->notifier) {
			if (sigismember(current->notifier_mask, sig)) {
				if (!(current->notifier)(current->notifier_data)) {
					/* 在提取信号之前调用进程的notifier()函数,
					如果它返回0,
                    就终止信号处理*/
					current->sigpending = 0;	/*sigpending函数返回在送往进程的时候被阻塞挂起的信号集合。	这个信号集合通过参数set返回。
					在linux中其英文释义：
					sigpending()
					returns the set of signals
					that are pending for delivery to the calling thread 
					(i.e., the signals which have been raised while blocked). The mask of pending signals is returned in set.*/
					return 0;
				}
			}
		}

		if (!collect_signal(sig, &current->pending, info))
			sig = 0;
				
		/* XXX: Once POSIX.1b timers are in, if si_code == SI_TIMER,
		   we need to xchg out the timer overrun values.  */
		
        /* XXX:一旦POSIX。如果si_code == SI_TIMER，则有1b计时器。
           我们需要把计时器的超值值xchg出来。*/

	}
	recalc_sigpending(current);
	//重新计算_送往进程过程中被阻塞挂起的信号集合

//刷新sigpeding标志 recalc_sigpending(current);
#if DEBUG_SIG
printk(" %d -> %d\n", signal_pending(current), sig);
#endif

	return sig;
}

static int rm_from_queue(int sig, struct sigpending *s)
//过一个 while 循环遍历整个待处理信号队列，从而找到相应信号并将其删除
{
	struct sigqueue *q, **pp;

	if (!sigismember(&s->signal, sig))
		return 0;/* 首先判断待删除信号是否为信号队列的成员，如果不是则返回0 */

	sigdelset(&s->signal, sig); 
	/*sigdelset是一种函数，	功能是用来将参数signum代表的信号从参数set信号集里删除。
	函数执行成功则返回0，
	如果有错误则返回-1。*/

	pp = &s->head;/* 清除相应信号标志位 */

	while ((q = *pp) != NULL) {/* 循环遍历信号队列，查找相应消息 */
		if (q->info.si_signo == sig) {/* 找到了相应的信号 */
			if ((*pp = q->next) == NULL)/* 首先将其从等待队列中清除 */
				s->tail = pp;
			kmem_cache_free(sigqueue_cachep,q);/* 释放相应资源 */
			atomic_dec(&nr_queued_signals);
			continue;
		}
		pp = &q->next;
	}
	return 1;
}

/*
 * Remove signal sig from t->pending.
 * Returns 1 if sig was found.
 *
 * All callers must be holding t->sigmask_lock.
 */
 
/*
*将信号sig从t - >挂起。
*如果发现sig，返回1。
*
*所有呼叫者必须持有t -> sigmask_lock。
*/

static int rm_sig_from_queue(int sig, struct task_struct *t)
/*数通过调用rm_from_queue()函数
将一个指定的信号从等待处理的信号队列中删除，
即相当于从等待处理的信号队列中取出一个信号
*/
{
	return rm_from_queue(sig, &t->pending);
	//过一个 while 循环遍历整个待处理信号队列，从而找到相应信号并将其删除 
}

/*
 * Bad permissions for sending the signal
 */
/*
*发送信号的权限错误
*/

int bad_signal(int sig, struct siginfo *info, struct task_struct *t)
{
	return (!info || ((unsigned long)info != 1 && SI_FROMUSER(info)))
	    && ((sig != SIGCONT) || (current->session != t->session))
	    && (current->euid ^ t->suid) && (current->euid ^ t->uid)
	    && (current->uid ^ t->suid) && (current->uid ^ t->uid)
	    && !capable(CAP_KILL); //获取暂时性特权
}
//Current为当前进程task_struct结构，T为目标进程task_struct结构

/*
 * Signal type:
 *    < 0 : global action (kill - spread to all non-blocked threads)
 *    = 0 : ignored
 *    > 0 : wake up.
 */
/*
*信号类型:
* < 0:全局操作(kill -扩展到所有非阻塞线程)
* = 0:忽略
* > 0:醒醒。
*/
static int signal_type(int sig, struct signal_struct *signals)
{
	unsigned long handler;

	if (!signals)//没有信号
		return 0;
	
	handler = (unsigned long) signals->action[sig-1].sa.sa_handler;
	if (handler > 1)
		return 1;

	/* "Ignore" handler.. Illogical, but that has an implicit handler for SIGCHLD */
	/* “忽略”处理程序。不合逻辑，但它有一个隐式处理程序，用于SIGCHLD */
	if (handler == 1)
		return sig == SIGCHLD;

	/* Default handler. Normally lethal, but.. */
	/* 默认处理程序。通常致命,但是.. */
	switch (sig) {//信号动作

	/* Ignored */
	/* 忽视 */
	case SIGCONT:
    /*忽略信号 继续执行一个停止的进程 */
	/*当被stop的进程恢复运行的时候，自动发送*/
	case SIGWINCH:
	/*忽略信号 窗口大小发生变化*/
	/*当Terminal的窗口大小改变的时候，发送给Foreground Group的所有进程*/
	case SIGCHLD:
	/* 忽略信号 当子进程停止或退出时通知父进程*/
	/*进程Terminate或Stop的时候，SIGCHLD会发送给它的父进程。缺省情况下该Signal会被忽略*/
	case SIGURG:
	/*忽略信号 I/O紧急信号*/
	/*当out-of-band data接收的时候可能发送*/
		return 0;

	/* Implicit behaviour */
	/* 隐式行为  */
	case SIGTSTP: 
	/* 停止进程 终端来的停止信号*/
	/*Suspend Key，一般是Ctrl+Z。发送给所有Foreground Group的进程*/
	case SIGTTIN: 
	/* 停止进程 后台进程读终端*/
	/*当Background Group的进程尝试读取Terminal的时候发送*/
	case SIGTTOU:
	/* 停止进程 后台进程写终端*/
	/*当Background Group的进程尝试写Terminal的时候发送*/
		return 1;

	/* Implicit actions (kill or do special stuff) */
	/* 隐式操作(杀死或做特殊的事情) */
	default:
		return -1;
	}
}
		
/*
 * Determine whether a signal should be posted or not.
 *
 * Signals with SIG_IGN can be ignored, except for the
 * special case of a SIGCHLD. 
 *
 * Some signals with SIG_DFL default to a non-action.
 */
/*
*确定是否应该发布一个信号。
*
*可以忽略带有SIG_IGN的信号，除了
*特殊情况。
*
*一些信号与SIG_DFL默认为不动作。
*/
static int ignored_signal(int sig, struct task_struct *t)
//响应为忽略，则不进行投递
{
	/* Don't ignore traced or blocked signals */
	/* 不要忽略跟踪或阻塞的信号 */
	if ((t->ptrace & PT_PTRACED) || sigismember(&t->blocked, sig))
		return 0;

	return signal_type(sig, t->sig) == 0;
}

/*
 * Handle TASK_STOPPED cases etc implicit behaviour
 * of certain magical signals.
 *
 * SIGKILL gets spread out to every thread. 
 */
/*
*处理task_停止用例等隐式行为
*有某种神奇的信号。
*
* SIGKILL扩展到每个线程。
*/
static void handle_stop_signal(int sig, struct task_struct *t)
//目标进程正在task_stopped则将其唤醒，状态改为task_running
/*task_running:TASK_RUNNING:可执行状态（执行状态、执行等待状态）*/
{
	switch (sig) {
	case SIGKILL: case SIGCONT:
		/* Wake up the process if stopped.  */
		/* 如果停止，就唤醒这个线程。*/
		if (t->state == TASK_STOPPED)//状态检测
			wake_up_process(t);//唤醒
		t->exit_code = 0;
		rm_sig_from_queue(SIGSTOP, t);//丢弃消息队列;
		rm_sig_from_queue(SIGTSTP, t);
		/*
        SIGTSTP和SIGSTOP的区别：  SIGTSTP与SIGSTOP都是 
        使进程暂停（都使用SIGCONT让进程重新激活）。
        唯一的区别是SIGSTOP不可以捕获。
        捕捉SIGTSTP后一般处理如下：
        1）处理完额外的事
        2）恢复默认处理
        3）发送SIGTSTP信号给自己。（使进程进入suspend状态。）
        */
		rm_sig_from_queue(SIGTTOU, t);
		rm_sig_from_queue(SIGTTIN, t);
		break;

	case SIGSTOP: case SIGTSTP:
	case SIGTTIN: case SIGTTOU:
		/* If we're stopping again, cancel SIGCONT */
		/* 如果我们再停下来，取消SIGCONT */
		rm_sig_from_queue(SIGCONT, t);
		break;
	}
}


/*
send_signal()函数有四个入参，sig表示要发送的信号，
info表征信号的一些信息，t接收所发送信号的进程描述符，
group表示是发送给描述符t所代表的单个进程还是进程描述符t所处的整个线程组，
send_signal()调用__send_signal()，多了个入参from_ancestor_ns，
没有过多关注。
*/
// 发送信号
//函数send_signal完成了信号投递工作，将发送的信号排队到signals中
static int send_signal(int sig, struct siginfo *info, struct sigpending *signals)
{
	struct sigqueue * q = NULL;//建立消息队列

	/* Real-time signals must be queued if sent by sigqueue, or
	   some other real-time mechanism.  It is implementation
	   defined whether kill() does so.  We attempt to do so, on
	   the principle of least surprise, but since kill is not
	   allowed to fail with EAGAIN when low on memory we just
	   make sure at least one signal gets delivered and don't
	   pass on the info struct.  */
    /*实时信号如果由sigqueue发送，则必须排队
      其他一些实时的机制。它是实现
      定义kill()是否这样做。我们试图这样做
      最不惊讶的原则，但因为杀死不被
      允许在低内存时再次失败
      确保至少有一个信号被传递，而不是
      传递信息结构。*/

	if (atomic_read(&nr_queued_signals) < max_queued_signals) {
		q = kmem_cache_alloc(sigqueue_cachep, GFP_ATOMIC);
	}// 分配信号队列结构, 从sigqueue_cachep中分配(这个一个kmem_cache)

	if (q) {// 将该信号队列挂接到待发送信号链表末尾
		atomic_inc(&nr_queued_signals);
		q->next = NULL;
		*signals->tail = q;//新分配的sigqueue结构链入到sigpengding结构里面的sigqueue 
		signals->tail = &q->next;
		switch ((unsigned long) info) {//按标志位进行选择
			case 0:
				q->info.si_signo = sig;//信号追踪
				q->info.si_errno = 0;
				q->info.si_code = SI_USER;
				q->info.si_pid = current->pid;
				q->info.si_uid = current->uid;
				break;
			case 1:
				q->info.si_signo = sig;//信号值
				q->info.si_errno = 0;
				q->info.si_code = SI_KERNEL;
				/*SI_KERNEL:Generic kernel function 
				通用内核函数
				*/
				q->info.si_pid = 0;
				q->info.si_uid = 0;
				break;
			default:
				copy_siginfo(&q->info, info);
				//q->info来源于info，里面的成员si_signo代表了哪个信号
				break;
		}
	} else if (sig >= SIGRTMIN && info && (unsigned long)info != 1
		   && info->si_code != SI_USER) {
		/*
		 * Queue overflow, abort.  We may abort if the signal was rt
		 * and sent by user using something other than kill().
		 */
		 /*队列溢出，退出。如果信号是实时的，
		 并且被使用非kill的用户发送，就可以退出。
		 */
		return -EAGAIN;
	}

	sigaddset(&signals->signal, sig);
	//sig结构对应位置1
	return 0;
}

/*
 * Tell a process that it has a new active signal..
 *
 * NOTE! we rely on the previous spin_lock to
 * lock interrupts for us! We can only be called with
 * "sigmask_lock" held, and the local interrupt must
 * have been disabled when that got acquired!
 *
 * No need to set need_resched since signal event passing
 * goes through ->blocked
 */
 
 /*
   告诉一个进程它有一个新的主动信号。
  *请注意!我们依赖于前面的spin_lock
  *锁中断我们!我们只能被召唤
  *“sigmask_lock”，本地中断必须
  *被收购后就被禁用了!
   在信号事件通过后，不需要设置必要的resched
  *经过- >了
  */

static inline void signal_wake_up(struct task_struct *t)
//内联函数 信号唤醒
{
	t->sigpending = 1;

#ifdef CONFIG_SMP
	/*
	 * If the task is running on a different CPU 
	 * force a reschedule on the other CPU to make
	 * it notice the new signal quickly.
	 *
	 * The code below is a tad loose and might occasionally
	 * kick the wrong CPU if we catch the process in the
	 * process of changing - but no harm is done by that
	 * other than doing an extra (lightweight) IPI interrupt.
	 */
	 
	 /* 如果任务在不同的CPU上运行
        在另一个CPU上执行重新调度
       *它很快就注意到了新的信号。
       *下面的代码有点松散，可能偶尔会出现
       *如果我们捕捉到进程，就踢错CPU
       *改变的过程——但没有任何伤害
        除了做额外的(轻量级的)IPI中断外。
     */

	spin_lock(&runqueue_lock);
	if (task_has_cpu(t) && t->processor != smp_processor_id())
		smp_send_reschedule(t->processor);
	/*调用smp_send_reschedule(cpu)向cpu发中断
	  以唤醒该cpu。*/
	spin_unlock(&runqueue_lock);//释放指定的锁
#endif /* CONFIG_SMP */

	if (t->state & TASK_INTERRUPTIBLE) {
		wake_up_process(t);//唤醒进程
		return;
	}
}

static int deliver_signal(int sig, struct siginfo *info, struct task_struct *t)
/*递送信号函数*/
{
	int retval = send_signal(sig, info, &t->pending);//投递消息

	if (!retval && !sigismember(&t->blocked, sig))//如果目标进程正在睡眠中，并且没有遮蔽所投递的信号，就要将其唤醒并立即进行调度
		signal_wake_up(t);//唤醒进程

	return retval;
}

int
send_sig_info(int sig, struct siginfo *info, struct task_struct *t)
/*发送信号数据*/
{
	unsigned long flags;
	int ret;


#if DEBUG_SIG
printk("SIG queue (%s:%d): %d ", t->comm, t->pid, sig);
#endif

	ret = -EINVAL;
	if (sig < 0 || sig > _NSIG)
		goto out_nolock;
	/* The somewhat baroque permissions check... */
	/* 有点巴洛克式的权限检查……  */
	ret = -EPERM;
	if (bad_signal(sig, info, t))//信号检测
		goto out_nolock;

	/* The null signal is a permissions and process existance probe.
	   No signal is actually delivered.  Same goes for zombies. */
	   
    /* 空信号是一个权限和过程存在的探针。
       没有发出信号。僵尸也一样。*/

	ret = 0;
	if (!sig || !t->sig)
		goto out_nolock;

	spin_lock_irqsave(&t->sigmask_lock, flags);
	//保存中断的当前状态，并禁止本地中断，然后再去获取指定的锁
	handle_stop_signal(sig, t);//唤醒进程

	/* Optimize away the signal, if it's a signal that can be
	   handled immediately (ie non-blocked and untraced) and
	   that is ignored (either explicitly or by default).  */
	
    /* 如果有一个
	   能够被立即处理(即非阻塞和未跟踪)并且
	   被忽略的(无论是显式的还是默认的)信号，
	   那么，优化这个信号。
	*/

	if (ignored_signal(sig, t))//若相应模式为“忽略”，则不进行投递
		goto out;

	/* Support queueing exactly one non-rt signal, so that we
	   can get more detailed information about the cause of
	   the signal. */
	
    /* 支持对一个非rt信号进行排队，这样我们就可以了
       能得到更详细的原因吗
       这个信号。*/

	if (sig < SIGRTMIN && sigismember(&t->pending.signal, sig)) 
	/*SIGRTMIN为32，对于"老编制"的信号，所谓"投递"本来是很简单的，
    因为那只是将目标进程的"接收信号位图"signal中相应的标志位设置成1，
    也将sigqueue结构挂入队列中，不过只挂入一次。
	对于新编制，可以将sigqueue结构挂入到队列很多次。*/  
		goto out;

	ret = deliver_signal(sig, info, t);
	/*要将sigpengding结构里面的sig结构对应位置1，
	还要将分配一个sigqueue结构
	(里面siginfo_t结构si_signo代表哪个信号)
	链入到sigpengding结构里面的sigqueue*/ 
out:
	spin_unlock_irqrestore(&t->sigmask_lock, flags);
	//释放指定的锁，并让本地中断恢复到以前状态
out_nolock:
#if DEBUG_SIG
printk(" %d -> %d\n", signal_pending(t), ret);
#endif

	return ret;
}

/*
 * Force a signal that the process can't ignore: if necessary
 * we unblock the signal and change any SIG_IGN to SIG_DFL.
 */
 
/*
 强迫一个过程不能忽视的信号:如果有必要的话
 我们解封信号并将任何SIG_IGN更改为SIG_DFL。
*/
 
int
force_sig_info(int sig, struct siginfo *info, struct task_struct *t)
//强制目标接收信号
{
	unsigned long int flags;

	spin_lock_irqsave(&t->sigmask_lock, flags);
	//保存本地中断的状态,禁止本地中断,并获取指定的锁
	if (t->sig == NULL) {
		spin_unlock_irqrestore(&t->sigmask_lock, flags);
		//释放指定的锁，并让本地中断恢复到以前状态
		return -ESRCH;
		/*ESRCH：没有这样的进程*/
	}

	if (t->sig->action[sig-1].sa.sa_handler == SIG_IGN)
		t->sig->action[sig-1].sa.sa_handler = SIG_DFL;//不允许目标进程忽略该信号
	sigdelset(&t->blocked, sig);//将其遮蔽位也强制清除
	recalc_sigpending(t);
	//重新计算_送往进程过程中被阻塞挂起的信号集合
	spin_unlock_irqrestore(&t->sigmask_lock, flags);
	//释放指定的锁，并让本地中断恢复到以前状态

	return send_sig_info(sig, info, t);/*发送信号数据*/
}

/*
 * kill_pg_info() sends a signal to a process group: this is what the tty
 * control characters do (^C, ^Z etc)
 */

/*
  kill_pg_info()向进程组发送一个信号:这就是tty
  控制字符(^,^ Z等)要做的
*/
 
int
kill_pg_info(int sig, struct siginfo *info, pid_t pgrp)
{
	int retval = -EINVAL;
	if (pgrp > 0) {
		struct task_struct *p;

		retval = -ESRCH;/*ESRCH：没有这样的进程*/
		read_lock(&tasklist_lock);
		for_each_task(p) {
			if (p->pgrp == pgrp) {
				int err = send_sig_info(sig, info, p);
				/*发送信号数据*/
				if (retval)
					retval = err;
			}
		}
		read_unlock(&tasklist_lock);
	}
	return retval;
}

/*
 * kill_sl_info() sends a signal to the session leader: this is used
 * to send SIGHUP to the controlling process of a terminal when
 * the connection is lost.
 */

/*
* kill_sl_info()向会话领导发送一个信号:这是使用的
*在一个终端的控制过程中发送叹息
*连接丢失了。
*/
 
int
kill_sl_info(int sig, struct siginfo *info, pid_t sess)
{
	int retval = -EINVAL;
	/*EINVAL无效的参数*/
	if (sess > 0) {
		struct task_struct *p;

		retval = -ESRCH;
		/*ESRCH：没有这样的进程*/
		read_lock(&tasklist_lock);
		for_each_task(p) {
			if (p->leader && p->session == sess) {
				int err = send_sig_info(sig, info, p);/*发送信号数据*/
				if (retval)
					retval = err;
			}
		}
		read_unlock(&tasklist_lock);
	}
	return retval;//ret val 返回值
}

inline int
kill_proc_info(int sig, struct siginfo *info, pid_t pid)
{
	int error;
	struct task_struct *p;

	read_lock(&tasklist_lock);//读锁-1
	p = find_task_by_pid(pid);//根据pid找到对应的task_struct结构
	error = -ESRCH;
	/*ESRCH: No such process*/
	/*ESRCH：没有这样的进程*/
	if (p)
		error = send_sig_info(sig, info, p);//将信号发送给他们
	read_unlock(&tasklist_lock);//解锁
	return error;
}

/*
 * kill_something_info() interprets pid in interesting ways just like kill(2).
 *
 * POSIX specifies that kill(-1,sig) is unspecified, but what we have
 * is probably wrong.  Should make it like BSD or SYSV.
 */
 
/*
 * kill_something_info()以有趣的方式解释pid，就像kill(2)一样。
 * POSIX指定kill(- 1,sig)未指定，但我们有
 * 可能是错误的。应该使它像BSD或SYSV。
*/
 
static int kill_something_info(int sig, struct siginfo *info, int pid)
{
	if (!pid) {//pid为0时，表示发送给当前进程所在进程组中所有的进程
		return kill_pg_info(sig, info, current->pgrp);//表示发送给当前进程所在进程组中所有的进程
	} else if (pid == -1) {// pid为-1时发送给系统中的所有进程
		int retval = 0, count = 0;
		struct task_struct * p;//任务结构体

		read_lock(&tasklist_lock);
		/*read_lock()对锁变量减1，如果结果为负，则说明已被某个write_lock()上锁。
		然后read_lock()对锁变量加1，释 放read_lock状态，接着等待锁变量的值变为1；
		一旦锁变量变为1，read_lock()再次对锁变量减1 ，如果非负则成功，
		否则重复上述过程。 */
		for_each_task(p) {
			if (p->pid > 1 && p != current) {
				int err = send_sig_info(sig, info, p);//-1时则发送给系统中的所有进程
				++count;
				if (err != -EPERM)
					retval = err;
			}
		}
		read_unlock(&tasklist_lock);
		return count ? retval : -ESRCH;/*ESRCH：没有这样的进程*/
	} else if (pid < 0) {//pid < -1时，发送给进程组中所有进程
		return kill_pg_info(sig, info, -pid);
	} else {//发送给pid进程
		return kill_proc_info(sig, info, pid);//发送给具体的进程 
	}
}

/*
 * These are for backward compatibility with the rest of the kernel source.
 */
/*
 *这些是与内核源代码的其他部分向后兼容的。
 */

int
send_sig(int sig, struct task_struct *p, int priv)
{
	return send_sig_info(sig, (void*)(long)(priv != 0), p);
	/*发送信号数据*/
}

void
force_sig(int sig, struct task_struct *p)
{
	force_sig_info(sig, (void*)1L, p);
}

int
kill_pg(pid_t pgrp, int sig, int priv)
{
	return kill_pg_info(sig, (void *)(long)(priv != 0), pgrp);
}

int
kill_sl(pid_t sess, int sig, int priv)
{
	return kill_sl_info(sig, (void *)(long)(priv != 0), sess);
	/*与发送信号相关的函数 kill_sl_info*/
}

int
kill_proc(pid_t pid, int sig, int priv)
{
	return kill_proc_info(sig, (void *)(long)(priv != 0), pid);
}

/*
 * Joy. Or not. Pthread wants us to wake up every thread
 * in our parent group.
 */
 
/*
 *无论如何，Pthread希望我们唤醒每一个线程
 *在我们的父母群体中。
 */

static void wake_up_parent(struct task_struct *parent)
{
	struct task_struct *tsk = parent;

	do {
		wake_up_interruptible(&tsk->wait_chldexit);
		//唤醒可中断线程
		tsk = next_thread(tsk);
		//下一个线程
	} while (tsk != parent);
}

/*
 * Let a parent know about a status change of a child.
 */
 
/*
 *让父母了解孩子的地位变化。
 */

void do_notify_parent(struct task_struct *tsk, int sig)
{
	struct siginfo info;
	int why, status;

	info.si_signo = sig;
	info.si_errno = 0;
	info.si_pid = tsk->pid;
	info.si_uid = tsk->uid;

	/* FIXME: find out whether or not this is supposed to be c*time. */
	/* FIXME:找出是否应该是c * time。*/
	info.si_utime = tsk->times.tms_utime;
	info.si_stime = tsk->times.tms_stime;

	status = tsk->exit_code & 0x7f;
	why = SI_KERNEL;	/* shouldn't happen */  /* 不应该发生 */
	switch (tsk->state) {
	case TASK_STOPPED:
		/* FIXME -- can we deduce CLD_TRAPPED or CLD_CONTINUED? */
		/* FIXME -我们能推断cld_陷或cld_继续吗?*/
		if (tsk->ptrace & PT_PTRACED)
			why = CLD_TRAPPED;
		    /*陷入 CLD_TRAPPED*/
		else
			why = CLD_STOPPED;
		    /*信号导致子进程停止执行*/
		break;

	default:
		if (tsk->exit_code & 0x80)
			why = CLD_DUMPED;
		else if (tsk->exit_code & 0x7f)
			why = CLD_KILLED;/*子进程被信号杀死*/
		else {
			why = CLD_EXITED;/*子进程调用_exit退出*/
			status = tsk->exit_code >> 8;
		}
		break;
	}
	info.si_code = why;
	info.si_status = status;

	send_sig_info(sig, &info, tsk->p_pptr);
	/*发送信号数据*/
	wake_up_parent(tsk->p_pptr);
}


/*
 * We need the tasklist lock because it's the only
 * thing that protects out "parent" pointer.
 *
 * exit.c calls "do_notify_parent()" directly, because
 * it already has the tasklist lock.
 */
 
/*
   我们需要任务列表锁，因为它是唯一的
  *保护“父”指针的东西。
  *出口。c调用“do_notify_parent()“直接,因为
  *它已经有任务列表锁了。
*/

void
notify_parent(struct task_struct *tsk, int sig)
{
	read_lock(&tasklist_lock);
	do_notify_parent(tsk, sig);
	read_unlock(&tasklist_lock);
}

EXPORT_SYMBOL(dequeue_signal);
EXPORT_SYMBOL(flush_signals);
EXPORT_SYMBOL(force_sig);
EXPORT_SYMBOL(force_sig_info);
EXPORT_SYMBOL(kill_pg);
EXPORT_SYMBOL(kill_pg_info);
EXPORT_SYMBOL(kill_proc);
EXPORT_SYMBOL(kill_proc_info);
EXPORT_SYMBOL(kill_sl);
EXPORT_SYMBOL(kill_sl_info);
EXPORT_SYMBOL(notify_parent);
EXPORT_SYMBOL(recalc_sigpending);
EXPORT_SYMBOL(send_sig);
EXPORT_SYMBOL(send_sig_info);/*发送信号数据*/
EXPORT_SYMBOL(block_all_signals);
EXPORT_SYMBOL(unblock_all_signals);
/*  http://blog.csdn.net/cailiwei712/article/details/7998525  */
/*把内核函数的符号导出，也可以理解成将函数名作为符号导出；
符号的意思就是函数的入口地址，或者说是把这些符号和对应的地址保存起来的，
在内核运行的过程中，可以找到这些符号对应的地址的。*/

/*
 * System call entry points.
 */
/*
*系统调用入口点。
*/
 
/*
 * We don't need to get the kernel lock - this is all local to this
 * particular thread.. (and that's good, because this is _heavily_
 * used by various programs)
 */

/*
我们不需要得到内核锁——这都是本地的
*特定线程. .(这很好，因为这很重要
*各项目使用*
*/
 
asmlinkage long
sys_rt_sigprocmask(int how, sigset_t *set, sigset_t *oset, size_t sigsetsize)
{
	int error = -EINVAL;
	sigset_t old_set, new_set;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	/* XXX:不要排除处理不同大小的sigset_t。*/
	if (sigsetsize != sizeof(sigset_t))
		goto out;

	if (set) {
		error = -EFAULT;
		if (copy_from_user(&new_set, set, sizeof(*set)))
			//用户空间到内核空间的复制
			goto out;
		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));//见do_sigaction()

		spin_lock_irq(&current->sigmask_lock);//禁止本地中断获取指定的锁
		old_set = current->blocked;

		error = 0;
		switch (how) {
		default:
			error = -EINVAL;
			break;
		case SIG_BLOCK:
			sigorsets(&new_set, &old_set, &new_set);	
			/*调用sigorsets()将当前进程的信号信息
			old_set,new_set进行或操作
			（也就是将两个地方的信号掩码合并起来）
			存储在变量new_set中
			*/
			break;
		case SIG_UNBLOCK:
			signandsets(&new_set, &old_set, &new_set);
			/*调用sigandsets()将当前进程的信号信息
			old_set,new_set进行或操作
			（也就是将两个地方的信号掩码合并起来）
			存储在变量new_set中
			*/
			break;
		case SIG_SETMASK:
			break;
		}

		current->blocked = new_set;
		recalc_sigpending(current);
		//重新计算_送往进程过程中被阻塞挂起的信号集合
		spin_unlock_irq(&current->sigmask_lock);
		//释放指定的锁，并激活本地中断
		if (error)
			goto out;
		if (oset)
			goto set_old;
	} else if (oset) {
		spin_lock_irq(&current->sigmask_lock);//禁止本地中断获取指定的锁
		old_set = current->blocked;
		spin_unlock_irq(&current->sigmask_lock);
        //释放指定的锁，并激活本地中断
		
	set_old:
		error = -EFAULT;
		if (copy_to_user(oset, &old_set, sizeof(*oset)))
			//内核空间到用户空间的复制
			goto out;
	}
	error = 0;
out:
	return error;
}

long do_sigpending(void *set, unsigned long sigsetsize)
{
	long error = -EINVAL;
	sigset_t pending;

	if (sigsetsize > sizeof(sigset_t))
		goto out;

	spin_lock_irq(&current->sigmask_lock);//加锁
	
	/*Outside the lock because only this thread touches it.*/
	                                      
	sigandsets(&pending, &current->blocked, &current->pending.signal);//最后将待决信号和阻塞的信号取交集，因为待决信号并不一定是阻塞的，有可能是还没来得及投递的，所以这里要取交集
	spin_unlock_irq(&current->sigmask_lock);
	//释放指定的锁，并激活本地中断

	
	
	error = -EFAULT;
	if (!copy_to_user(set, &pending, sigsetsize))
		//内核空间到用户空间的复制
		error = 0;
out:
	return error;
}	

asmlinkage long
sys_rt_sigpending(sigset_t *set, size_t sigsetsize)
{
	return do_sigpending(set, sigsetsize);
}

asmlinkage long
sys_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
		    const struct timespec *uts, size_t sigsetsize)
{
	int ret, sig;
	sigset_t these;
	struct timespec ts;
	siginfo_t info;
	long timeout = 0;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	/* XXX:不要排除处理不同大小的sigset_t。*/
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&these, uthese, sizeof(these)))
		//用户空间到内核空间的复制
		return -EFAULT;
		
	/*
	 * Invert the set of allowed signals to get those we
	 * want to block.
	 */
	 /*
      *将允许的信号的集合转化为得到我们的信号
      *想要阻止。
      */

	sigdelsetmask(&these, sigmask(SIGKILL)|sigmask(SIGSTOP));
	signotset(&these);

	if (uts) {
		if (copy_from_user(&ts, uts, sizeof(ts)))
			//用户空间到内核空间的复制
			return -EFAULT;
		if (ts.tv_nsec >= 1000000000L || ts.tv_nsec < 0
		    || ts.tv_sec < 0)
			return -EINVAL;
	}

	spin_lock_irq(&current->sigmask_lock);//禁止本地中断获取指定的锁
	sig = dequeue_signal(&these, &info);
	if (!sig) {
		timeout = MAX_SCHEDULE_TIMEOUT;
		if (uts)
			timeout = (timespec_to_jiffies(&ts)
				   + (ts.tv_sec || ts.tv_nsec));

		if (timeout) {
			/* None ready -- temporarily unblock those we're
			 * interested while we are sleeping in so that we'll
			 * be awakened when they arrive.  */
			 
            /* 没有准备好——暂时取消我们的封锁
               在我们睡觉的时候对我们感兴趣，所以我们会
              *当他们到达时，要被唤醒。*/

			sigset_t oldblocked = current->blocked;
			sigandsets(&current->blocked, &current->blocked, &these);
			recalc_sigpending(current);//重新计算_送往进程过程中被阻塞挂起的信号集合
			spin_unlock_irq(&current->sigmask_lock);
			//释放指定的锁，并激活本地中断

			current->state = TASK_INTERRUPTIBLE;
			/*TASK_INTERRUPTIBLE:等待状态。等待状态可被信号解除*/
			timeout = schedule_timeout(timeout);

			spin_lock_irq(&current->sigmask_lock);//禁止本地中断获取指定的锁
			sig = dequeue_signal(&these, &info);
			current->blocked = oldblocked;
			recalc_sigpending(current);
			//重新计算_送往进程过程中被阻塞挂起的信号集合
		}
	}
	spin_unlock_irq(&current->sigmask_lock);
	//释放指定的锁，并激活本地中断

	if (sig) {
		ret = sig;
		if (uinfo) {
			if (copy_siginfo_to_user(uinfo, &info))
				ret = -EFAULT;
			    /* EFAULT:Bad address 
				错误的地址
				*/
		}
	} else {
		ret = -EAGAIN;
		if (timeout)
			ret = -EINTR;
		    /*EINTR:Interrupted system call*/
			/*中断系统调用*/
	}

	return ret;
}

asmlinkage long
sys_kill(int pid, int sig)
{
	struct siginfo info;

	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = current->pid;
	info.si_uid = current->uid;

	return kill_something_info(sig, &info, pid);
}
//gnofo结构，并调用kill_something_info结构

asmlinkage long
sys_rt_sigqueueinfo(int pid, int sig, siginfo_t *uinfo)
{
	siginfo_t info;

	if (copy_from_user(&info, uinfo, sizeof(siginfo_t)))//把siginfo数据结构从用户空间拷贝到内核中
		return -EFAULT;

	/* Not even root can pretend to send signals from the kernel.
	   Nor can they impersonate a kill(), which adds source info.  */
	/* 甚至连根都不能假装从内核发送信号。
       他们也不能模拟一个会添加源信息的kill()函数。*/

	if (info.si_code >= 0)
		return -EPERM;
	info.si_signo = sig;

	/* POSIX.1b doesn't mention process groups.  */
	/* POSIX。1b没有提到进程组。*/
	return kill_proc_info(sig, &info, pid);//最后还是调用kill_proc_info 
}

int
do_sigaction(int sig, const struct k_sigaction *act, struct k_sigaction *oact)
{
	struct k_sigaction *k;

	if (sig < 1 || sig > _NSIG ||
	    (act && (sig == SIGKILL || sig == SIGSTOP)))//系统对信号SIGKILL和SIGSTOP的响应是不允许改变的
		return -EINVAL;/* 判断是否为有效信号 */

	k = &current->sig->action[sig-1];
    /*获取当前进程中信号对应的响应函数*/
	spin_lock(&current->sig->siglock);
    /* 为当前进程设置锁结构 */
	if (oact)
		*oact = *k;//返回原来的k_sigaction结构
    /* 备份旧的信号动作 */
	if (act) {
		*k = *act;/* 执行信号 */
		//现在的k_sigaction结构赋值给current->sig->action[sig-1]
		
		sigdelsetmask(&k->sa.sa_mask, sigmask(SIGKILL) | sigmask(SIGSTOP));/* 删除信号标志 */
		//SIGKILL和SIGSTOP相应屏蔽位也在每次设置"信号向量"时自动清0
		
		/*
		 * POSIX 3.3.1.3:
		 *  "Setting a signal action to SIG_IGN for a signal that is
		 *   pending shall cause the pending signal to be discarded,
		 *   whether or not it is blocked."
		 *
		 *  "Setting a signal action to SIG_DFL for a signal that is
		 *   pending and whose default action is to ignore the signal
		 *   (for example, SIGCHLD), shall cause the pending signal to
		 *   be discarded, whether or not it is blocked"
		 *
		 * Note the silly behaviour of SIGCHLD: SIG_IGN means that the
		 * signal isn't actually ignored, but does automatic child
		 * reaping, while SIG_DFL is explicitly said by POSIX to force
		 * the signal to be ignored.
		 */
         
         /*
          * POSIX 3.3.1.3:
          *“设置一个信号动作以发出信号。
          *未决的，将导致等待的信号被丢弃，
           不管它是否被屏蔽。
          *
          *“将信号动作设置为SIG_DFL，以获得信号。
          *挂起，其默认动作是忽略信号
          *(例如，SIGCHLD)将导致待处理的信号
          *被丢弃，不管是否被封锁

          *注意SIGCHLD的愚蠢行为:SIG_IGN表示
          *信号实际上并没有被忽略，而是自动生成的
          * re萍，而SIG_DFL被POSIX明确表示为force
          *被忽略的信号。
          */

		if (k->sa.sa_handler == SIG_IGN
		    || (k->sa.sa_handler == SIG_DFL
			&& (sig == SIGCONT ||
			    sig == SIGCHLD ||
			    sig == SIGWINCH))) {
		    //新设置的向量为SIG_IGN时，或者为SIG_DFL而涉及的信号为SIGCONT、SIGCHLD和SIGWINCH之一时，如果已经有一个或几个这样的信号在等待处理，那么将这些已到达的信号丢弃
			spin_lock_irq(&current->sigmask_lock);
			//禁止本地中断获取指定的锁
			/* 处理忽略的或默认的信号 */
			if (rm_sig_from_queue(sig, current))//丢弃已经到达的信号
				recalc_sigpending(current);//重新计算_送往进程过程中被阻塞挂起的信号集合
			spin_unlock_irq(&current->sigmask_lock);
			//释放指定的锁，并激活本地中断
			/* 从信号队列中获取（删除）信号 */
		}
	}

	spin_unlock(&current->sig->siglock);//释放指定的锁
	return 0;
}

int 
do_sigaltstack (const stack_t *uss, stack_t *uoss, unsigned long sp)
{
	stack_t oss;
	int error;

	if (uoss) {
		oss.ss_sp = (void *) current->sas_ss_sp;
		oss.ss_size = current->sas_ss_size;
		oss.ss_flags = sas_ss_flags(sp);
	}

	if (uss) {
		void *ss_sp;
		size_t ss_size;
		int ss_flags;

		error = -EFAULT;
		if (verify_area(VERIFY_READ, uss, sizeof(*uss))
		    || __get_user(ss_sp, &uss->ss_sp)
		    || __get_user(ss_flags, &uss->ss_flags)
		    || __get_user(ss_size, &uss->ss_size))
			goto out;

		error = -EPERM;
		if (on_sig_stack (sp))
			goto out;

		error = -EINVAL;
		/*
		 *
		 * Note - this code used to test ss_flags incorrectly
		 *  	  old code may have been written using ss_flags==0
		 *	  to mean ss_flags==SS_ONSTACK (as this was the only
		 *	  way that worked) - this fix preserves that older
		 *	  mechanism
		 */
		 /*
          *注意—该代码用于测试ss_flags错误
          *旧代码可能是使用ss_flags == 0编写的
          *表示ss_flags == SS_ONSTACK(因为这是唯一的)
          *工作的方式)-这个修复保留了那个旧的
          *机制
          */

		if (ss_flags != SS_DISABLE && ss_flags != SS_ONSTACK && ss_flags != 0)
			goto out;

		if (ss_flags == SS_DISABLE) {
			ss_size = 0;
			ss_sp = NULL;
		} else {
			error = -ENOMEM;
			if (ss_size < MINSIGSTKSZ)
				goto out;
		}

		current->sas_ss_sp = (unsigned long) ss_sp;
		current->sas_ss_size = ss_size;
	}

	if (uoss) {
		error = -EFAULT;
		if (copy_to_user(uoss, &oss, sizeof(oss)))
			//内核空间到用户空间的复制
			goto out;
	}

	error = 0;
out:
	return error;
}

asmlinkage long
sys_sigpending(old_sigset_t *set)
{
	return do_sigpending(set, sizeof(*set));
}

#if !defined(__alpha__)
/* Alpha has its own versions with special arguments.  */
/* Alpha有它自己的带有特殊参数的版本。*/
asmlinkage long
sys_sigprocmask(int how, old_sigset_t *set, old_sigset_t *oset)
{
	int error;
	old_sigset_t old_set, new_set;

	if (set) {
		error = -EFAULT;
		if (copy_from_user(&new_set, set, sizeof(*set)))//用户空间到内核空间的复制
			goto out;
		new_set &= ~(sigmask(SIGKILL)|sigmask(SIGSTOP));

		spin_lock_irq(&current->sigmask_lock);//禁止本地中断获取指定的锁
		old_set = current->blocked.sig[0];

		error = 0;
		switch (how) {
		default:
			error = -EINVAL;
			break;
		case SIG_BLOCK:
			sigaddsetmask(&current->blocked, new_set);
			break;
		case SIG_UNBLOCK:
			sigdelsetmask(&current->blocked, new_set);
			break;
		case SIG_SETMASK:
			current->blocked.sig[0] = new_set;
			break;
		}

		recalc_sigpending(current);
		//重新计算_送往进程过程中被阻塞挂起的信号集合
		spin_unlock_irq(&current->sigmask_lock);
		//释放指定的锁，并激活本地中断
		if (error)
			goto out;
		if (oset)
			goto set_old;
	} else if (oset) {
		old_set = current->blocked.sig[0];
	set_old:
		error = -EFAULT;
		if (copy_to_user(oset, &old_set, sizeof(*oset)))
			//内核空间到用户空间的复制
			goto out;
	}
	error = 0;
out:
	return error;
}

#ifndef __sparc__
asmlinkage long
sys_rt_sigaction(int sig, const struct sigaction *act, struct sigaction *oact,
		 size_t sigsetsize)
{
	struct k_sigaction new_sa, old_sa;
	int ret = -EINVAL;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	/* XXX:不要排除处理不同大小的sigset_t。*/
	if (sigsetsize != sizeof(sigset_t))
		goto out;

	if (act) {
		if (copy_from_user(&new_sa.sa, act, sizeof(new_sa.sa)))
			//用户空间到内核空间的复制
			return -EFAULT;
	}

	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);
	//陷入内核

	if (!ret && oact) {
		if (copy_to_user(oact, &old_sa.sa, sizeof(old_sa.sa)))
		    //内核空间到用户空间的复制
			return -EFAULT;
	}
out:
	return ret;
}
#endif /* __sparc__ */
#endif

#if !defined(__alpha__) && !defined(__ia64__)
/*
 * For backwards compatibility.  Functionality superseded by sigprocmask.
 */
/*
*向后兼容性。功能sigprocmask取代。
*/
asmlinkage long
sys_sgetmask(void)
{
	/* SMP safe */     /* SMP安全 */ 
	return current->blocked.sig[0];
}

asmlinkage long
sys_ssetmask(int newmask)
{
	int old;

	spin_lock_irq(&current->sigmask_lock);//禁止本地中断获取指定的锁
	old = current->blocked.sig[0];

	siginitset(&current->blocked, newmask & ~(sigmask(SIGKILL)|
						  sigmask(SIGSTOP)));
	/*siginitset(set,mask)
    用mask设置set的1-32个信号,并把set的33-63个信号清空.
    */
	recalc_sigpending(current);
	//重新计算_送往进程过程中被阻塞挂起的信号集合
	/*recalc_sigpending_tsk (t) and recalc_sigpending ( )
      第一个函数检查 t->pending->signal 或者
 	  t->signal->shared_pending->signal 上是否有悬挂的非阻塞信号. 
      若有设置 t->thread_info->flags 为 TIF_SIGPENDING.
      recalc_sigpending( ) 等价于 recalc_sigpending_tsk(current).
    */
	spin_unlock_irq(&current->sigmask_lock);
    //释放指定的锁，并激活本地中断
	return old;
}
#endif /* !defined(__alpha__) */       /* !定义alpha */ 

#if !defined(__alpha__) && !defined(__ia64__) && !defined(__mips__)
/*
 * For backwards compatibility.  Functionality superseded by sigaction.
 */
/*
*向后兼容性。个sigaction取代的功能。
*/
asmlinkage unsigned long
sys_signal(int sig, __sighandler_t handler)
{
	struct k_sigaction new_sa, old_sa;
	int ret;

	new_sa.sa.sa_handler = handler;
	/* 设置信号动作的行为（处理函数）和标志 */
	new_sa.sa.sa_flags = SA_ONESHOT | SA_NOMASK;
	//SA_ONESHOT :表示信号处理函数一旦执行一次 ，信号就恢复为SIG_DFL           
	//SA_NOMASK 表示信号处理程序运行过程中不屏蔽同一个信号

	ret = do_sigaction(sig, &new_sa, &old_sa);
	/* 执行do_sigaction()，陷入内核 */

	return ret ? ret : (unsigned long)old_sa.sa.sa_handler;
}
#endif /* !alpha && !__ia64__ && !defined(__mips__) */
/* !α && !__ia64__ & & !(__mips__)定义 */
/*
  该函数是系统调用函数signal()函数的入口点， 其功能是注册一个函数到一个特定的信号，
  当该信号产生时，
  系统自动执行用户所注册的函数。
*/
