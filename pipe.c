/*
 *  linux/fs/pipe.c
 *
 *  Copyright (C) 1991, 1992, 1999  Linus Torvalds
 */

#include <linux/mm.h>         //(1)
#include <linux/file.h>       //(2)
#include <linux/poll.h>       //(3)
#include <linux/slab.h>       //(4)
#include <linux/module.h>     //(5)
#include <linux/init.h>       //(6)

#include <asm/uaccess.h>       //(7) 
#include <asm/ioctls.h>        // 输入输出控制  (8) 


/*
<linux/mm.h>    //内存管理头文件，含有页面大小定义和一些页面释放函数原型。
<linux/poll.h>    //轮询文件
<linux/slab.h>   //包含了kcalloc、kzalloc内存分配函数的定义。
<linux/module.h> //最基本的文件，支持动态添加和卸载模块。Hello World驱动要这一个文件就可以了
<linux/init.h>   //初始化头文件
<linux/uaccess.h>     //包含了copy_to_user、copy_from_user等内核访问用户进程内存地址的函数定义。  
<asm/ioctls.h>        //输入输出控制 
*/

/*
 * We use a start+len construction, which provides full use of the 
 * allocated memory.
 * -- Florian Coosmann (FGC)
 * 
 * Reads with count = 0 should always return 0.
 * -- Julian Bradfield 1999-06-07.
 */
 /*
 我们使用一个start+len结构，它充分利用了分配的内存。
 计数= 0的读应该总是返回0
 */

/* Drop the inode semaphore and wait for a pipe event, atomically */
/*原子性地，减少inode信号量并等待管道事件*/

/*
管道是进程间通信的主要手段之一。一个管道实际上就是个只存在于内存中的文件，对这个文件的操作要通过两个已经打开文件进行，它们分别代表管道的两端。管道是一种特殊的文件，它不属于某一种文件系统，而是一种独立的文件系统，有其自己的数据结构。根据管道的适用范围将其分为：无名管道和命名管道。
	
管道（Pipe）及有名管道（named pipe）。管道可用于具有亲缘关系进程间的通信，
有名管道克服了管道没有名字的限制，因此，除具有管道所具有的功能外，它还允许无亲缘关系进程间的通信。

每个管道只有一个页面作为缓冲区，该页面是按照环形缓冲区的方式来使用的。这种访问方式是典型的“生产者——消费者”模型。当“生产者”进程有大量的数据需要写时，而且每当写满一个页面就需要进行睡眠等待，等待“消费者”从管道中读走一些数据，为其腾出一些空间。相应的，如果管道中没有可读数据，“消费者”进程就要睡眠等待。
*/

/*Linux内核中采用struct pipe_inode_info结构体来描述一个管道
wait_queue_head_t wait;  
        unsigned int nrbufs, curbuf;  
        struct page *tmp_page;  
        unsigned int readers;  
        unsigned int writers;  
        unsigned int waiting_writers;  
        unsigned int r_counter;  
        unsigned int w_counter;  
        struct fasync_struct *fasync_readers;  
        struct fasync_struct *fasync_writers;  
        struct inode *inode;  
        struct pipe_buffer bufs[PIPE_BUFFERS];  
};   
wait：读/写/poll等待队列；由于读/写不可能同时出现在等待的情况，所以可以共用等待队列；poll读与读，poll写与写可以共存出现在等待队列中
nrbufs：非空的pipe_buffer数量
curbuf：数据的起始pipe_buffer
tmp_page：页缓存，可以加速页帧的分配过程；当释放页帧时将页帧记入tmp_page，当分配页帧时，先从tmp_page中获取，如果tmp_page为空才从伙伴系统中获取
readers：当前管道的读者个数；每次以读方式打开时，readers加1；关闭时readers减1
writers：当前管道的写者个数；每次以写方式打开时，writers加1；关闭时writers减1
waiting_writers：被阻塞的管道写者个数；写进程被阻塞时，waiting_writers加1；被唤醒时，waiting_writers减一。
r_counter：管道读者记数器，每次以读方式打开管道时，r_counter加1；关闭是不变
w_counter：管道读者计数器；每次以写方式打开时，w_counter加1；关闭是不变
fasync_readers：读端异步描述符
fasync_writers：写端异步描述符
inode：pipe对应的inode
bufs：pipe_buffer回环数据*/

//如果没有退出，或者成功读取数据，读进程会主动调用pipe_wait函数进行睡眠等待
void pipe_wait(struct inode * inode)
{
	//创建一个等待队列的项
	DECLARE_WAITQUEUE(wait, current);
	//进程状态，如果收到信号会被唤醒并处理信号(然后再次进入等待睡眠状态)
	current->state = TASK_INTERRUPTIBLE;
	//向等待管道队列中加入新节点
	add_wait_queue(PIPE_WAIT(*inode), &wait);
	//互斥锁
	up(PIPE_SEM(*inode));
	schedule();//实现进程的调度,完成进程的切换
	//向等待管道队列中去掉入新节点
	remove_wait_queue(PIPE_WAIT(*inode), &wait);
	current->state = TASK_RUNNING;
	//互斥锁
	down(PIPE_SEM(*inode));
}

// 从管道中读取数据和写数据非常相似。进程允许进行非阻塞的读（依赖于它们打开文件或者管道的模式），这时，如果没有数据可读或者管道被锁定，会返回一个错误。这意味着进程会继续运行。另一种方式是在管道的 I 节点的等待队列中等待，直到写进程完成。如果管道的进程都完成了操作，管道的 I 节点和相应的共享数据页被废弃。
//1.计算写数据长度，如果长度为0直接返回
//2.获取pipe互斥锁，进入读数据临界区
//3.如果pipe缓存中有数据															
// A.通过confirm,map,copy,unmap一系列操作将数据从内核空间的pipe缓存复制到用户进程空间
// B.如果当前缓存pipe_buffer中数据复制完，则释放当前pipe_buffer；将唤醒标识置1
// C.如果复制完所需的数据，跳转步骤5退出
//4.如果pipe缓存中没有数据
// A.如果没有写者了，跳转步骤5退出
// B.如果没有数据写等待进程，读出部分数据时返回实际读出数据,未读出数据且时NONBLOCK读时返回EAGAIN错误
// C.有果有信号产生，且没有读出数据时，返回ERESTARTSYS错误，内核处理完信号后会自动重启系统调用read
// D.如果唤醒标识do_wakeup置位，唤醒被阻塞的写者进程；向设置了O_ASYNC标识的文件所属写者进程发送异步I/O信号SIGIO
// E.释放pipe互斥锁，进程被阻塞；如果进程被唤醒，获取pipe互斥锁，跳转步骤3继续循环
//5.释放pipe互斥锁，退出读数据临界区
//6.如果唤醒标识do_wakeup置位，唤醒被阻塞的写者进程；向设置了O_ASYNC标识的文件所属写者进程发送异步I/O信号SIGIO
//7.返回实际读出的数据
//注：
// 由于实际读出的数据长度可能比要求的小，所以要在程序中判断实际读出数据长度

//loff_t类型用于维护当前读写位置
static ssize_t
pipe_read(struct file *filp, char *buf, size_t count, loff_t *ppos)
{
	struct inode *inode = filp->f_dentry->d_inode;
	ssize_t size, read, ret;

	/* Seeks are not allowed on pipes.  不允许在管道上寻找*/
	ret = -ESPIPE;// Illegal seek      非法寻找
	read = 0;
	if (ppos != &filp->f_pos)	//
		goto out_nolock;

	/* Always return 0 on null read. 在空读时总是返回0。 */
	ret = 0;
	if (count == 0)
		goto out_nolock;

	/* Get the pipe semaphore 得到管道信号量*/
	ret = -ERESTARTSYS;//如果可以把用户看到的设备状态完全回滚到执行驱动代码之前，则返回ERESTARTSYS
	if (down_interruptible(PIPE_SEM(*inode)))//down_interruptible()是处理信号量的函数,返回值有三种:0代表正常返回,-ETIME等待超时,-EINTR 中断
		goto out_nolock;

	if (PIPE_EMPTY(*inode)) {//如果管道为空
	//4.如果pipe缓存中没有数据
do_more_read:       
		ret = 0;
		if (!PIPE_WRITERS(*inode))
			goto out;
		// A.如果没有写者了，跳转步骤5退出

		ret = -EAGAIN;
		// B.如果没有数据写等待进程，读出部分数据时返回实际读出数据,未读出数据且时NONBLOCK读时返回EAGAIN错误
		if (filp->f_flags & O_NONBLOCK)
			goto out;

		for (;;) {
			PIPE_WAITING_READERS(*inode)++;
			pipe_wait(inode);
			PIPE_WAITING_READERS(*inode)--;
			ret = -ERESTARTSYS;
			// C.有果有信号产生，且没有读出数据时，返回ERESTARTSYS错误，内核处理完信号后会自动重启系统调用read
			if (signal_pending(current))
				goto out;
			ret = 0;
			if (!PIPE_EMPTY(*inode))
				break;
			if (!PIPE_WRITERS(*inode))
				goto out;
		}
	}

	/* Read what data is available. 读取可用的数据。 */
	ret = -EFAULT;
	while (count > 0 && (size = PIPE_LEN(*inode))) {
		char *pipebuf = PIPE_BASE(*inode) + PIPE_START(*inode);
		ssize_t chars = PIPE_MAX_RCHUNK(*inode);     

		if (chars > count)
			chars = count;
		if (chars > size)
			chars = size;

		if (copy_to_user(buf, pipebuf, chars))   // 拷贝给用户  
			goto out;

		read += chars;
		PIPE_START(*inode) += chars;
		PIPE_START(*inode) &= (PIPE_SIZE - 1);
		PIPE_LEN(*inode) -= chars;
		count -= chars;
		buf += chars;
	}

	/* Cache behaviour optimization 高速缓存的性能优化*/
	if (!PIPE_LEN(*inode))
		PIPE_START(*inode) = 0;

	if (count && PIPE_WAITING_WRITERS(*inode) && !(filp->f_flags & O_NONBLOCK)) {     
	   //   如果pipe缓存中有数据 AND pipe有等待写入进程 AND 文件需要打开且没有空间的情况没有发生  
		/*
		 * We know that we are going to sleep: signal
		 * writers synchronously that there is more
		 * room.
		 我们知道我们要睡觉了：信号作者同步地说，还有更多的空间。
		 */
		wake_up_interruptible_sync(PIPE_WAIT(*inode));//唤醒注册到等待队列上的进程,但该进程进程可能抢占当前进程, 并且在 wake_up 返回之前被调度到处理器
		if (!PIPE_EMPTY(*inode))
			BUG();
		goto do_more_read;
	}
	/* Signal writers asynchronously that there is more room.  信号写入器异步，有更多的空间。*/
	wake_up_interruptible(PIPE_WAIT(*inode));//唤醒注册到等待队列上的进程
	//6.如果唤醒标识do_wakeup置位，唤醒被阻塞的写者进程；向设置了O_ASYNC标识的文件所属写者进程发送异步I/O信号SIGIO

	ret = read;
out:
	up(PIPE_SEM(*inode));//释放pipe互斥锁
	//5.释放pipe互斥锁，退出读数据临界区
out_nolock:
	if (read)
		ret = read;
	return ret;
}


/*     当写进程向管道写的时候，它使用标准的 write 库函数。
   这些库函数传递的文件描述符是进程的 file 数据结构组中的索引，每一个都表示一个打开的文件，
   在这种情况下，是打开的管道。
       Linux 系统调用使用描述这个管道的 file 数据结构指向的 write 例程。
   这个 write 例程使用表示管道的 VFS I 节点存放的信息，来管理写的请求。
       如果有足够的空间把所有的字节都写导管到中，只要管道没有被读进程锁定，
   Linux 为写进程上锁，并把字节从进程的地址空间拷贝到共享的数据页。  
       如果管道被读进程锁定或者空间不够，当前进程睡眠，并放在管道I节点的等待队列中，并调用调度程序，运行另外一个进程。
	   它是可以中断的，所以它可以接收信号。
	   当管道中有了足够的空间写数据或者锁定解除，写进程就会被读进程唤醒。
	   当数据写完之后，管道的 VFS I 节点锁定解除，
	   管道 I 节点的等待队列中的所有读进程都会被唤醒。 
*/
// 1.计算写数据长度，如果长度为0直接返回
// 2.获取pipe互斥锁，进入数据复制临界区
// 3.当没有读者时返回EPIPE错误，并向当前写进程发送SIGPIPE信号
// 4.计算写数据超过页大小的整数倍的长度（主要用于将余数部分与当前缓存合并，整数页分配新页帧存储）
// 5.如果当前缓存有空间容纳余数大小的数据，并且缓存可以合并数据，就复制余数长度数据到当前缓存中；如果复制完成，跳到步骤
  // 注：
    // 由于缓存页帧可能是高端内存页，所以要用confirm,map,写数据,unmap一系列操作；
    // 由于用户进程写pipe的数据所在页帧可能被swap到硬盘中，内核访问就会出现缺页异常；为了能够原子复制，在复制前先触发缺页异常，主要通过pipe_iov_copy_from_user去预触发缺页异常。
// 6.分配新缓存存放数据
  // A.当没有读者时返回EPIPE错误，并向当前写进程发送SIGPIPE信号；当pipe缓存被写满后，仍有数据未写，写进程会被阻塞，pipe锁被释放，此时读进程可以获取pipe锁进而读数据，读到数据后可能会关闭pipe的读端，所以每循环一次都会检测读者个数。
  // B.当有空闲缓存空间时
    // a.从tmp_page中分配页帧，如果tmp_page没有页帧则从伙伴系统中获取分配页帧
    // b.iov_fault_in_pages_read进行读用户地址空间缺页异常预触发，以便后面原子复制数据，保证数据从用户空间往内核空间复制时不产生缺页异常。
    // c.将页帧映射到内核永久映射区中，获得线性地址，以便内核访问物理页帧
    // d.将数据从用户空间复制到页帧中
    // e.将页帧从内核永久映射区中移除
    // f.初始化pipe缓存，如缓存页帧、偏移、大小、操作等
    // g.如果数据复制完，走步骤7，退出；否则走步骤6继续循环
  // C.当没有空闲缓存空间时
    // a.如果是非阻塞写时，有数据写入则返回写入的数据长度，没有数据写入则走步骤7并返回EAGAIN错误
    // b.如果有信号产生，有数据写入则返回写入的数据长度，没有数据写入则走步骤7并返回ERESTARTSYS错误，内核处理完信号后会自动重启系统调用write
    // c.如果有数据写入且之前没有唤醒操作，则唤醒被阻塞的读者进程；向设置了O_ASYNC标识的文件所属读者进程发送异步I/O信号SIGIO
    // d.阻塞写者计数器加1，释放pipe锁阻塞当前进程；进程被唤醒时获取pipe锁，并将阻塞写者计数器减1
    // e.走步骤6继续循环
// 7.释放pipe互斥锁，退出数据复制临界区
// 8.如果有数据写入且之前没有唤醒操作，则唤醒被阻塞的读者进程；向设置了O_ASYNC标识的文件所属读者进程发送异步I/O信号SIGIO
// 9.返回写的数据长度
// 注：
  // 当没有pipe缓存空间时，不管是NOBLOCK的写还是阻塞进程因信号而被唤醒，在有数据写入时都会返回实际写入的数据长度；所以需在用户进程中判断实际写入数据的长度是否是预期的写入长度。
static ssize_t
pipe_write(struct file *filp, const char *buf, size_t count, loff_t *ppos)
{
	struct inode *inode = filp->f_dentry->d_inode;	
	ssize_t free, written, ret;

	/* Seeks are not allowed on pipes.  不允许在管道上寻找。*/
	ret = -ESPIPE;    
	//ESPIPE:Illegal seek
	//非法寻找
	written = 0;
	if (ppos != &filp->f_pos)
		goto out_nolock;

	/* Null write succeeds.  空写成功。*/
	ret = 0;
	if (count == 0)                                                                    // 1.计算写数据长度，如果长度为0直接返回
		goto out_nolock;

	ret = -ERESTARTSYS;
	//ERESTART:Interrupted system call should berestarted
	//中断的系统调用应该停止
	
	if (down_interruptible(PIPE_SEM(*inode)))                                          // 2.获取pipe互斥锁，进入数据复制临界区
		goto out_nolock;

	/* No readers yields SIGPIPE.  没有读者产生sigpipe。*/
	
	if (!PIPE_READERS(*inode))                                                         // 3.当没有读者时返回EPIPE错误，并向当前写进程发送SIGPIPE信号
		goto sigpipe;
	/* If count <= PIPE_BUF, we have to make it atomic. 我们必须使其原子化。 */
	free = (count <= PIPE_BUF ? count : 1);                                           // 4.计算写数据超过页大小的整数倍的长度
	                                                                                  //（主要用于将余数部分与当前缓存合并，整数页分配新页帧存储）

	/* Wait, or check for, available space. 等待或检查可用空间。 */
	                                                                                  
	if (filp->f_flags & O_NONBLOCK) {                                                 //5.如果当前缓存有空间容纳余数大小的数据，并且缓存可以合并数据，
	//fileOpen		                                                                      //  就复制余数长度数据到当前缓存中；如果复制完成，跳到步骤
		ret = -EAGAIN;
		//EAGAIN:Resource temporarily unavailable
		//资源暂时不可用
		if (PIPE_FREE(*inode) < free)
			goto out;                                                                 // 6.分配新缓存存放数据
	} else {                          
		while (PIPE_FREE(*inode) < free) {
			PIPE_WAITING_WRITERS(*inode)++;
			pipe_wait(inode);
			PIPE_WAITING_WRITERS(*inode)--;

			ret = -ERESTARTSYS;               
			if (signal_pending(current))
				goto out;
            
			if (!PIPE_READERS(*inode))
				goto sigpipe;
		}
	}
	
	/* Copy into available space.  复制到可用空间。*/
	ret = -EFAULT;
	//EFAULT:错误的地址
	while (count > 0) {                                             //A.当没有读者时返回EPIPE错误，并向当前写进程发送SIGPIPE信号；
                                                                    //当pipe缓存被写满后，仍有数据未写，写进程会被阻塞，pipe锁被释放，
                                                                    //此时读进程可以获取pipe锁进而读数据，读到数据后可能会关闭pipe的读端，
                                                                    //所以每循环一次都会检测读者个数。
		int space;
		char *pipebuf = PIPE_BASE(*inode) + PIPE_END(*inode);
		ssize_t chars = PIPE_MAX_WCHUNK(*inode);
     
		if ((space = PIPE_FREE(*inode)) != 0) {                     // B.当有空闲缓存空间时
		                                                            // a.从tmp_page中分配页帧，
																	  // 如果tmp_page没有页帧则从伙伴系统中获取分配页帧
			if (chars > count)                                      //b.iov_fault_in_pages_read进行读用户地址空间缺页异常预触发，
			                                                        //以便后面原子复制数据，保证数据从用户空间往内核空间复制时不产生缺页异常。
				chars = count;                                      //c.将页帧映射到内核永久映射区中，获得线性地址，以便内核访问物理页帧
			if (chars > space)                                      // d.将数据从用户空间复制到页帧中
				chars = space;                                      // e.将页帧从内核永久映射区中移除

			if (copy_from_user(pipebuf, buf, chars))
				goto out;

			written += chars;                                       // f.初始化pipe缓存，如缓存页帧、偏移、大小、操作等
			PIPE_LEN(*inode) += chars;
			count -= chars;
			buf += chars;
			space = PIPE_FREE(*inode);
			continue;                                               // g.如果数据复制完，走步骤7，退出；否则走步骤6继续循环
		}

		ret = written;
		if (filp->f_flags & O_NONBLOCK)                              // C.当没有空闲缓存空间时
			break;

		do {                                                            // a.如果是非阻塞写时，有数据写入则返回写入的数据长度，
		                                                                // 没有数据写入则走步骤7并返回EAGAIN错误
																		
																		// b.如果有信号产生，有数据写入则返回写入的数据长度，
																		// 没有数据写入则走步骤7并返回ERESTARTSYS错误，
																		// 内核处理完信号后会自动重启系统调用write
			/*
			 * Synchronous wake-up: it knows that this process
			 * is going to give up this CPU, so it doesnt have
			 * to do idle reschedules.
			 同步唤醒：它知道这个过程是要放弃这个CPU，
			 所以它并不需要空闲安排。
			 */
			wake_up_interruptible_sync(PIPE_WAIT(*inode));               //c.如果有数据写入且之前没有唤醒操作，则唤醒被阻塞的读者进程；
			                                                             //  向设置了O_ASYNC标识的文件所属读者进程发送异步I/O信号SIGIO
			
			PIPE_WAITING_WRITERS(*inode)++;     
			pipe_wait(inode);                   
			PIPE_WAITING_WRITERS(*inode)--;                              //d.阻塞写者计数器加1，释放pipe锁阻塞当前进程；
			                                                             //  进程被唤醒时获取pipe锁，并将阻塞写者计数器减1
																		 
			if (signal_pending(current))
				goto out;
			if (!PIPE_READERS(*inode))               
				goto sigpipe;
			
		} while (!PIPE_FREE(*inode));
		
		ret = -EFAULT;
	}
	
	
	/* Signal readers asynchronously that
	there is more data. 
	异步读取信号有更多的数据。*/
	wake_up_interruptible(PIPE_WAIT(*inode));

	inode->i_ctime = inode->i_mtime = CURRENT_TIME;
	mark_inode_dirty(inode);//标记信息节点为脏

out:
	up(PIPE_SEM(*inode));
out_nolock:
	if (written)
		ret = written;
	return ret;

sigpipe://信号管道
	if (written)                    
		goto out;                   
	up(PIPE_SEM(*inode));                                           //7.释放pipe互斥锁，退出数据复制临界区  
	send_sig(SIGPIPE, current, 0);                                  //8.如果有数据写入且之前没有唤醒操作，则唤醒被阻塞的读者进程；
	                                                                //  向设置了O_ASYNC标识的文件所属读者进程发送异步I/O信号SIGIO
	return -EPIPE;                                                  //9.返回写的数据长度
}

//非法寻找
static loff_t
pipe_lseek(struct file *file, loff_t offset, int orig)
{
	return -ESPIPE; //Illegal seek
}

//管道读失败
static ssize_t
bad_pipe_r(struct file *filp, char *buf, size_t count, loff_t *ppos)
{
	return -EBADF; //File descriptor in bad state
}

//管道写失败
static ssize_t
bad_pipe_w(struct file *filp, const char *buf, size_t count, loff_t *ppos)
{
	return -EBADF;
}

//pipe_ioctl会在系统调用ioctl中调用，设置硬件控制寄存器，或者读取硬件状态寄存器的数值
//只支持FIONREAD命令，用于取pipe缓存中的数据大小
static int
pipe_ioctl(struct inode *pino, struct file *filp,
	   unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case FIONREAD:
			return put_user(PIPE_LEN(*pino), (int *)arg);
		default:
			return -EINVAL;// Invalid argument 无效参数
	}
}

/* No kernel lock held - fine */
//pipe_poll主要用于返回文件当前可以进行的poll操作
static unsigned int
pipe_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask;
	struct inode *inode = filp->f_dentry->d_inode;  	// 信息节点 = 内核文件打开 -> 索引节点链接 -> 数据信息节点 
 	// filp,fileOpen，内核文件打开函数

	poll_wait(filp, PIPE_WAIT(*inode), wait);  // 投票等待

	/* Reading only -- no need for acquiring the semaphore.  */  
	/*只读，没有必要获得这个信号量*/
	mask = POLLIN | POLLRDNORM;
	if (PIPE_EMPTY(*inode))
		mask = POLLOUT | POLLWRNORM;
	if (!PIPE_WRITERS(*inode) && filp->f_version != PIPE_WCOUNTER(*inode))
		mask |= POLLHUP;            
	if (!PIPE_READERS(*inode))
		mask |= POLLERR;

	return mask;
}

/* FIXME: most Unices do not set POLLERR for fifos */
#define fifo_poll pipe_poll


//当close文件时会调用release操作(文件引用计数器为0)
// 1.获取管道互斥锁，进入管道操作临界区
// 2.读/写者计数器减1
// 3.如果管道既没有读者也没有写者，则释放管道缓存及管道描述符
// 4.否则，唤醒管道等待队列中的阻塞进程，向管道读者&写者发送异步I/O信号SIGIO
 
/*管道释放*/ 
static int
pipe_release(struct inode *inode, int decr, int decw)
{
	down(PIPE_SEM(*inode));                                                                 // 1.获取管道互斥锁，进入管道操作临界区
	PIPE_READERS(*inode) -= decr;
	PIPE_WRITERS(*inode) -= decw;                                                           // 2.读/写者计数器减1
	if (!PIPE_READERS(*inode) && !PIPE_WRITERS(*inode)) {                                   // 3.如果管道既没有读者也没有写者，
	                                                                                        //   则释放管道缓存及管道描述符
		struct pipe_inode_info *info = inode->i_pipe;
		inode->i_pipe = NULL;
		free_page((unsigned long) info->base);                                              
		kfree(info);
	} else {
		wake_up_interruptible(PIPE_WAIT(*inode));                                           // 4.否则，唤醒管道等待队列中的阻塞进程，
		                                                                                    //   向管道读者&写者发送异步I/O信号SIGIO
		                                                                                    //   唤醒可中断进程
	}
	up(PIPE_SEM(*inode));

	return 0;
}

/*管道读取的释放*/
static int
pipe_read_release(struct inode *inode, struct file *filp)
{
	return pipe_release(inode, 1, 0);
}

/*管道写入的释放*/
static int
pipe_write_release(struct inode *inode, struct file *filp)
{
	return pipe_release(inode, 0, 1);
}

/*管道读写模式的释放*/
static int
pipe_rdwr_release(struct inode *inode, struct file *filp)
{
	int decr, decw;

	decr = (filp->f_mode & FMODE_READ) != 0;
	decw = (filp->f_mode & FMODE_WRITE) != 0;
	return pipe_release(inode, decr, decw);
}

/*管道读取模式打开*/
static int
pipe_read_open(struct inode *inode, struct file *filp)
{
	/* We could have perhaps used atomic_t, but this and friends
	   below are the only places.  So it doesn't seem worthwhile.  */
	/*我们也许可以用atomic_t，但它和下列朋友
      是仅有的空间，所以这看起来不值得。*/

	down(PIPE_SEM(*inode));
	PIPE_READERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

/*管道写入模式打开*/
static int
pipe_write_open(struct inode *inode, struct file *filp)
{
	down(PIPE_SEM(*inode));
	PIPE_WRITERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

/*管道读写模式打开*/
static int
pipe_rdwr_open(struct inode *inode, struct file *filp)
{
	down(PIPE_SEM(*inode));
	if (filp->f_mode & FMODE_READ)
		PIPE_READERS(*inode)++;
	if (filp->f_mode & FMODE_WRITE)
		PIPE_WRITERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

/*
 * The file_operations structs are not static because they
 * are also used in linux/fs/fifo.c to do operations on FIFOs.
 */
 // 文件操作集
// 当创建pipe/FIFO时，内核会分配file,dentry,inode,inode_pipe_info对象；
// 并将file对象的f_op指向read_pipefifo_fop/write_pipefifo_fops/rdwr_pipefifo_fops，当后续的read,write,poll等系统调用，会通过vfs调用相应的f_op中方法。
// pipe/FIFO文件操作集如下
 // read_pipefifo_fops：pipe读端文件操作/FIFO只读方式文件操作
 // write_pipefifo_fops：pipe写端文件操作/FIFO只写方式文件操作
 // rdwr_pipefifo_fops：pipe读写文件操作/FIFO读写方式文件操作
 
 //read_fifo_fops：FIFO只读方式文件操作
struct file_operations read_fifo_fops = {
	llseek:		pipe_lseek,              /*管道访问*/
                                         /*lseek函数,lseek function,移动文件读/写指针,随机访问文件 */	
	read:		pipe_read,               /*管道读*/
	write:		bad_pipe_w,              /*坏管道写入*/
	poll:		fifo_poll,               /*先进先出投票*/
	ioctl:		pipe_ioctl,              /*管道输入输出控制*/
	open:		pipe_read_open,          /*管道读打开*/
	release:	pipe_read_release,       /*管道读释放*/
};

 //read_fifo_fops：FIFO只写方式文件操作   
struct file_operations write_fifo_fops = {
	llseek:		pipe_lseek,   
	read:		bad_pipe_r,
	write:		pipe_write,
	poll:		fifo_poll,     
	ioctl:		pipe_ioctl,
	open:		pipe_write_open,      
	release:	pipe_write_release,
};

//read_fifo_fops：FIFO读写方式文件操作
struct file_operations rdwr_fifo_fops = {
	llseek:		pipe_lseek,
	read:		pipe_read,
	write:		pipe_write,
	poll:		fifo_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_rdwr_open,
	release:	pipe_rdwr_release,
};

// read_pipefifo_fops：pipe读端文件操作
struct file_operations read_pipe_fops = {
	llseek:		pipe_lseek,
	read:		pipe_read,
	write:		bad_pipe_w,
	poll:		pipe_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_read_open,
	release:	pipe_read_release,
};

// write_pipefifo_fops：pipe写端文件操作
struct file_operations write_pipe_fops = {
	llseek:		pipe_lseek,
	read:		bad_pipe_r,
	write:		pipe_write,
	poll:		pipe_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_write_open,
	release:	pipe_write_release,
};

// read_pipefifo_fops：pipe读写文件操作
struct file_operations rdwr_pipe_fops = {
	llseek:		pipe_lseek,
	read:		pipe_read,
	write:		pipe_write,
	poll:		pipe_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_rdwr_open,
	release:	pipe_rdwr_release,
};


//接着通过调用get_pipe_inode来实例化一个带有pipe属性的inode
struct inode* pipe_new(struct inode* inode)
{
	unsigned long page;
	// 申请一个内存页，作为pipe的缓存
	page = __get_free_page(GFP_USER);	
	// GFP_USER 用来为用户空间页来分配内存，可能睡眠。
	if (!page)
		return NULL;
    // 为pipe_inode_info结构体分配内存
	inode->i_pipe = kmalloc(sizeof(struct pipe_inode_info), GFP_KERNEL);
	if (!inode->i_pipe)
		goto fail_page;
    
	// 初始化pipe_inode_info属性
	init_waitqueue_head(PIPE_WAIT(*inode));     
	/* 初始化等待队列 */ 
	PIPE_BASE(*inode) = (char*) page;
	PIPE_START(*inode) = PIPE_LEN(*inode) = 0;
	PIPE_READERS(*inode) = PIPE_WRITERS(*inode) = 0;
	PIPE_WAITING_READERS(*inode) = PIPE_WAITING_WRITERS(*inode) = 0;
	PIPE_RCOUNTER(*inode) = PIPE_WCOUNTER(*inode) = 1;

	return inode;
fail_page:
	free_page(page);
	return NULL;
}

static struct vfsmount *pipe_mnt;
static int pipefs_delete_dentry(struct dentry *dentry)
{
	return 1;
}
static struct dentry_operations pipefs_dentry_operations = {
	d_delete:	pipefs_delete_dentry,
};

/*inode:information node，信息节点，索引点*/
/*获取管道的信息节点*/
static struct inode * get_pipe_inode(void)
{
	//　从pipefs超级块中分配一个inode
	struct inode *inode = new_inode(pipe_mnt->mnt_sb);

	if (!inode)
		goto fail_inode;
	/* pipe_new函数主要用来为这个inode初始化pipe属性，
	就是pipe_inode_info结构体*/
	/*如果信息节点值为0*/ /*跳转：fail_inode（查询信息节点失败）*/

	if(!pipe_new(inode))
		goto fail_iput;
	
    /* 新管道函数返回值为0 */   /* 跳转：fail_iput */   
	
	PIPE_READERS(*inode) = PIPE_WRITERS(*inode) = 1;
	inode->i_fop = &rdwr_pipe_fops;
	//设置pipefs的inode操作函数集合，rdwr_pipe_fops
	// 为结构体，包含读写管道所有操作

	/*
	 * Mark the inode dirty from the very beginning,
	 * that way it will never be moved to the dirty
	 * list because "mark_inode_dirty()" will think
	 * that it already _is_ on the dirty list.
	 */
	 
     /*
      *从一开始就把inode标记为污染的，
      *这样它就不会被移动到污染表中去了
      *因为“mark_inode_dirty()“将认为
      *它已经在黑名单上了。
      */
 
	inode->i_state = I_DIRTY;
	inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
	inode->i_uid = current->fsuid;
	inode->i_gid = current->fsgid;
	
	/* fs 文件系统  */
	/*
      GID为GroupId，即组ID，用来标识用户组的唯一标识符
      UID为UserId，即用户ID，用来标识每个用户的唯一标示符
      扩展：
      用户组：将同一类用户设置为同一个组，如可将所有的系统管理员设置为admin组，便于分配权限，
      将某些重要的文件设置为所有admin组用户可以读写，这样可以进行权限分配。
      每个用户都有一个唯一的用户id，每个用户组都有一个唯一的组id
    */
	
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_blksize = PAGE_SIZE;
	return inode;

fail_iput:
	iput(inode);
fail_inode:
	return NULL;
}

// 执行do_pipe 操作 
int do_pipe(int *fd)
{
	struct qstr this;
	char name[32];
	struct dentry *dentry;
	struct inode * inode;
	struct file *f1, *f2;
	int error;
	int i,j;

	error = -ENFILE;/* File table overflow 文件表溢出 */
	f1 = get_empty_filp();
	if (!f1)
		goto no_files;

	f2 = get_empty_filp();
	if (!f2)
		goto close_f1;

	inode = get_pipe_inode();
	if (!inode)
		goto close_f12;

	error = get_unused_fd();
	if (error < 0)
		goto close_f12_inode;
	i = error;

	error = get_unused_fd();
	if (error < 0)
		goto close_f12_inode_i;
	j = error;

	error = -ENOMEM;/* Out of memory  内存不足 */
	sprintf(name, "[%lu]", inode->i_ino);
	this.name = name;
	this.len = strlen(name);  /*获取长度*/
	this.hash = inode->i_ino; /* will go */
	dentry = d_alloc(pipe_mnt->mnt_sb->s_root, &this);
	
	if (!dentry)
		goto close_f12_inode_i_j;
	dentry->d_op = &pipefs_dentry_operations;
	d_add(dentry, inode);
	f1->f_vfsmnt = f2->f_vfsmnt = mntget(mntget(pipe_mnt));
	/*linux下mnt目录的作用：
      mount 可直接理解为“挂载”*/
	f1->f_dentry = f2->f_dentry = dget(dentry);
	/* dentry
dentry是一个内存实体，其中的d_inode成员指向对应的inode
    */

	/* read file */  /*读文件*/
	f1->f_pos = f2->f_pos = 0;
	f1->f_flags = O_RDONLY;//f1这个file实例只可读
	f1->f_op = &read_pipe_fops;//这是这个可读file的操作函数集合结构体
	f1->f_mode = 1;
	f1->f_version = 0;

	/* write file */  /*写文件*/
	f2->f_flags = O_WRONLY;//f2这个file实例只可写
	f2->f_op = &write_pipe_fops;//这是这个只可写的file操作函数集合结构体
	f2->f_mode = 2;
	f2->f_version = 0;

	fd_install(i, f1);//将i(fd)和f1(file)关联起来
	fd_install(j, f2);//将j(fd)和f2(file)关联起来
	fd[0] = i;
	fd[1] = j;
	return 0;

close_f12_inode_i_j:
	put_unused_fd(j);
close_f12_inode_i:
	put_unused_fd(i);
close_f12_inode:
	free_page((unsigned long) PIPE_BASE(*inode));
	kfree(inode->i_pipe);
	inode->i_pipe = NULL;
	iput(inode);
close_f12:
	put_filp(f2);
close_f1:
	put_filp(f1);
no_files:
	return error;	
}

/*
 * pipefs should _never_ be mounted by userland - too much of security hassle,
 * no real gain from having the whole whorehouse mounted. So we don't need
 * any operations on the root directory. However, we need a non-trivial
 * d_name - pipe: will go nicely and kill the special-casing in procfs.
 */
 
 /* 
   pipefs应该不会被用户态安装——太多的安全麻烦，
   把整个妓院都装上，没有什么好处。
   所以我们不需要根目录上的任何操作。
   然而，我们需要一个重要的数据类型的名称：管道。
   管道能够运作地很好并除去procfs中的特殊外壳。
  */

 //pipefs是一个虚拟的文件系统，挂载在内核中而不会被挂载到根文件系统中
static int pipefs_statfs(struct super_block *sb, struct statfs *buf)
{
	buf->f_type = PIPEFS_MAGIC;
	buf->f_bsize = 1024;
	buf->f_namelen = 255;
	return 0;
}

/* 特级操作：pipefs特级操作 */
static struct super_operations pipefs_ops = {
	statfs:		pipefs_statfs,
};

/* 特级块：pipefs特级读取 */
static struct super_block * pipefs_read_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root = new_inode(sb);
	if (!root)
		return NULL;
	root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	root->i_uid = root->i_gid = 0;
	root->i_atime = root->i_mtime = root->i_ctime = CURRENT_TIME;
	sb->s_blocksize = 1024;
	sb->s_blocksize_bits = 10;
	sb->s_magic = PIPEFS_MAGIC;
	sb->s_op	= &pipefs_ops;
	sb->s_root = d_alloc(NULL, &(const struct qstr) { "pipe:", 5, 0 });
	if (!sb->s_root) {
		iput(root);
		return NULL;
	}
	sb->s_root->d_sb = sb;
	sb->s_root->d_parent = sb->s_root;
	d_instantiate(sb->s_root, root);
	return sb;
}

/*声明：文件系统类型*/       /*FS:file system，文件系统*/
static DECLARE_FSTYPE(pipe_fs_type, "pipefs", pipefs_read_super, FS_NOMOUNT);

/*初始化管道文件系统*/
static int __init init_pipe_fs(void)
{
	int err = register_filesystem(&pipe_fs_type);   // err变量得到寄存器-文件系统函数的返回值
	if (!err) {
		pipe_mnt = kern_mount(&pipe_fs_type);        
		err = PTR_ERR(pipe_mnt);                     
		if (IS_ERR(pipe_mnt))
			unregister_filesystem(&pipe_fs_type);   
		else
			err = 0;
	}
	return err;
}

/* 退出管道文件系统 */
static void __exit exit_pipe_fs(void)
{
	unregister_filesystem(&pipe_fs_type);   
	mntput(pipe_mnt);
}

/*初始化模块*/
module_init(init_pipe_fs)
/*退出模块*/
module_exit(exit_pipe_fs)
