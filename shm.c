/*
 * linux/ipc/shm.c
 * Copyright (C) 1992, 1993 Krishna Balasubramanian
 *	 Many improvements/fixes by Bruno Haible.
 * Replaced `struct shm_desc' by `struct vm_area_struct', July 1994.
 * Fixed the shm swap deallocation (shm_unuse()), August 1998 Andrea Arcangeli.
 *
 * /proc/sysvipc/shm support (c) 1999 Dragos Acostachioaie <dragos@iname.com>
 * BIGMEM support, Andrea Arcangeli <andrea@suse.de>
 * SMP thread shm, Jean-Luc Boyard <jean-luc.boyard@siemens.fr>
 * HIGHMEM support, Ingo Molnar <mingo@redhat.com>
 * Make shmmax, shmall, shmmni sysctl'able, Christoph Rohland <cr@sap.com>
 * Shared /dev/zero support, Kanoj Sarcar <kanoj@sgi.com>
 * Move the mm functionality over to mm/shmem.c, Christoph Rohland <cr@sap.com>
 *
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/shm.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

//在操作系统理论中，每当提到信号量、消息队列和共享内存，我们通常称之为“IPC机制”；但在Linux的具体实现中，它们通常作为一种实体存在，占用一定的内存，具有一定的逻辑结构并拥有一组既定的操作，因此在研究操作系统具体实现中，我们将其称为“IPC资源”。
#include "util.h"

//共享内存允许两个或多个进程共享一给定的存储区，因为数据不需要来回复制，所以是最快的一种进程间通信机制。共享内存可以通过mmap()映射普通文件（特殊情况下还可以采用匿名映射）机制实现，也可以通过系统V共享内存机制实现。应用接口和原理很简单，内部机制复杂。为了实现更安全通信，往往还与信号灯等同步机制共同使用。
//共享内存涉及到了存储管理以及文件系统等方面的知识，深入理解其内部机制需要紧紧抓住内核使用的重要数据结构。系统V共享内存是以文件的形式组织在特殊文件系统shm中的。通过shmget可以创建或获得共享内存的标识符。取得共享内存标识符后，要通过shmat将这个内存区映射到本进程的虚拟地址空间。

//共享内存允许一个或多个进程通过同时出现在它们的虚拟地址空间的内存通讯。这块虚拟内存的页面在每一个共享进程的页表中都有页表条目引用。但是不需要在所有进程的虚拟内存都有相同的地址。象所有的系统 V IPC 对象一样，对于共享内存区域的访问通过 key 控制，并进行访问权限检查。内存共享之后，就不再检查进程如何使用这块内存。它们必须依赖于其他机制，比如系统 V 的信号量来同步对于内存的访问。 

//每一个新创建的内存区域都用一个 shmid_ds 数据结构来表达。这些数据结构保存在 shm_segs 向量表中。 Shmid_ds数据结构描述了这个共享内存取有多大、多少个进程在使用它以及共享内存如何映射到它们的地址空间。由共享内存的创建者来控制对于这块内存的访问权限和它的 key 是公开或私有。如果有足够的权限它也可以把共享内存锁定在物理内存中。 

struct shmid_kernel /* private to the kernel 内核私有,它是存储管理和文件系统结合起来的桥梁*/
{	
	struct kern_ipc_perm	shm_perm;
	/*
	// used by in-kernel data structures 许可证,所有的IPC资源都与这样一个数据结构相关，以表示其所有者、建立者等必要信息期望将其放入系统内核已达到进程间通信的最高效率
	struct kern_ipc_perm {  
		key_t  key;  //IPC资源关键字
		uid_t  uid; //所有者进程的UID    
		gid_t  gid;  //所有者进程的GID    
		uid_t  cuid; //创建者进程的UID   
		gid_t  cgid; //创建者进程的GID    
		mode_t  mode; //该结构的权限,用三个八进制位组表示该资源的所有者、组和其他用户对该资源的读写访问权限
		unsigned long seq;  //IPC资源数组中的位置
	};
	*/
	struct file *		shm_file;//存储了将被映射文件的地址。每个共享内存区对象都对应特殊文件系统shm中的一个文件，一般情况下，特殊文件系统shm中的文件是不能用read()、write()等方法访问的，当采取共享内存的方式把其中的文件映射到进程地址空间后，可直接采用访问内存的方式对其访问
	int			id;
	unsigned long		shm_nattch;
	unsigned long		shm_segsz;
	time_t			shm_atim;
	time_t			shm_dtim;
	time_t			shm_ctim;
	pid_t			shm_cprid;
	pid_t			shm_lprid;
};

#define shm_flags	shm_perm.mode

static struct file_operations shm_file_operations;
static struct vm_operations_struct shm_vm_ops;

// 正如消息队列和信号量一样，内核通过数据结构struct ipc_ids shm_ids维护系统中的所有共享内存区域。上图中的shm_ids.entries变量指向一个ipc_id结构数组，而每个ipc_id结构数组中有个指向kern_ipc_perm结构的指针。到这里读者应该很熟悉了，对于系统V共享内存区来说，kern_ipc_perm的宿主是shmid_kernel结构，shmid_kernel是用来描述一个共享内存区域的，这样内核就能够控制系统中所有的共享区域。同时，在shmid_kernel结构的file类型指针shm_file指向文件系统shm中相应的文件，这样，共享内存区域就与shm文件系统中的文件对应起来
static struct ipc_ids shm_ids;
//所有的IPC资源都与这样一个结构相关，以表示其所有者、建立者等必要信息
/*
struct ipc_ids {  
	int size;     //资源标识数量
	int in_use;    //是否被使用
	int max_id;    //最大标识符值
	unsigned short seq;  //序列位置
	unsigned short seq_max;  //最大序列位置值
	struct semaphore sem;  //用于进程同步的信号量
	spinlock_t ary;   //用于进程同步
	struct ipc_id* entries;  // ipc_id结构链表的入口
}; 
*/

#define shm_lock(id)	((struct shmid_kernel*)ipc_lock(&shm_ids,id))
#define shm_unlock(id)	ipc_unlock(&shm_ids,id)
#define shm_lockall()	ipc_lockall(&shm_ids)
#define shm_unlockall()	ipc_unlockall(&shm_ids)
#define shm_get(id)	((struct shmid_kernel*)ipc_get(&shm_ids,id))
#define shm_buildid(id, seq) \
	ipc_buildid(&shm_ids, id, seq)

static int newseg (key_t key, int shmflg, size_t size);
static void shm_open (struct vm_area_struct *shmd);
static void shm_close (struct vm_area_struct *shmd);
#ifdef CONFIG_PROC_FS
static int sysvipc_shm_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data);
#endif

size_t	shm_ctlmax = SHMMAX;//单个共享内存片断的最大size
size_t 	shm_ctlall = SHMALL;//可分配的共享内存数量的系统级限制。在某些系统上，SHMALL可能表示成页数量，而不是字节数量
int 	shm_ctlmni = SHMMNI;//共享内存片断数量的系统级的限制

static int shm_tot; /* total number of shared memory pages 共享内存页的总数*/

void __init shm_init (void)
{
	ipc_init_ids(&shm_ids, 1);//给定一个IPC标识符的范围大小（低于ipcmni）建立序列的应用范围并分配和初始化数组本身。
#ifdef CONFIG_PROC_FS
	create_proc_read_entry("sysvipc/shm", 0, 0, sysvipc_shm_read_proc, NULL);
#endif
}

//id检测
static inline int shm_checkid(struct shmid_kernel *s, int id)
{
	if (ipc_checkid(&shm_ids,&s->shm_perm,id))//定义于ipc/util.h中，该函数用于检测一个资源标识符是否在资源数组的正确位置上，如果是的话，返回1，否则返回0
		return -EIDRM;
	return 0;
}

//获取
static inline struct shmid_kernel *shm_rmid(int id)
{
	return (struct shmid_kernel *)ipc_rmid(&shm_ids,id);//得到了全局消息队列、信号量和消息队列的自旋锁锁定。在验证消息队列的ID和当前任务的访问权限
}

static inline int shm_addid(struct shmid_kernel *shp)
{
	return ipc_addid(&shm_ids, &shp->shm_perm, shm_ctlmni+1);//当一个新的信号量，消息队列，或共享内存段的加入，ipc_addid()首先调用grow_ary()确保相应的描述符数组的大小在系统最大值范围内是足够大的。为第一个未使用的元素搜索描述符数组。如果未找到一个未使用的元素，则正在使用的描述符的计数将递增。对新资源描述符的kern_ipc_perm结构进行初始化，并以新的描述符数组的索引返回。当ipc_addid()成功，它返回IPC型锁给定的全局自旋锁
}

//shm_inc()设置PID，设置当前时间，并增加一些附件为给定的共享内存段。这些操作在保持全局共享内存锁时将会执行。
static inline void shm_inc (int id) {
	struct shmid_kernel *shp;

	if(!(shp = shm_lock(id)))
		BUG();//未上锁时错误检测
	shp->shm_atim = CURRENT_TIME;
	shp->shm_lprid = current->pid;
	shp->shm_nattch++;
	shm_unlock(id);
}

/* This is called by fork, once for every shm attach. 由进程调用，每个shm附加一次*/
static void shm_open (struct vm_area_struct *shmd)
{
	shm_inc (shmd->vm_file->f_dentry->d_inode->i_ino);
}

/*
 * shm_destroy - free the struct shmid_kernel
 *
 * @shp: struct to free
 *
 * It has to be called with shp and shm_ids.sem locked
 */

//shm_destroy()来调整共享内存的页面总数进而导致共享内存段的移除，ipc_rmid()通过shm_rmid()删除共享内存ID。shmem_lock用于解锁共享内存页，有效减少引用计数为零的每一页。fput()用于减少使用计数器f_count的相关文件，如果有必要，释放文件对象资源 kfree()来释放共享内存段描述符.
static void shm_destroy (struct shmid_kernel *shp)
{
	shm_tot -= (shp->shm_segsz + PAGE_SIZE - 1) >> PAGE_SHIFT;//计算物理地址
	shm_rmid (shp->id);
	shmem_lock(shp->shm_file, 0);
	fput (shp->shm_file);//指定的文件写入
	kfree (shp);//释放
}

/*
 * remove the attach descriptor shmd.
 * free memory for segment if it is marked destroyed.
 * The descriptor has already been removed from the current->mm->mmap list
 * and will later be kfree()d.
  移除联系描述符，如果标记为销毁，移除free内存段
  描述符已从current->mm->mmap列表中移除，并且之后执行kfree().
 */
//shm_close()更新shm_lprid和shm_dtim并减少连接的共享内存块的数目。如果没有其他依附的共享内存段，shm_destroy()被调用来释放共享内存段的资源。

static void shm_close (struct vm_area_struct *shmd)
{
	struct file * file = shmd->vm_file;
	int id = file->f_dentry->d_inode->i_ino;
	struct shmid_kernel *shp;

	down (&shm_ids.sem);//信号量互斥锁
	/* remove from the list of attaches of the shm segment 从shm的附属列表中删除*/
	if(!(shp = shm_lock(id)))
		BUG();
	shp->shm_lprid = current->pid;
	shp->shm_dtim = CURRENT_TIME;
	shp->shm_nattch--;
	if(shp->shm_nattch == 0 &&
	   shp->shm_flags & SHM_DEST)//符合销毁条件
		shm_destroy (shp);//调用销毁

	shm_unlock(id);//资源解锁
	up (&shm_ids.sem);
}

static int shm_mmap(struct file * file, struct vm_area_struct * vma)
{
	UPDATE_ATIME(file->f_dentry->d_inode);//更新一个节点内部的访问时间并标记为回写。这个函数会自动处理只读文件系统和媒体，以及“noatime”标志和inode具体的“noatime”标记。
	vma->vm_ops = &shm_vm_ops;
	//设置PID，设置当前时间
	shm_inc(file->f_dentry->d_inode->i_ino);
	return 0;
}

static struct file_operations shm_file_operations = {
	mmap:	shm_mmap
};

static struct vm_operations_struct shm_vm_ops = {
	open:	shm_open,	/* callback for a new vm-area open 新VM区域打开时回调*/
	close:	shm_close,	/* callback for when the vm-area is released 当VM区域被释放时回调*/
	nopage:	shmem_nopage,
};

/*当一个新的共享内存段的需要创建时，newseg()函数被调用。它对新段的三个参数起作用：键、标志和大小。经过验证的共享内存段的大小在SHMMIN和SHMMAX之间。共享内存段的总数不超过SHMALL，它分配一个新的共享内存段描述符。
*/
static int newseg (key_t key, int shmflg, size_t size)
{
	int error;
	struct shmid_kernel *shp;
	int numpages = (size + PAGE_SIZE -1) >> PAGE_SHIFT;
	struct file * file;
	char name[13];
	int id;

	if (size < SHMMIN || size > shm_ctlmax)//检查范围
		return -EINVAL;

	if (shm_tot + numpages >= shm_ctlall)//检验段大小
		return -ENOSPC;

	shp = (struct shmid_kernel *) kmalloc (sizeof (*shp), GFP_USER);
	if (!shp)
		return -ENOMEM;
	sprintf (name, "SYSV%08x", key);
	file = shmem_file_setup(name, size);
	error = PTR_ERR(file);//返回错误的指针
	if (IS_ERR(file))
		goto no_file;

	error = -ENOSPC;
	id = shm_addid(shp);
	if(id == -1) 
		goto no_id;
	//更改shp属性
	shp->shm_perm.key = key;
	shp->shm_flags = (shmflg & S_IRWXUGO);
	shp->shm_cprid = current->pid;
	shp->shm_lprid = 0;
	shp->shm_atim = shp->shm_dtim = 0;
	shp->shm_ctim = CURRENT_TIME;
	shp->shm_segsz = size;
	shp->shm_nattch = 0;
	shp->id = shm_buildid(id,shp->shm_perm.seq);
	shp->shm_file = file;
	file->f_dentry->d_inode->i_ino = shp->id;
	file->f_op = &shm_file_operations;
	shm_tot += numpages;
	shm_unlock (id);
	return shp->id;

no_id:
	fput(file);
no_file:
	kfree(shp);
	return error;
}

//该函数用来创建共享内存
//第一个参数，与信号量的semget函数一样，程序需要提供一个参数key（非0整数），它有效地为共享内存段命名，shmget函数成功时返回一个与key相关的共享内存标识符（非负整数），用于后续的共享内存函数。调用失败返回-1.
asmlinkage long sys_shmget (key_t key, size_t size, int shmflg)
{
	struct shmid_kernel *shp;
	int err, id = 0;

	down(&shm_ids.sem);
	if (key == IPC_PRIVATE) {
		err = newseg(key, shmflg, size);//创建一个新的共享内存段
	} else if ((id = ipc_findkey(&shm_ids, key)) == -1) {//该函数通过一个for循环遍历一个ipc_ids结构中的资源标识符数组以查找相应的IPC关键字。如果找到指定的关键字则返回相应的资源标识符，否则返回-1。
		if (!(shmflg & IPC_CREAT))
			err = -ENOENT;
		else
			err = newseg(key, shmflg, size);
	} else if ((shmflg & IPC_CREAT) && (shmflg & IPC_EXCL)) {
		err = -EEXIST;
	} else {
		shp = shm_lock(id);
		if(shp==NULL)
			BUG();
		if (shp->shm_segsz < size)
			err = -EINVAL;
		else if (ipcperms(&shp->shm_perm, shmflg))//检测IPC许可证对于所有者、组和其他用户是否具有访问权限，如果有则返回0，否则返回-1。
			err = -EACCES;
		else
			err = shm_buildid(id, shp->shm_perm.seq);
		shm_unlock(id);
	}
	up(&shm_ids.sem);
	return err;
}

static inline unsigned long copy_shmid_to_user(void *buf, struct shmid64_ds *in, int version)
{
	switch(version) {
	case IPC_64:
		return copy_to_user(buf, in, sizeof(*in));
	case IPC_OLD:
	    {
		struct shmid_ds out;

		ipc64_perm_to_ipc_perm(&in->shm_perm, &out.shm_perm);
		out.shm_segsz	= in->shm_segsz;
		out.shm_atime	= in->shm_atime;
		out.shm_dtime	= in->shm_dtime;
		out.shm_ctime	= in->shm_ctime;
		out.shm_cpid	= in->shm_cpid;
		out.shm_lpid	= in->shm_lpid;
		out.shm_nattch	= in->shm_nattch;

		return copy_to_user(buf, &out, sizeof(out));
	    }
	default:
		return -EINVAL;
	}
}

struct shm_setbuf {
	uid_t	uid;
	gid_t	gid;
	mode_t	mode;
};	

static inline unsigned long copy_shmid_from_user(struct shm_setbuf *out, void *buf, int version)
{
	switch(version) {
	case IPC_64:
	    {
		struct shmid64_ds tbuf;

		if (copy_from_user(&tbuf, buf, sizeof(tbuf)))
			return -EFAULT;

		out->uid	= tbuf.shm_perm.uid;
		out->gid	= tbuf.shm_perm.gid;
		out->mode	= tbuf.shm_flags;

		return 0;
	    }
	case IPC_OLD:
	    {
		struct shmid_ds tbuf_old;

		if (copy_from_user(&tbuf_old, buf, sizeof(tbuf_old)))
			return -EFAULT;

		out->uid	= tbuf_old.shm_perm.uid;
		out->gid	= tbuf_old.shm_perm.gid;
		out->mode	= tbuf_old.shm_flags;

		return 0;
	    }
	default:
		return -EINVAL;
	}
}

static inline unsigned long copy_shminfo_to_user(void *buf, struct shminfo64 *in, int version)
{
	switch(version) {
	case IPC_64:
		return copy_to_user(buf, in, sizeof(*in));
	case IPC_OLD:
	    {
		struct shminfo out;

		if(in->shmmax > INT_MAX)
			out.shmmax = INT_MAX;
		else
			out.shmmax = (int)in->shmmax;

		out.shmmin	= in->shmmin;
		out.shmmni	= in->shmmni;
		out.shmseg	= in->shmseg;
		out.shmall	= in->shmall; 

		return copy_to_user(buf, &out, sizeof(out));
	    }
	default:
		return -EINVAL;
	}
}
//shm_get_stat()循环通过所有的共享内存结构，并计算在使用共享内存的总内存页面数和共享内存页交换的总数。每个共享内存段都有一个文件结构和inode结构。因为所需的数据是通过索引节点获得，每个被访问的inode结构的自旋锁按顺序锁定和解锁。
static void shm_get_stat (unsigned long *rss, unsigned long *swp) 
{
	struct shmem_inode_info *info;
	int i;

	*rss = 0;
	*swp = 0;

	for(i = 0; i <= shm_ids.max_id; i++) {
		struct shmid_kernel* shp;
		struct inode * inode;

		shp = shm_get(i);
		if(shp == NULL)
			continue;
		inode = shp->shm_file->f_dentry->d_inode;
		info = SHMEM_I(inode);
		spin_lock (&info->lock);//自旋锁
		*rss += inode->i_mapping->nrpages;//计算在使用共享内存的总内存页面数
		*swp += info->swapped;//计算共享内存页交换的总数
		spin_unlock (&info->lock);//自旋锁
	}
}

//用来控制共享内存
// 第一个参数，shm_id是shmget函数返回的共享内存标识符。
// 第二个参数，command是要采取的操作，它可以取下面的三个值 ：
//IPC_STAT：把shmid_ds结构中的数据设置为共享内存的当前关联值，即用共享内存的当前关联值覆盖shmid_ds的值。
//IPC_SET：如果进程有足够的权限，就把共享内存的当前关联值设置为shmid_ds结构中给出的值
//IPC_RMID：删除共享内存段
// 第三个参数，buf是一个结构指针，它指向共享内存模式和访问权限的结构。
asmlinkage long sys_shmctl (int shmid, int cmd, struct shmid_ds *buf)
{
	struct shm_setbuf setbuf;
	struct shmid_kernel *shp;
	int err, version;

	if (cmd < 0 || shmid < 0)
		return -EINVAL;

	version = ipc_parse_version(&cmd);

	switch (cmd) { /* replace with proc interface ? 替换与程序接口？*/
	case IPC_INFO: //临时缓冲变量shminfo64加载系统范围的共享内存参数,将其复制到用户空间让调用应用程序访问
	{
		struct shminfo64 shminfo;

		memset(&shminfo,0,sizeof(shminfo));
		shminfo.shmmni = shminfo.shmseg = shm_ctlmni;
		shminfo.shmmax = shm_ctlmax;
		shminfo.shmall = shm_ctlall;

		shminfo.shmmin = SHMMIN;
		if(copy_shminfo_to_user (buf, &shminfo, version))
			return -EFAULT;
		/* reading a integer is always atomic 读取整数总是原子的。*/
		err= shm_ids.max_id;
		if(err<0)
			err = 0;
		return err;
	}
	case SHM_INFO://全局共享内存信号量和共享内存锁被保持，在采集系统范围的统计信息的共享内存中
	{
		struct shm_info shm_info;

		memset(&shm_info,0,sizeof(shm_info));
		down(&shm_ids.sem);
		shm_lockall();
		shm_info.used_ids = shm_ids.in_use;
		shm_get_stat (&shm_info.shm_rss, &shm_info.shm_swp);//获得状态信息
		shm_info.shm_tot = shm_tot;
		shm_info.swap_attempts = 0;
		shm_info.swap_successes = 0;
		err = shm_ids.max_id;
		shm_unlockall();//解锁共享空间
		up(&shm_ids.sem);
		if(copy_to_user (buf, &shm_info, sizeof(shm_info)))
			return -EFAULT;

		return err < 0 ? 0 : err;
	}
	case SHM_STAT:
	case IPC_STAT://对于shm_stat和ipc_stata，临时缓冲结构shmid64_ds被初始化，全局共享内存锁上锁
	{
		struct shmid64_ds tbuf;
		int result;
		//空间设置
		memset(&tbuf, 0, sizeof(tbuf));
		shp = shm_lock(shmid);
		if(shp==NULL)
			return -EINVAL;
		if(cmd==SHM_STAT) {
			err = -EINVAL;
			if (shmid > shm_ids.max_id)
				goto out_unlock;
			//初始化新建id
			result = shm_buildid(shmid, shp->shm_perm.seq);
		} else {
			err = shm_checkid(shp,shmid);//继续之前验证ID
			if(err)
				goto out_unlock;
			result = 0;
		}
		err=-EACCES;
		if (ipcperms (&shp->shm_perm, S_IRUGO))//权限检查
			goto out_unlock;
		//所需的统计信息被加载到临时缓冲区中，然后复制到调用应用程序中
		kernel_to_ipc64_perm(&shp->shm_perm, &tbuf.shm_perm);
		tbuf.shm_segsz	= shp->shm_segsz;
		tbuf.shm_atime	= shp->shm_atim;
		tbuf.shm_dtime	= shp->shm_dtim;
		tbuf.shm_ctime	= shp->shm_ctim;
		tbuf.shm_cpid	= shp->shm_cprid;
		tbuf.shm_lpid	= shp->shm_lprid;
		tbuf.shm_nattch	= shp->shm_nattch;
		shm_unlock(shmid);
		if(copy_shmid_to_user (buf, &tbuf, version))
			return -EFAULT;
		return result;
	}
	case SHM_LOCK:
	case SHM_UNLOCK:
	//在验证访问权限后，全局共享内存锁上锁，并且验证共享内存段ID
	{
/* Allow superuser to lock segment in memory 允许超级用户锁定在内存中的段*/
/* Should the pages be faulted in here or leave it to user? 页面应该在这里出错，还是留给用户？*/
/* need to determine interaction with current->swappable 需要确定与current->swappable的交互*/
		if (!capable(CAP_IPC_LOCK))
			return -EPERM;

		shp = shm_lock(shmid);
		if(shp==NULL)
			return -EINVAL;
		err = shm_checkid(shp,shmid);
		if(err)
			goto out_unlock;
		if(cmd==SHM_LOCK) {
			shmem_lock(shp->shm_file, 1);
			shp->shm_flags |= SHM_LOCKED;
		} else {
			shmem_lock(shp->shm_file, 0);
			shp->shm_flags &= ~SHM_LOCKED;//解锁
		}
		shm_unlock(shmid);
		return err;
	}
	case IPC_RMID:
	//全局共享内存、信号量和全局共享内存锁被保持，之后对共享内存的id进行验证。如果当前没有进程依附该内存段，shm_destroy()来销毁共享内存段。
	{
		/*
		 *	We cannot simply remove the file. The SVID states
		 *	that the block remains until the last person
		 *	detaches from it, then is deleted. A shmat() on
		 *	an RMID segment is legal in older Linux and if 
		 *	we change it apps break...
		 *
		 *	Instead we set a destroyed flag, and then blow
		 *	the name away when the usage hits zero.
		 */
		down(&shm_ids.sem);
		shp = shm_lock(shmid);//上锁
		err = -EINVAL;
		if (shp == NULL) 
			goto out_up;
		err = shm_checkid(shp, shmid);
		if(err)
			goto out_unlock_up;
		if (current->euid != shp->shm_perm.uid &&
		    current->euid != shp->shm_perm.cuid && 
		    !capable(CAP_SYS_ADMIN)) {//操作者权限检查
			err=-EPERM;
			goto out_unlock_up;
		}
		if (shp->shm_nattch){
			shp->shm_flags |= SHM_DEST;// SHM_DEST用来标志其是需销毁的，
			/* Do not find it any more */
			shp->shm_perm.key = IPC_PRIVATE;//IPC_PRIVATE用来防止其他进程参考共享内存ID。
		} else
			shm_destroy (shp);

		/* Unlock */
		shm_unlock(shmid);
		up(&shm_ids.sem);
		return err;
	}

	case IPC_SET://在验证共享内存段ID和用户访问权限之后,UID，GID，和共享内存段模式标志被用户数据更新。
	{
		if(copy_shmid_from_user (&setbuf, buf, version))
			return -EFAULT;
		down(&shm_ids.sem);
		shp = shm_lock(shmid);
		err=-EINVAL;
		if(shp==NULL)
			goto out_up;
		err = shm_checkid(shp,shmid);
		if(err)
			goto out_unlock_up;
		err=-EPERM;
		if (current->euid != shp->shm_perm.uid &&
		    current->euid != shp->shm_perm.cuid && 
		    !capable(CAP_SYS_ADMIN)) {
			goto out_unlock_up;
		}

		//数据更新
		shp->shm_perm.uid = setbuf.uid;
		shp->shm_perm.gid = setbuf.gid;
		shp->shm_flags = (shp->shm_flags & ~S_IRWXUGO)
			| (setbuf.mode & S_IRWXUGO);
		shp->shm_ctim = CURRENT_TIME;
		break;
	}

	default:
		return -EINVAL;
	}

	err = 0;
out_unlock_up:
	shm_unlock(shmid);
out_up:
	up(&shm_ids.sem);
	return err;
out_unlock:
	shm_unlock(shmid);
	return err;
}

/*
 * Fix shmaddr, allocate descriptor, map shm, add attach descriptor to lists.
   确定shmaddr，分配描述符，规划共享内存，描述符映射到连接列表
第一次创建完共享内存时，它还不能被任何进程访问，shmat函数的作用就是用来启动对该共享内存的访问，并把共享内存连接到当前进程的地址空间。
 */
 
//第一个参数，shm_id是由shmget函数返回的共享内存标识。
//第二个参数，shm_addr指定共享内存连接到当前进程中的地址位置，通常为空，表示让系统来选择共享内存的地址。
//第三个参数，shm_flg是一组标志位，通常为0。
//调用成功时返回一个指向共享内存第一个字节的指针，如果调用失败返回-1.
asmlinkage long sys_shmat (int shmid, char *shmaddr, int shmflg, ulong *raddr)
{
	struct shmid_kernel *shp;
	unsigned long addr;
	unsigned long size;
	struct file * file;
	int    err;
	unsigned long flags;
	unsigned long prot;
	unsigned long o_flags;
	int acc_mode;
	void *user_addr;

	if (shmid < 0)
		return -EINVAL;

	if ((addr = (ulong)shmaddr)) {
		if (addr & (SHMLBA-1)) {
			if (shmflg & SHM_RND)
				addr &= ~(SHMLBA-1);	   /* round down 四舍五入到SHMLBA*/
			else//如果shmaddr不是SHMLBA的整数倍或者shm_rnd没有指定，那么EINVAL返回
				return -EINVAL;
		}
		flags = MAP_SHARED | MAP_FIXED; //映射的内存所做的修改同样影响到文件
	} else {
		if ((shmflg & SHM_REMAP))
			return -EINVAL;

		flags = MAP_SHARED;
	}

	if (shmflg & SHM_RDONLY) {//只读模式
		prot = PROT_READ;
		o_flags = O_RDONLY;
		acc_mode = S_IRUGO;
	} else {//可读可写
		prot = PROT_READ | PROT_WRITE;
		o_flags = O_RDWR;
		acc_mode = S_IRUGO | S_IWUGO;
	}

	/*
	 * We cannot rely on the fs check since SYSV IPC does have an
	 * additional creator id...
	 我们不能依靠FS检查因为SysV IPC有额外的创建者ID
	 */
	shp = shm_lock(shmid);
	if(shp == NULL)
		return -EINVAL;
	err = shm_checkid(shp,shmid);
	if (err) {
		shm_unlock(shmid);
		return err;
	}
	if (ipcperms(&shp->shm_perm, acc_mode)) {//ipc权限检查
		shm_unlock(shmid);
		return -EACCES;
	}
	file = shp->shm_file;
	size = file->f_dentry->d_inode->i_size;
	//调用者的权限被验证，共享内存段的shm_nattch递增。此增量保证附件计数是非零的，并防止在连接到段时共享内存段被破坏。这些操作在保持全局共享内存锁时执行
	shp->shm_nattch++;
	shm_unlock(shmid);

	down_write(&current->mm->mmap_sem);//写者使用该函数来得到读写信号量sem，它也会导致调用者睡眠，因此只能在进程上下文使用
	if (addr && !(shmflg & SHM_REMAP)) {
		user_addr = ERR_PTR(-EINVAL);
		if (find_vma_intersection(current->mm, addr, addr + size))
			goto invalid;
		/*
		 * If shm segment goes below stack, make sure there is some
		 * space left for the stack to grow (at least 4 pages).
		 如果SHM段在堆栈下面，请确保有一些空间供堆栈增长（至少有4页）
		 */
		if (addr < current->mm->start_stack &&
		    addr > current->mm->start_stack - size - PAGE_SIZE * 5)
			goto invalid;
	}
		
	//do_mmap()函数用来创建一个虚拟内存映射到共享内存段的页面。
	user_addr = (void*) do_mmap (file, addr, size, prot, flags, 0);

invalid:
	up_write(&current->mm->mmap_sem);//写者调用该函数释放信号量sem。它与down_write或down_write_trylock配对使用。如果down_write_trylock返回0，不需要调用up_write，因为返回0表示没有获得该读写信号量。
	down (&shm_ids.sem);
	if(!(shp = shm_lock(shmid)))
		BUG();
	shp->shm_nattch--;
	if(shp->shm_nattch == 0 &&
	   shp->shm_flags & SHM_DEST)//如果段标记为破坏（shm_dest），然后shm_destroy()被调用来释放共享内存段的资源
		shm_destroy (shp);
	shm_unlock(shmid);
	up (&shm_ids.sem);

	*raddr = (unsigned long) user_addr;
	err = 0;
	if (IS_ERR(user_addr))
		err = PTR_ERR(user_addr);
	return err;

}

/*该函数用于将共享内存从当前进程中分离。注意，将共享内存分离并不是删除它，只是使该共享内存对当前进程不再可用。shmaddr是shmat函数返回的地址指针
 * detach and kill segment if marked destroyed.
 * The work is done in shm_close.
 */
//全局共享内存、信号量在执行sys_shmdt()时被保持，当前进程的mm_struct搜索与共享内存地址相关联的vm_area_struct。当它被找到时，调用do_munmap()来撤消对共享内存段的虚拟地址映射。sys_shmdt()无条件返回0。
asmlinkage long sys_shmdt (char *shmaddr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *shmd, *shmdnext;

	down_write(&mm->mmap_sem);
	for (shmd = mm->mmap; shmd; shmd = shmdnext) {
		shmdnext = shmd->vm_next;
		if (shmd->vm_ops == &shm_vm_ops
		    && shmd->vm_start - (shmd->vm_pgoff << PAGE_SHIFT) == (ulong) shmaddr)
			do_munmap(mm, shmd->vm_start, shmd->vm_end - shmd->vm_start);//撤消对共享内存段的虚拟地址映射
	}
	up_write(&mm->mmap_sem);
	return 0;
}

#ifdef CONFIG_PROC_FS
static int sysvipc_shm_read_proc(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int i, len = 0;

	down(&shm_ids.sem);
	len += sprintf(buffer, "       key      shmid perms       size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime\n");

	for(i = 0; i <= shm_ids.max_id; i++) {
		struct shmid_kernel* shp;

		shp = shm_lock(i);
		if(shp!=NULL) {
#define SMALL_STRING "%10d %10d  %4o %10u %5u %5u  %5d %5u %5u %5u %5u %10lu %10lu %10lu\n"
#define BIG_STRING   "%10d %10d  %4o %21u %5u %5u  %5d %5u %5u %5u %5u %10lu %10lu %10lu\n"
			char *format;

			if (sizeof(size_t) <= sizeof(int))
				format = SMALL_STRING;
			else
				format = BIG_STRING;
			len += sprintf(buffer + len, format,
				shp->shm_perm.key,
				shm_buildid(i, shp->shm_perm.seq),
				shp->shm_flags,
				shp->shm_segsz,
				shp->shm_cprid,
				shp->shm_lprid,
				shp->shm_nattch,
				shp->shm_perm.uid,
				shp->shm_perm.gid,
				shp->shm_perm.cuid,
				shp->shm_perm.cgid,
				shp->shm_atim,
				shp->shm_dtim,
				shp->shm_ctim);
			shm_unlock(i);

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
	up(&shm_ids.sem);
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if(len > length)
		len = length;
	if(len < 0)
		len = 0;
	return len;
}
#endif
