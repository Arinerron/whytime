/* Hand-written subset of vmlinux.h: only what whytime.bpf.c and the libbpf headers need.
 *
 * Field order and offsets are deliberately NOT the kernel's. Every record below is
 * preserve_access_index, so clang emits a CO-RE relocation for each field access and aya
 * rewrites the offset against /sys/kernel/btf/vmlinux at load time. Matching is by type name
 * (minus any ___flavor suffix) and field name; anonymous unions and structs in the kernel type
 * (sock_common's address and port pairs, mm_struct's argument range) are looked through.
 *
 * __VMLINUX_H__ tells bpf_tracing.h to use kernel pt_regs register names (x86: di, si, dx, ...;
 * arm64: orig_x0, regs[]). Everything else here is arch-neutral.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef _Bool bool;
#define true 1
#define false 0
typedef int pid_t;
typedef unsigned short umode_t;
typedef __u32 dev_t;
typedef unsigned int __poll_t;

/* UAPI values (stable ABI); vmlinux.h would supply these. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* bpf_get_stackid flags. */
enum {
	BPF_F_USER_STACK = 1ULL << 8,
};

struct linux_binprm;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef struct {
	int counter;
} atomic_t;

/* Syscall argument registers read by PT_REGS_PARM*_CORE_SYSCALL. arm64 reads arg 1 from
 * pt_regs.orig_x0 (bpf_tracing.h's pt_regs___arm64 flavor) and the rest from user_pt_regs.regs[],
 * which the kernel's pt_regs embeds; `pstate` is the saved user PSTATE (AArch32 or not). */
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
};
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct pt_regs;
#else
#error "vmlinux_min.h declares pt_regs for x86 and arm64 only"
#endif

struct super_block {
	dev_t s_dev;
	unsigned long s_magic;
};

struct qstr {
	const unsigned char *name;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
};

struct vfsmount {
	struct dentry *mnt_root;
};

/* fs/mount.h: wraps every vfsmount; reached with container_of on `mnt`. */
struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct inode {
	umode_t i_mode;
	unsigned long i_ino;
	struct super_block *i_sb;
};

struct file {
	struct inode *f_inode;
	unsigned int f_flags;
	void *private_data;
	struct path f_path;
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
};

struct files_struct {
	struct fdtable *fdt;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
};

struct sock_common {
	__be32 skc_daddr;
	__be16 skc_dport;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
};

struct sock {
	struct sock_common __sk_common;
};

struct socket {
	short type;
	struct sock *sk;
};

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
};

struct vm_area_struct {
	struct file *vm_file;
};

/* Scheduler run queues. cfs_rq->rq exists with CONFIG_FAIR_GROUP_SCHED. */
struct rq {
	struct task_struct *curr;
};

struct cfs_rq {
	struct rq *rq;
};

struct sched_entity {
	struct cfs_rq *cfs_rq;
};

/* preempt_count is here on arm64 and riscv; x86-64 keeps it per-CPU. `status` (x86 only)
 * holds TS_COMPAT during a 32-bit syscall. */
struct thread_info {
	int preempt_count;
	unsigned int status;
};

struct list_head {
	struct list_head *next;
};

struct wait_queue_head {
	struct list_head head;
};

struct wait_queue_entry {
	void *private;
	struct list_head entry;
};

/* poll/select: one per (file, waitqueue); `wait.private` is the poll_wqueues. */
struct poll_table_entry {
	struct file *filp;
	__poll_t key;
	struct wait_queue_entry wait;
};

struct poll_wqueues {
	struct task_struct *polling_task;
};

/* epoll: `epoll_key` on 7.x, `epoll_filefd` before; CO-RE matches the member by name. */
struct epoll_filefd {
	struct file *file;
	int fd;
};

struct epoll_event {
	__poll_t events;
};

struct eventpoll {
	struct wait_queue_head wq;
};

struct epitem {
	struct epoll_filefd ffd;
	struct eventpoll *ep;
	struct epoll_event event;
};

struct eppoll_entry {
	struct epitem *base;
	struct wait_queue_entry wait;
};

struct signal_struct {
	atomic_t live;
	int group_exit_code;
	unsigned int flags;
};

struct task_struct {
	struct thread_info thread_info;
	pid_t pid;
	pid_t tgid;
	unsigned int flags;
	int exit_code;
	char comm[16];
	u64 start_boottime;
	struct sched_entity se;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct files_struct *files;
	struct mm_struct *mm;
	struct signal_struct *signal;
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
