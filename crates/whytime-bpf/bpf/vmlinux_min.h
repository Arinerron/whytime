/* Hand-written subset of vmlinux.h: only what whytime.bpf.c and the libbpf headers need.
 *
 * Field order and offsets are deliberately NOT the kernel's. Every record below is
 * preserve_access_index, so clang emits a CO-RE relocation for each field access and aya
 * rewrites the offset against /sys/kernel/btf/vmlinux at load time. Matching is by type name
 * (minus any ___flavor suffix) and field name; anonymous unions and structs in the kernel type
 * (sock_common's address and port pairs, mm_struct's argument range) are looked through.
 *
 * __VMLINUX_H__ tells bpf_tracing.h to use kernel pt_regs register names (di, si, dx, r10, ...).
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

/* UAPI values (stable ABI); vmlinux.h would supply these. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

struct linux_binprm;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef struct {
	int counter;
} atomic_t;

struct pt_regs {
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
};

struct super_block {
	dev_t s_dev;
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
	struct sock *sk;
};

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
};

struct signal_struct {
	atomic_t live;
};

struct task_struct {
	pid_t pid;
	pid_t tgid;
	int exit_code;
	char comm[16];
	u64 start_boottime;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct files_struct *files;
	struct mm_struct *mm;
	struct signal_struct *signal;
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
