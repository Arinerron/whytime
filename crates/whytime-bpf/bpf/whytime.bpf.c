// SPDX-License-Identifier: MIT
/*
 * whytime kernel side: per-thread off-CPU episodes for one process tree.
 *
 * Membership is by lineage: user space puts the wrapped command's tgid in `tracked`, and
 * sched_process_fork adds every child process of a tracked one (in kernel, so a child can
 * never run untracked). Each tracked thread has a `tasks` entry holding its open accounting
 * segment. sched_switch accumulates on-CPU and preempted-runqueue time in place, so a
 * CPU-bound thread produces no records; one EPISODE record is emitted per block -> wake -> run
 * cycle, when the thread runs again. sys_enter/sys_exit remember the syscall in flight and its
 * first arguments; the first time a syscall blocks, sched_switch describes its file descriptor
 * (type, identity, socket peer, path) so user space can say what each block waited for. The
 * description is lazy because most syscalls never block, and it is the expensive part.
 *
 * Optional fentry programs refine that: pollwake/ep_poll_callback record which file ended a
 * poll/select/epoll wait, and handle_mm_fault entry/exit mark blocks inside page faults.
 *
 * Stack capture (flamegraphs) is compiled in only with WHYTIME_STACKS, a second object that
 * user space loads for --flamegraph/--folded: sched_switch then also records the user and
 * kernel stack of every voluntary switch-out of a tracked thread, and a perf_event CPU-clock
 * sampler emits SAMPLE records with the stacks of tracked threads it finds on a CPU. Stacks
 * go to two stack maps used alternately by generation (see `stack_ref`); a stack neither
 * can take is copied whole into a STACK record.
 *
 * Untracked tasks cost one hash lookup per handler (two in sched_switch).
 */
#include "vmlinux_min.h"
#include "whytime_wire.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define AF_INET 2
#define AF_INET6 10
#define TASK_RUNNING 0
/* Dentries plus mount crossings visited by one path walk. */
#define PATH_DEPTH 32
#define PF_EXITING 0x00000004
/* epoll_event.events bits that are not readiness events (EPOLLEXCLUSIVE, EPOLLWAKEUP,
 * EPOLLONESHOT, EPOLLET): an item with none of the others is disabled. */
#define EP_PRIVATE_BITS 0xf0000000u

/* MIT code may be distributed under the GPL, and the verifier grants GPL-only helpers
 * (bpf_probe_read_kernel, ...) only to programs declaring a GPL-compatible license. */
char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} events SEC(".maps");

/* tid -> state of a tracked thread. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TASKS_MAX);
	__type(key, u32);
	__type(value, struct task_state);
} tasks SEC(".maps");

/* tgid -> 1 for every process in the traced tree. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TRACKED_MAX);
	__type(key, u32);
	__type(value, u32);
} tracked SEC(".maps");

/* syscall nr -> SYSF_* bits, filled by user space from its libc syscall numbers. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SYS_TABLE_LEN);
	__type(key, u32);
	__type(value, u32);
} sys_flags SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_NR);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

/* Twice PATH_BYTES: a name read at any offset below PATH_BYTES, of at most PATH_BYTES bytes,
 * stays in bounds as far as the verifier can tell. */
struct path_scratch {
	char bytes[2 * PATH_BYTES];
};

/* Per-CPU buffer where capture_path assembles a path. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct path_scratch);
} path_buf SEC(".maps");
/* One zeroed task_state, the template of new `tasks` entries: task_state is too large for
 * the 512-byte BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct task_state);
} task_zero SEC(".maps");

#ifdef WHYTIME_STACKS
/* Stack id -> STACK_DEPTH addresses, leaf first, in two maps used alternately: generation g
 * stores into stacks0 when g is even, stacks1 when odd, and every reference carries g. User
 * space flips generations on a timer; after a flip it reads what the old generation's
 * references still need, then empties that map for the generation after next. Without
 * this, entries are never freed and a long run fills the map with stale stacks. */
struct stack_map {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, STACKS_MAX);
	__uint(key_size, sizeof(u32));
	__uint(value_size, STACK_DEPTH * sizeof(u64));
};
struct stack_map stacks0 SEC(".maps");
struct stack_map stacks1 SEC(".maps");

/* [0]: the current stack generation, set by user space. */
struct gen_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
};
struct gen_map stack_gen SEC(".maps");

/* Never used by the programs: user space stores `stack_gen` in it after a flip, because a
 * map-in-map update returns only after an RCU grace period, when every program that may have
 * read the old generation has finished. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, u32);
	__array(values, struct gen_map);
} stack_barrier SEC(".maps");
#endif

static __always_inline void stat_inc(u32 slot)
{
	u64 *v = bpf_map_lookup_elem(&stats, &slot);

	if (v)
		*v += 1;
}

static __always_inline void *reserve(u64 size)
{
	void *e = bpf_ringbuf_reserve(&events, size, 0);

	if (!e)
		stat_inc(STAT_RING_FULL);
	return e;
}

static __always_inline void fill_hdr(struct ev_header *h, u32 kind, u32 tid, u32 tgid, u64 ts)
{
	h->kind = kind;
	h->tid = tid;
	h->tgid = tgid;
	h->_pad = 0;
	h->ts = ts;
}

#ifdef WHYTIME_STACKS
/* bpf_get_stackid errors that mean the map could not take the stack. */
#define EEXIST 17
#define ENOMEM 12

/* The current stack generation. */
static __always_inline u32 stack_generation(void)
{
	u32 zero = 0;
	u32 *gen = bpf_map_lookup_elem(&stack_gen, &zero);

	return gen ? *gen : 0;
}

/* The current task's user (`flags` BPF_F_USER_STACK) or kernel stack as a stack reference
 * (see task_state.user_stack): id + 1 in generation `gen`'s map; when the map cannot take
 * it (bucket collision, full), STACK_INLINE after copying it whole into a STACK record for
 * thread `tid` at capture time `ts`; else the negative errno. */
static __always_inline s32 stack_ref(void *ctx, u32 gen, u64 flags, u32 tid, u32 tgid, u64 ts)
{
	struct stack_record *e;
	long id, bytes;

	if (gen & 1)
		id = bpf_get_stackid(ctx, &stacks1, flags);
	else
		id = bpf_get_stackid(ctx, &stacks0, flags);
	if (id >= 0)
		return id + 1;
	if (id != -EEXIST && id != -ENOMEM)
		return id;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_STACK_LOST);
		return id;
	}
	bytes = bpf_get_stack(ctx, e->ips, sizeof(e->ips), flags);
	if (bytes <= 0) {
		bpf_ringbuf_discard(e, 0);
		stat_inc(STAT_STACK_LOST);
		return id;
	}
	fill_hdr(&e->hdr, EV_STACK, tid, tgid, ts);
	e->kernel = !(flags & BPF_F_USER_STACK);
	e->nr = bytes / sizeof(u64);
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_STACK_INLINE);
	return STACK_INLINE;
}
#endif

/* Copies the open segment into a record and starts a new one at `now`. */
static __always_inline void close_segment(struct task_state *t, struct cpu_segment *out, u64 now)
{
	if (out)
		*out = t->seg;
	__builtin_memset(&t->seg, 0, sizeof(t->seg));
	t->seg.start = now;
}

static __always_inline void clear_sys(struct sys_info *s)
{
	__builtin_memset(s, 0, sizeof(*s));
	s->nr = NR_NONE;
	s->fd = -1;
}

/* ---- descriptor description (at a syscall's first block) ---------------------------- */

/* Fills inode type/identity, open flags and, for inet sockets, the peer address of `f`. */
static __always_inline void describe_file(struct sys_info *s, struct file *f)
{
	struct inode *ino = BPF_CORE_READ(f, f_inode);
	struct socket *sock;
	struct sock *sk;

	if (!ino)
		return;
	s->mode = BPF_CORE_READ(ino, i_mode) & S_IFMT;
	s->ino = BPF_CORE_READ(ino, i_ino);
	s->dev = BPF_CORE_READ(ino, i_sb, s_dev);
	s->f_flags = BPF_CORE_READ(f, f_flags);
	if (s->mode != S_IFSOCK)
		return;
	sock = BPF_CORE_READ(f, private_data);
	sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return;
	s->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (s->family == AF_INET) {
		__be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(s->addr, &daddr, sizeof(daddr));
		s->port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	} else if (s->family == AF_INET6) {
		BPF_CORE_READ_INTO(&s->addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		s->port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	}
}

/* Describes the current task's descriptor `fd` into `s`; returns its file, 0 if not open. */
static __always_inline struct file *describe_fd(struct sys_info *s, int fd)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	struct file **fds, *f = 0;
	unsigned int max;

	if (!fdt || fd < 0)
		return 0;
	max = BPF_CORE_READ(fdt, max_fds);
	if ((unsigned int)fd >= max)
		return 0;
	fds = BPF_CORE_READ(fdt, fd);
	if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f)
		return 0;
	describe_file(s, f);
	return f;
}

/* connect(fd, addr, len): the target address, from user memory. */
static __always_inline void describe_sockaddr(struct sys_info *s, const void *uaddr, long len)
{
	u16 family = 0;
	__be16 port = 0;

	if (!uaddr || len < 4 || bpf_probe_read_user(&family, sizeof(family), uaddr))
		return;
	if (bpf_probe_read_user(&port, sizeof(port), uaddr + 2))
		return;
	if (family == AF_INET && len >= 8) {
		if (bpf_probe_read_user(s->addr, 4, uaddr + 4))
			return;
	} else if (family == AF_INET6 && len >= 24) {
		if (bpf_probe_read_user(s->addr, 16, uaddr + 8))
			return;
	} else {
		return;
	}
	s->family = family;
	s->port = __builtin_bswap16(port);
}

/*
 * Walks `f`'s dentries up to the root of the task's mount namespace, crossing mount points
 * through struct mount, and stores the names leaf first into `d->path` (see SysDetail). The
 * walk is relative to the namespace root, not to a chroot. Only whole names are kept.
 */
static __always_inline void capture_path(struct sys_detail *d, struct file *f)
{
	u32 zero = 0, off = 0, flags = SYSD_PATH_TRUNCATED, i;
	struct path_scratch *buf = bpf_map_lookup_elem(&path_buf, &zero);
	struct vfsmount *vfs = BPF_CORE_READ(f, f_path.mnt);
	struct dentry *dent = BPF_CORE_READ(f, f_path.dentry);
	struct mount *mnt = (struct mount *)((char *)vfs - bpf_core_field_offset(struct mount, mnt));
	struct dentry *root = BPF_CORE_READ(vfs, mnt_root);

	if (!buf || !vfs || !dent)
		return;
	for (i = 0; i < PATH_DEPTH; i++) {
		struct dentry *parent;
		u32 at = off & (PATH_BYTES - 1);
		long n;

		if (dent == root) {
			struct mount *up = BPF_CORE_READ(mnt, mnt_parent);

			if (up == mnt) {
				flags = SYSD_PATH_ROOTED;
				break;
			}
			if (!up)
				break;
			/* Continue from the dentry this mount sits on, in the parent mount. */
			dent = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = up;
			root = BPF_CORE_READ(up, mnt.mnt_root);
			continue;
		}
		n = bpf_probe_read_kernel_str(&buf->bytes[at], PATH_BYTES - at,
					      BPF_CORE_READ(dent, d_name.name));
		/* A name that fills the buffer may be cut: drop it. */
		if (n <= 0 || off + n >= PATH_BYTES)
			break;
		off += n;
		parent = BPF_CORE_READ(dent, d_parent);
		if (parent == dent) {
			/* A root that is not a mount's: pseudo filesystems (anon inodes, pipes). */
			flags = 0;
			break;
		}
		dent = parent;
	}
	d->flags |= flags;
	d->path_len = off;
	if (off)
		bpf_probe_read_kernel(d->path, sizeof(d->path), buf->bytes);
}

/*
 * Describes the syscall `t` is blocking in: its descriptor (type, identity, socket peer,
 * filesystem, path) and, for connect, the target address. Runs once per syscall, at its first
 * switch-out, where current is still the blocking task, so its files and user memory are at
 * hand.
 */
static __always_inline void describe_blocked(struct task_state *t)
{
	u32 nr = t->sys.nr, *flags = bpf_map_lookup_elem(&sys_flags, &nr), want;
	struct file *f;

	t->detail.flags = SYSD_DESCRIBED;
	t->detail.magic = 0;
	t->detail.path_len = 0;
	if (!flags || !*flags)
		return;
	want = *flags;
	clear_sys(&t->sys);
	t->sys.nr = nr;
	if (want & SYSF_FD0) {
		t->sys.fd = t->detail.args[0];
		f = describe_fd(&t->sys, t->sys.fd);
		if (f) {
			u32 mode = t->sys.mode;

			t->detail.magic = BPF_CORE_READ(f, f_inode, i_sb, s_magic);
			if (mode == S_IFREG || mode == S_IFDIR || mode == S_IFBLK ||
			    t->detail.magic == ANON_INODE_FS_MAGIC)
				capture_path(&t->detail, f);
		}
	}
	if (want & SYSF_SOCKADDR)
		describe_sockaddr(&t->sys, (const void *)t->detail.args[1], t->detail.args[2]);
}

/* Creates (or resets) the `tasks` entry of `tid`, with a segment open from `now`. */
static __always_inline struct task_state *new_task(u32 tid, u32 tgid, u32 state, u64 now)
{
	u32 zero = 0;
	struct task_state *t, *tmpl = bpf_map_lookup_elem(&task_zero, &zero);

	if (!tmpl)
		return 0;
	if (bpf_map_update_elem(&tasks, &tid, tmpl, BPF_ANY)) {
		stat_inc(STAT_TASKS_FULL);
		return 0;
	}
	t = bpf_map_lookup_elem(&tasks, &tid);
	if (!t)
		return 0;
	t->seg.start = now;
	t->last_ts = now;
	t->state = state;
	t->tgid = tgid;
	clear_sys(&t->sys);
	clear_sys(&t->ready);
	clear_sys(&t->fault);
	return t;
}

/* ---- scheduler ---------------------------------------------------------------------- */

/* Called as the thread blocks: what the episode needs that is only known now. */
static __always_inline void note_block(struct task_state *p)
{
	p->wake_ts = 0;
	p->waker_tid = 0;
	p->waker_tgid = 0;
	__builtin_memset(p->waker_comm, 0, sizeof(p->waker_comm));
	p->has_ready = 0;
	if (p->in_fault) {
		/* The vma's file is held while the fault waits on its pages; the reads are probe
		 * reads in any case. */
		clear_sys(&p->fault);
		if (p->fault_file)
			describe_file(&p->fault, (struct file *)p->fault_file);
	}
}

/* A preempted (or new) thread gets the CPU back after `waited` ns: keep the longest such
 * wait of the segment and who held the CPU meanwhile. */
static __always_inline void note_preemption(struct task_state *n, struct task_struct *prev,
					    u64 waited)
{
	if (waited <= n->seg.preempt_max_ns)
		return;
	n->seg.preempt_max_ns = waited;
	if (n->pend_comm[0]) {
		n->seg.preempt_tgid = n->pend_tgid;
		__builtin_memcpy(n->seg.preempt_comm, n->pend_comm, sizeof(n->pend_comm));
	} else {
		/* Never preempted: a new task waiting for its first run. */
		n->seg.preempt_tgid = prev->tgid;
		__builtin_memcpy(n->seg.preempt_comm, prev->comm, sizeof(n->pend_comm));
	}
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next,
	     unsigned int prev_state)
{
	u32 ptid = prev->pid, ntid = next->pid;
	struct task_state *p = 0, *n = 0;
	u64 now;

	/* pid 0 is a per-CPU idle task, never tracked. */
	if (ptid)
		p = bpf_map_lookup_elem(&tasks, &ptid);
	if (ntid)
		n = bpf_map_lookup_elem(&tasks, &ntid);
	/* Separate tests: clang folds `!p && !n` into `p | n`, which the verifier rejects. */
	if (p)
		now = bpf_ktime_get_ns();
	else if (n)
		now = bpf_ktime_get_ns();
	else
		return 0;

	if (p) {
		if (p->state == ST_RUNNING)
			p->seg.run_ns += now - p->last_ts;
		p->last_ts = now;
		if (!preempt && prev_state != TASK_RUNNING) {
			p->state = ST_BLOCKED;
			p->block_ts = now;
			p->block_state = prev_state;
			note_block(p);
			if (p->sys.nr != NR_NONE && !(p->detail.flags & SYSD_DESCRIBED))
				describe_blocked(p);
#ifdef WHYTIME_STACKS
			/* `current` is still `prev`: its stacks are where it blocked. */
			p->stack_gen = stack_generation();
			p->user_stack = stack_ref(ctx, p->stack_gen, BPF_F_USER_STACK, ptid, p->tgid, now);
			p->kernel_stack = stack_ref(ctx, p->stack_gen, 0, ptid, p->tgid, now);
#endif
		} else {
			p->state = ST_RUNNABLE;
			/* `next` holds the CPU while this thread waits for it. */
			p->pend_tgid = next->tgid;
			__builtin_memcpy(p->pend_comm, next->comm, sizeof(p->pend_comm));
		}
	}

	if (n) {
		if (n->state == ST_RUNNABLE) {
			n->seg.rq_ns += now - n->last_ts;
			note_preemption(n, prev, now - n->last_ts);
		} else if (n->state == ST_BLOCKED || n->state == ST_WOKEN) {
			struct episode_record *e = reserve(sizeof(*e));

			if (e) {
				fill_hdr(&e->hdr, EV_EPISODE, ntid, n->tgid, now);
				e->seg = n->seg;
				e->block_ts = n->block_ts;
				e->wake_ts = n->wake_ts;
				e->sys = n->sys;
				e->waker_tid = n->waker_tid;
				e->waker_tgid = n->waker_tgid;
				e->block_state = n->block_state;
				e->_pad = 0;
				e->detail = n->detail;
				/* in_fault cannot change while blocked: it says where it blocked. */
				e->flags = (n->in_fault ? EPF_FAULT : 0) | (n->has_ready ? EPF_READY : 0);
				e->run_holder_tgid = prev->tgid;
				__builtin_memcpy(e->run_holder_comm, prev->comm, sizeof(e->run_holder_comm));
				__builtin_memcpy(e->waker_comm, n->waker_comm, sizeof(e->waker_comm));
				e->ready = n->ready;
				e->fault = n->fault;
				e->user_stack = n->user_stack;
				e->kernel_stack = n->kernel_stack;
				e->stack_gen = n->stack_gen;
				e->_pad2 = 0;
				__builtin_memcpy(e->comm, next->comm, sizeof(e->comm));
				bpf_ringbuf_submit(e, 0);
			}
			close_segment(n, 0, now);
		}
		n->state = ST_RUNNING;
		n->last_ts = now;
	}
	return 0;
}

/*
 * Distance in bytes from a CPU's `runqueues` to its `__preempt_count` (x86-64) in the per-CPU
 * area; 0 when unknown. Every CPU's copy of the per-CPU variables has the same layout, so user
 * space computes it from the offsets in the kernel BTF's `.data..percpu` section.
 */
const volatile s64 preempt_count_from_rq = 0;

/* preempt_count bits: NMI, hardirq nesting, and "serving a softirq". */
#define NMI_MASK 0x00f00000
#define HARDIRQ_MASK 0x000f0000
#define SOFTIRQ_OFFSET 0x00000100

/*
 * True when the wakeup runs in hardirq, softirq or NMI context, where `current` is just the
 * interrupted task (or the CPU's ksoftirqd). preempt_count says so. arm64 and riscv keep it
 * in thread_info. x86-64 keeps it in the per-CPU `__preempt_count`, which BPF could address
 * as a __ksym, but aya cannot load those; instead this CPU's run queue (`current`'s CFS run
 * queue's `rq`, confirmed by rq->curr == current) plus the distance user space found in BTF.
 * When neither works (no BTF offsets, no CONFIG_FAIR_GROUP_SCHED) the answer is false and
 * the waker is `current`, as before.
 */
static __always_inline bool in_interrupt_context(struct task_struct *cur)
{
	int count = 0;

	if (bpf_core_field_exists(cur->thread_info.preempt_count)) {
		count = BPF_CORE_READ(cur, thread_info.preempt_count);
	} else if (preempt_count_from_rq && bpf_core_field_exists(cur->se.cfs_rq)) {
		struct rq *rq = BPF_CORE_READ(cur, se.cfs_rq, rq);

		if (!rq || BPF_CORE_READ(rq, curr) != cur)
			return false;
		if (bpf_probe_read_kernel(&count, sizeof(count), (void *)rq + preempt_count_from_rq))
			return false;
	}
	return count & (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_OFFSET);
}

SEC("tp_btf/sched_waking")
int BPF_PROG(on_waking, struct task_struct *p)
{
	u32 tid = p->pid, waker_tgid;
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);
	struct task_struct *cur;

	if (!t || t->state != ST_BLOCKED)
		return 0;
	t->wake_ts = bpf_ktime_get_ns();
	t->state = ST_WOKEN;
	/* The waker stays 0/0 (cleared at block) when raised from interrupt context. */
	cur = bpf_get_current_task_btf();
	if (in_interrupt_context(cur))
		return 0;
	waker_tgid = cur->tgid;
	t->waker_tid = cur->pid;
	t->waker_tgid = waker_tgid;
	/* A tracked process leaves `tracked` before its exit wakes its parent: exiting wakers
	 * are not named. */
	if (waker_tgid && !(cur->flags & PF_EXITING) &&
	    !bpf_map_lookup_elem(&tracked, &waker_tgid))
		__builtin_memcpy(t->waker_comm, cur->comm, sizeof(t->waker_comm));
	return 0;
}

/* ---- process lifecycle -------------------------------------------------------------- */

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	u32 ptgid = parent->tgid, ctid = child->pid, ctgid = child->tgid, one = 1;
	struct fork_record *e;
	u64 now;

	if (!bpf_map_lookup_elem(&tracked, &ptgid))
		return 0;
	if (ctgid != ptgid && bpf_map_update_elem(&tracked, &ctgid, &one, BPF_ANY))
		stat_inc(STAT_TRACKED_FULL);

	now = bpf_ktime_get_ns();
	/* A new task is runnable until it first gets a CPU. */
	new_task(ctid, ctgid, ST_RUNNABLE, now);

	e = reserve(sizeof(*e));
	if (!e)
		return 0;
	fill_hdr(&e->hdr, EV_FORK, parent->pid, ptgid, now);
	e->child_tid = ctid;
	e->child_tgid = ctgid;
	e->child_start = child->start_boottime;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	u32 tgid = p->tgid, tid = p->pid, old = old_pid;
	struct task_state *t;
	struct exec_record *e;
	unsigned long arg_start, arg_end;
	u64 now, len;

	if (!bpf_map_lookup_elem(&tracked, &tgid))
		return 0;
	now = bpf_ktime_get_ns();

	t = bpf_map_lookup_elem(&tasks, &tid);
	if (!t && old != tid) {
		/* A non-leader thread exec'd and took over the leader's tid. */
		struct task_state *prev = bpf_map_lookup_elem(&tasks, &old);

		if (prev) {
			if (bpf_map_update_elem(&tasks, &tid, prev, BPF_ANY))
				stat_inc(STAT_TASKS_FULL);
			else
				t = bpf_map_lookup_elem(&tasks, &tid);
			bpf_map_delete_elem(&tasks, &old);
		}
	}
	if (!t) {
		/* The wrapped command's first exec: its timeline starts here, on-CPU. */
		t = new_task(tid, tgid, ST_RUNNING, now);
		if (!t)
			return 0;
	} else if (t->state == ST_RUNNING) {
		t->seg.run_ns += now - t->last_ts;
		t->last_ts = now;
	}

	e = reserve(sizeof(*e));
	if (!e) {
		close_segment(t, 0, now);
		return 0;
	}
	fill_hdr(&e->hdr, EV_EXEC, tid, tgid, now);
	close_segment(t, &e->seg, now);
	e->start = BPF_CORE_READ(p, group_leader, start_boottime);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->old_tid = old;
	__builtin_memcpy(e->comm, p->comm, sizeof(e->comm));
	e->_pad = 0;
	e->argv_len = 0;
	arg_start = BPF_CORE_READ(p, mm, arg_start);
	arg_end = BPF_CORE_READ(p, mm, arg_end);
	len = arg_end - arg_start;
	if (len > sizeof(e->argv))
		len = sizeof(e->argv);
	if (arg_end > arg_start && bpf_probe_read_user(e->argv, len, (void *)arg_start) == 0)
		e->argv_len = len;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	u32 tid = p->pid, tgid = p->tgid;
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);
	struct exit_record *e;
	/* do_exit decrements signal->live before this tracepoint on every kernel; reading it
	 * avoids depending on the tracepoint's group_dead argument (added in 6.x). */
	int live = BPF_CORE_READ(p, signal, live.counter);
	u64 now;

	if (!t)
		return 0;
	now = bpf_ktime_get_ns();
	if (t->state == ST_RUNNING)
		t->seg.run_ns += now - t->last_ts;

	e = reserve(sizeof(*e));
	if (e) {
		fill_hdr(&e->hdr, EV_EXIT, tid, tgid, now);
		e->seg = t->seg;
		e->start = BPF_CORE_READ(p, group_leader, start_boottime);
		e->code = p->exit_code;
		e->group_dead = live == 0;
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&tasks, &tid);
	if (live == 0)
		bpf_map_delete_elem(&tracked, &tgid);
	return 0;
}

/* ---- syscalls ----------------------------------------------------------------------- */


SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long id)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);

	if (!t)
		return 0;
	/* Runs on every syscall: keep only what a later block needs, describe nothing. */
	t->sys.nr = id;
	t->detail.flags = 0;
	t->detail.args[0] = PT_REGS_PARM1_SYSCALL(regs);
	t->detail.args[1] = PT_REGS_PARM2_SYSCALL(regs);
	t->detail.args[2] = PT_REGS_PARM3_SYSCALL(regs);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);

	if (t)
		t->sys.nr = NR_NONE;
	return 0;
}

/* ---- readiness: which file ended a poll/select/epoll wait --------------------------- */

/* The state of `task` if it is tracked, blocked, and has no readiness source yet. */
static __always_inline struct task_state *blocked_poller(struct task_struct *task)
{
	u32 tid = BPF_CORE_READ(task, pid);
	struct task_state *t;

	if (!tid)
		return 0;
	t = bpf_map_lookup_elem(&tasks, &tid);
	if (!t || t->state != ST_BLOCKED || t->has_ready)
		return 0;
	return t;
}

/* `f` (descriptor `fd`, -1 if unknown) is about to wake the blocked thread `t`. The wakeup
 * follows synchronously; the first source claims the slot. */
static __always_inline void note_ready(struct task_state *t, struct file *f, int fd)
{
	if (__sync_val_compare_and_swap(&t->has_ready, 0, 1))
		return;
	clear_sys(&t->ready);
	t->ready.fd = fd;
	describe_file(&t->ready, f);
}

/* poll/select: one wait entry per polled file; `wait->private` is the poller's
 * poll_wqueues. */
SEC("fentry/pollwake")
int BPF_PROG(on_pollwake, struct wait_queue_entry *wait, unsigned int mode, int sync, void *key)
{
	struct poll_table_entry *entry = container_of(wait, struct poll_table_entry, wait);
	struct poll_wqueues *pwq = BPF_CORE_READ(wait, private);
	__poll_t events = (__poll_t)(unsigned long)key;
	struct task_state *t = blocked_poller(BPF_CORE_READ(pwq, polling_task));

	if (!t)
		return 0;
	/* pollwake ignores events the poller did not ask for. */
	if (events && !(events & BPF_CORE_READ(entry, key)))
		return 0;
	note_ready(t, BPF_CORE_READ(entry, filp), -1);
	return 0;
}

/* epoll: `wait` hangs off a watched file; the callback queues the item on its eventpoll and
 * wakes the first thread in epoll_wait on it (ep->wq waiters are exclusive). */
SEC("fentry/ep_poll_callback")
int BPF_PROG(on_ep_poll_callback, struct wait_queue_entry *wait, unsigned int mode, int sync,
	     void *key)
{
	struct eppoll_entry *pwq = container_of(wait, struct eppoll_entry, wait);
	struct epitem *epi = BPF_CORE_READ(pwq, base);
	struct eventpoll *ep = BPF_CORE_READ(epi, ep);
	struct list_head *first = BPF_CORE_READ(ep, wq.head.next);
	__poll_t events = (__poll_t)(unsigned long)key, want;
	struct wait_queue_entry *waiter;
	struct task_state *t;

	if (!first || first == &ep->wq.head)
		return 0;
	waiter = container_of(first, struct wait_queue_entry, entry);
	t = blocked_poller(BPF_CORE_READ(waiter, private));
	if (!t)
		return 0;
	/* Same filters as ep_poll_callback: disabled items and unwanted events wake nobody. */
	want = BPF_CORE_READ(epi, event.events);
	if (!(want & ~EP_PRIVATE_BITS) || (events && !(events & want)))
		return 0;
	note_ready(t, BPF_CORE_READ(epi, ffd.file), BPF_CORE_READ(epi, ffd.fd));
	return 0;
}

/* ---- page faults -------------------------------------------------------------------- */

/* Marks the thread as in a fault until fexit; a block meanwhile is described as the fault's
 * (note_block). handle_mm_fault also serves faults taken inside syscalls (copy_to_user). */
SEC("fentry/handle_mm_fault")
int BPF_PROG(on_fault_enter, struct vm_area_struct *vma)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);

	if (!t)
		return 0;
	t->fault_file = (u64)BPF_CORE_READ(vma, vm_file);
	t->in_fault = 1;
	return 0;
}

SEC("fexit/handle_mm_fault")
int BPF_PROG(on_fault_exit)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);

	if (t)
		t->in_fault = 0;
	return 0;
}

#ifdef WHYTIME_STACKS
/* ---- on-CPU stack sampling ---------------------------------------------------------- */

/* CPU-clock sampler, one perf event per CPU (SAMPLE_HZ). Runs in the timer interrupt:
 * `current` is the interrupted task, and its user stack comes from the registers saved at its
 * last kernel entry. The stacks are taken before the record is reserved, so a STACK record
 * holding a copy precedes the sample in the ring. */
SEC("perf_event")
int on_sample(void *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id, tgid, gen;
	struct task_state *t;
	struct sample_record *e;
	s32 user, kernel;
	u64 now;

	if (!tid)
		return 0;
	t = bpf_map_lookup_elem(&tasks, &tid);
	if (!t)
		return 0;
	tgid = t->tgid;
	now = bpf_ktime_get_ns();
	gen = stack_generation();
	user = stack_ref(ctx, gen, BPF_F_USER_STACK, tid, tgid, now);
	kernel = stack_ref(ctx, gen, 0, tid, tgid, now);
	e = reserve(sizeof(*e));
	if (!e)
		return 0;
	fill_hdr(&e->hdr, EV_SAMPLE, tid, tgid, now);
	e->user_stack = user;
	e->kernel_stack = kernel;
	e->stack_gen = gen;
	e->_pad = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
#endif
