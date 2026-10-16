// SPDX-License-Identifier: MIT
/*
 * whytime kernel side: per-thread off-CPU episodes for one process tree.
 *
 * Membership is by lineage: user space puts the wrapped command's tgid in `tracked`, and
 * sched_process_fork adds every child process of a tracked one (in kernel, so a child can
 * never run untracked). Each tracked thread has a `tasks` entry holding its open accounting
 * segment. sched_switch accumulates on-CPU and preempted-runqueue time in place, so a
 * CPU-bound thread produces no records; one EPISODE record is emitted per block -> wake -> run
 * cycle, when the thread runs again. sys_enter/sys_exit remember the syscall in flight (and
 * describe its file descriptor) so user space can say what each block waited for.
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
#define AF_INET 2
#define AF_INET6 10
#define TASK_RUNNING 0

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

/* Copies the open segment into a record and starts a new one at `now`. */
static __always_inline void close_segment(struct task_state *t, struct cpu_segment *out, u64 now)
{
	if (out)
		*out = t->seg;
	t->seg.start = now;
	t->seg.run_ns = 0;
	t->seg.rq_ns = 0;
}

static __always_inline void clear_sys(struct sys_info *s)
{
	__builtin_memset(s, 0, sizeof(*s));
	s->nr = NR_NONE;
	s->fd = -1;
}

/* ---- scheduler ---------------------------------------------------------------------- */

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
			p->wake_ts = 0;
			p->waker_tid = 0;
			p->waker_tgid = 0;
		} else {
			p->state = ST_RUNNABLE;
		}
	}

	if (n) {
		if (n->state == ST_RUNNABLE) {
			n->seg.rq_ns += now - n->last_ts;
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
				bpf_ringbuf_submit(e, 0);
			}
			close_segment(n, 0, now);
		}
		n->state = ST_RUNNING;
		n->last_ts = now;
	}
	return 0;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(on_waking, struct task_struct *p)
{
	u32 tid = p->pid;
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);
	u64 cur;

	if (!t || t->state != ST_BLOCKED)
		return 0;
	cur = bpf_get_current_pid_tgid();
	t->wake_ts = bpf_ktime_get_ns();
	t->waker_tid = (u32)cur;
	t->waker_tgid = cur >> 32;
	t->state = ST_WOKEN;
	return 0;
}

/* ---- process lifecycle -------------------------------------------------------------- */

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	u32 ptgid = parent->tgid, ctid = child->pid, ctgid = child->tgid, one = 1;
	struct task_state s = {};
	struct fork_record *e;
	u64 now;

	if (!bpf_map_lookup_elem(&tracked, &ptgid))
		return 0;
	if (ctgid != ptgid && bpf_map_update_elem(&tracked, &ctgid, &one, BPF_ANY))
		stat_inc(STAT_TRACKED_FULL);

	now = bpf_ktime_get_ns();
	/* A new task is runnable until it first gets a CPU. */
	s.seg.start = now;
	s.last_ts = now;
	s.state = ST_RUNNABLE;
	s.tgid = ctgid;
	clear_sys(&s.sys);
	if (bpf_map_update_elem(&tasks, &ctid, &s, BPF_ANY))
		stat_inc(STAT_TASKS_FULL);

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
			struct task_state moved = *prev;

			bpf_map_delete_elem(&tasks, &old);
			bpf_map_update_elem(&tasks, &tid, &moved, BPF_ANY);
			t = bpf_map_lookup_elem(&tasks, &tid);
		}
	}
	if (!t) {
		/* The wrapped command's first exec: its timeline starts here, on-CPU. */
		struct task_state s = {};

		s.seg.start = now;
		s.last_ts = now;
		s.state = ST_RUNNING;
		s.tgid = tgid;
		clear_sys(&s.sys);
		if (bpf_map_update_elem(&tasks, &tid, &s, BPF_ANY)) {
			stat_inc(STAT_TASKS_FULL);
			return 0;
		}
		t = bpf_map_lookup_elem(&tasks, &tid);
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

/* Fills inode type/identity, open flags and, for inet sockets, the peer address of `fd`. */
static __always_inline void describe_fd(struct sys_info *s, int fd)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	struct file **fds, *f = 0;
	struct inode *ino;
	struct socket *sock;
	struct sock *sk;
	unsigned int max;

	if (!fdt || fd < 0)
		return;
	max = BPF_CORE_READ(fdt, max_fds);
	if ((unsigned int)fd >= max)
		return;
	fds = BPF_CORE_READ(fdt, fd);
	if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f)
		return;
	ino = BPF_CORE_READ(f, f_inode);
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

SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long id)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_state *t = bpf_map_lookup_elem(&tasks, &tid);
	u32 nr = id, *flags;

	if (!t)
		return 0;
	clear_sys(&t->sys);
	t->sys.nr = id;
	flags = bpf_map_lookup_elem(&sys_flags, &nr);
	if (!flags || !*flags)
		return 0;
	if (*flags & SYSF_FD0) {
		int fd = PT_REGS_PARM1_CORE_SYSCALL(regs);

		t->sys.fd = fd;
		describe_fd(&t->sys, fd);
	}
	if (*flags & SYSF_SOCKADDR)
		describe_sockaddr(&t->sys, (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs),
				  PT_REGS_PARM3_CORE_SYSCALL(regs));
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
