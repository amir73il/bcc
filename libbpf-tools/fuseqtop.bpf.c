// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 CTERA Networks
//
// Maintain in-flight FUSE request state for fuseqtop.
//
// Three maps are maintained for userspace to poll periodically:
//   in_flight:         req_ptr -> req_info  (all requests, Q state until R)
//   workers:           pid_tgid -> worker_info  (daemon threads in D state)
//   conn_pending_head: conn_id -> head_unique  (Q/D watermark)
//
// Q/D classification (watermark approach):
//   At fuse_dev_read/fuse_dev_do_read exit, the daemon has just dequeued a
//   request and fiq->pending now reflects the updated queue.  We peek at
//   pending.next to read the unique ID of the OLDEST remaining queued request
//   (the "watermark").  Any in_flight request with unique < watermark has
//   already been dequeued (D state).  If the queue is empty, all in_flight
//   requests are in D state (watermark stored as 0).
//
//   Userspace reads conn_pending_head[conn_id] and classifies each in_flight
//   entry accordingly.  D timestamps are maintained in userspace between
//   polling intervals; see fuseqtop.c display_snapshot().
//
// First-dequeue limitation:
//   Daemon threads that were already blocking in fuse_dev_read when the probe
//   was attached miss their first return (kretprobe "first call" limitation).
//   Until those threads complete one full cycle, their dequeues are invisible
//   and affected requests remain classified as Q.  This is a startup artifact
//   only; a kernel fuse_request_dequeue tracepoint would eliminate it.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fuseqtop.h"

#define FUSE_MINOR_BITS	20
#define FUSE_MINOR(dev)	((unsigned int)((dev) & ((1U << FUSE_MINOR_BITS) - 1)))

#define MAX_ENTRIES	10240
#define MAX_DAEMONS	1024

/*
 * Minimal FUSE struct definitions with CO-RE relocations.
 * Field names must match the kernel; offsets are resolved from BTF at load.
 */
struct fuse_in_header {
	__u32	len;
	__u32	opcode;
	__u64	unique;
	__u64	nodeid;
	__u32	uid;
	__u32	gid;
	__u32	pid;
	__u16	total_extlen;
	__u16	padding;
} __attribute__((preserve_access_index));

struct fuse_iqueue {
	struct list_head pending;
} __attribute__((preserve_access_index));

struct fuse_conn {
	dev_t		dev;
	struct fuse_iqueue iq;
} __attribute__((preserve_access_index));

struct fuse_mount {
	struct fuse_conn *fc;
} __attribute__((preserve_access_index));

struct fuse_req {
	struct list_head list;	/* must be first — cast from list_head * is safe */
	struct list_head intr_entry;
	struct {
		struct fuse_in_header h;
	} in;
	struct fuse_mount *fm;
} __attribute__((preserve_access_index));

struct fuse_dev {
	struct fuse_conn *fc;
} __attribute__((preserve_access_index));

/* ------------------------------------------------------------------ */

const volatile pid_t	target_pid    = 0;
const volatile __u32	target_connid = 0;

/* enqueue_args: tid -> req_ptr (fuse_dev_queue_req entry -> exit) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} enqueue_args SEC(".maps");

/* dequeue_args: tid -> fud_ptr (fuse_dev_read entry -> exit) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DAEMONS);
	__type(key, u64);
	__type(value, u64);
} dequeue_args SEC(".maps");

/* in_flight: req_ptr -> req_info (Q state until R) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct req_info);
} in_flight SEC(".maps");

/* workers: pid_tgid -> worker_info (D state until R) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DAEMONS);
	__type(key, u64);
	__type(value, struct worker_info);
} workers SEC(".maps");

/*
 * conn_pending_head: conn_id -> struct watermark
 *   head_unique == 0  = pending queue was empty (all in_flight are D)
 *   head_unique == N  = oldest pending unique; in_flight with unique < N are D
 * Missing key         = no dequeue observed yet; treat all as Q
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, struct watermark);
} conn_pending_head SEC(".maps");

/* ------------------------------------------------------------------ */

/*
 * fuse_dev_queue_req(struct fuse_iqueue *fiq, struct fuse_req *req)
 * Entry: stash req_ptr for the kretprobe.
 */
SEC("kprobe/fuse_dev_queue_req")
int BPF_KPROBE(fuse_dev_queue_req_entry)
{
	u64 tid     = bpf_get_current_pid_tgid();
	u64 req_ptr = PT_REGS_PARM2_CORE(ctx);

	bpf_map_update_elem(&enqueue_args, &tid, &req_ptr, BPF_ANY);
	return 0;
}

/*
 * fuse_dev_queue_req exit: unique ID has been assigned.
 * Insert request into in_flight (Q state).
 */
SEC("kretprobe/fuse_dev_queue_req")
int BPF_KRETPROBE(fuse_dev_queue_req_exit)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 *req_ptrp, req_ptr;
	struct fuse_req *req;
	struct req_info ri = {};
	u32 pid, conn_id;
	dev_t dev;

	req_ptrp = bpf_map_lookup_elem(&enqueue_args, &tid);
	if (!req_ptrp)
		return 0;
	req_ptr = *req_ptrp;
	bpf_map_delete_elem(&enqueue_args, &tid);

	req = (struct fuse_req *)req_ptr;

	/* unique is 0 for FUSE_NOTIFY_REPLY or disconnected fiq */
	if (!BPF_CORE_READ(req, in.h.unique))
		return 0;

	pid = BPF_CORE_READ(req, in.h.pid);
	if (!pid)
		pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	dev     = BPF_CORE_READ(req, fm, fc, dev);
	conn_id = FUSE_MINOR(dev);

	if (target_pid && pid != (u32)target_pid)
		return 0;
	if (target_connid && conn_id != target_connid)
		return 0;

	ri.q_ts    = bpf_ktime_get_ns();
	ri.unique  = BPF_CORE_READ(req, in.h.unique);
	ri.opcode  = BPF_CORE_READ(req, in.h.opcode);
	ri.pid     = pid;
	ri.conn_id = conn_id;
	bpf_get_current_comm(&ri.comm, sizeof(ri.comm));
	bpf_map_update_elem(&in_flight, &req_ptr, &ri, BPF_ANY);
	return 0;
}

/* ------------------------------------------------------------------ */

/*
 * Peek at fiq->pending to compute the Q/D watermark, then record this
 * daemon thread as an active worker.
 *
 * fuse_req.list is the first field (offset 0), so casting list_head * to
 * fuse_req * is safe.  The peek is lock-free and racy; transient inaccuracies
 * (one refresh interval) are acceptable for a display tool.
 *
 * Empty queue detection: for a Linux circular doubly-linked list, the
 * sentinel head's next pointer equals itself when the list is empty.
 */
static __always_inline void
handle_dequeue_exit(struct fuse_dev *fud, u64 tid, u64 now)
{
	struct fuse_conn *fc = BPF_CORE_READ(fud, fc);
	dev_t dev            = BPF_CORE_READ(fc, dev);
	u32 conn_id          = FUSE_MINOR(dev);
	struct list_head *next_lh, *next_next;
	u64 head_unique;
	struct worker_info wi = {};

	/* Peek at the pending queue head. */
	next_lh  = BPF_CORE_READ(fc, iq.pending.next);
	next_next = BPF_CORE_READ(next_lh, next);

	if ((u64)next_next == (u64)next_lh) {
		/* Queue empty: all in_flight requests are in D state. */
		head_unique = 0;
	} else {
		/* Cast is safe: fuse_req.list is at offset 0. */
		head_unique = BPF_CORE_READ((struct fuse_req *)next_lh,
					    in.h.unique);
	}
	{
		struct watermark wm = { .head_unique = head_unique, .ts = now };

		bpf_map_update_elem(&conn_pending_head, &conn_id, &wm, BPF_ANY);
	}

	/* Record this daemon thread as an active worker. */
	wi.d_ts    = now;
	wi.conn_id = conn_id;
	wi.tid     = (u32)tid;
	bpf_get_current_comm(&wi.comm, sizeof(wi.comm));
	bpf_map_update_elem(&workers, &tid, &wi, BPF_ANY);
}

/*
 * fuse_dev_do_read(struct fuse_dev *fud, ...)
 * Splice() read path.  fud is PARM1.
 */
SEC("kprobe/fuse_dev_do_read")
int BPF_KPROBE(fuse_dev_do_read_entry)
{
	u64 tid     = bpf_get_current_pid_tgid();
	u64 fud_ptr = PT_REGS_PARM1_CORE(ctx);

	bpf_map_update_elem(&dequeue_args, &tid, &fud_ptr, BPF_ANY);
	return 0;
}

SEC("kretprobe/fuse_dev_do_read")
int BPF_KRETPROBE(fuse_dev_do_read_exit, ssize_t ret)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 *fud_ptrp;

	fud_ptrp = bpf_map_lookup_elem(&dequeue_args, &tid);
	if (!fud_ptrp)
		return 0;
	struct fuse_dev *fud = (struct fuse_dev *)*fud_ptrp;
	bpf_map_delete_elem(&dequeue_args, &tid);

	if (ret <= 0)
		return 0;

	handle_dequeue_exit(fud, tid, bpf_ktime_get_ns());
	return 0;
}

/*
 * fuse_dev_read(struct kiocb *iocb, struct iov_iter *to)
 * Regular read() path.  fud recovered from iocb->ki_filp->private_data.
 *
 * If fuse_dev_do_read is not inlined (constprop variant fired first), the
 * inner exit already deleted dequeue_args[tid]; this outer exit finds nothing
 * and returns, preventing double updates.
 */
SEC("kprobe/fuse_dev_read")
int BPF_KPROBE(fuse_dev_read_entry)
{
	u64 tid = bpf_get_current_pid_tgid();
	struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1_CORE(ctx);
	u64 fud_ptr =
		(u64)BPF_CORE_READ(iocb, ki_filp, private_data);

	bpf_map_update_elem(&dequeue_args, &tid, &fud_ptr, BPF_ANY);
	return 0;
}

SEC("kretprobe/fuse_dev_read")
int BPF_KRETPROBE(fuse_dev_read_exit, ssize_t ret)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 *fud_ptrp;

	fud_ptrp = bpf_map_lookup_elem(&dequeue_args, &tid);
	if (!fud_ptrp)
		return 0;
	struct fuse_dev *fud = (struct fuse_dev *)*fud_ptrp;
	bpf_map_delete_elem(&dequeue_args, &tid);

	if (ret <= 0)
		return 0;

	handle_dequeue_exit(fud, tid, bpf_ktime_get_ns());
	return 0;
}

/* ------------------------------------------------------------------ */

/*
 * fuse_request_end(struct fuse_req *req)
 * Request completed: remove from in_flight and workers.
 */
SEC("kprobe/fuse_request_end")
int BPF_KPROBE(fuse_request_end_entry)
{
	u64 req_ptr = PT_REGS_PARM1_CORE(ctx);
	u64 tid     = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&in_flight, &req_ptr);
	bpf_map_delete_elem(&workers, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
