// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 CTERA Networks
//
// Trace FUSE requests slower than a threshold, with wait/process split.
//
// For synchronous FUSE daemons (libfuse), fuse_request_end is called by
// the daemon thread that processed the request.  We record the timestamp
// when that thread returned from fuse_dev_do_read (i.e. took a request
// off the queue) and use it to split total latency into:
//
//   wait_ns    = dequeue_ts - q_ts   (time in fiq->pending queue)
//   process_ns = r_ts - dequeue_ts   (time being processed by daemon)
//
// If the current task at fuse_request_end is not a known daemon thread
// (async/background requests), has_split is set to 0 and only the total
// latency is reported.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fuseqslower.h"

#define FUSE_MINOR_BITS	20
#define FUSE_MINOR(dev)	((unsigned int)((dev) & ((1U << FUSE_MINOR_BITS) - 1)))

#define MAX_ENTRIES	10240
#define MAX_DAEMONS	1024

/*
 * Minimal FUSE struct definitions with CO-RE relocations.
 * Offsets are resolved at load time from the running kernel's BTF.
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

struct fuse_out_header {
	__u32	len;
	__s32	error;
	__u64	unique;
} __attribute__((preserve_access_index));

struct fuse_conn {
	dev_t	dev;
} __attribute__((preserve_access_index));

struct fuse_mount {
	struct fuse_conn *fc;
} __attribute__((preserve_access_index));

struct fuse_req {
	struct {
		struct fuse_in_header h;
	} in;
	struct {
		struct fuse_out_header h;
	} out;
	struct fuse_mount *fm;
} __attribute__((preserve_access_index));

struct fuse_dev {
	struct fuse_conn *fc;
} __attribute__((preserve_access_index));

/* ------------------------------------------------------------------ */

const volatile pid_t	target_pid     = 0;
const volatile __u32	target_connid  = 0;
/* Exactly one of these will be non-zero, selected by -w / -r / positional. */
const volatile __u64	min_lat_ns     = 0;  /* default: filter by total */
const volatile __u64	min_wait_ns    = 0;  /* -w: filter by wait time */
const volatile __u64	min_process_ns = 0;  /* -r: filter by process time */

/* enqueue_args: tid -> req pointer */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} enqueue_args SEC(".maps");

/* pending: req pointer -> {q_ts, opcode, pid, conn_id, comm} */
struct pending_info {
	__u64 ts_ns;
	__u32 opcode;
	__u32 pid;
	__u32 conn_id;
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct pending_info);
} pending SEC(".maps");

/*
 * dequeue_ts: daemon tid -> timestamp when fuse_dev_do_read last returned.
 * Used to split total latency into wait (Q→D) and process (D→R) times.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DAEMONS);
	__type(key, u64);
	__type(value, u64);
} dequeue_ts SEC(".maps");

/* dequeue_args: tid -> fud pointer (for kprobe/kretprobe correlation) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DAEMONS);
	__type(key, u64);
	__type(value, u64);
} dequeue_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* ------------------------------------------------------------------ */

/*
 * fuse_dev_queue_req(struct fuse_iqueue *fiq, struct fuse_req *req)
 * Entry: stash req pointer (PARM2) for the kretprobe.
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
 * Record request in the pending map for latency measurement at response time.
 */
SEC("kretprobe/fuse_dev_queue_req")
int BPF_KRETPROBE(fuse_dev_queue_req_exit)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 *req_ptrp, req_ptr;
	struct fuse_req *req;
	struct pending_info pi = {};
	u32 pid, conn_id;
	dev_t dev;

	req_ptrp = bpf_map_lookup_elem(&enqueue_args, &tid);
	if (!req_ptrp)
		return 0;
	req_ptr = *req_ptrp;
	bpf_map_delete_elem(&enqueue_args, &tid);

	req = (struct fuse_req *)req_ptr;
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

	pi.ts_ns   = bpf_ktime_get_ns();
	pi.opcode  = BPF_CORE_READ(req, in.h.opcode);
	pi.pid     = pid;
	pi.conn_id = conn_id;
	bpf_get_current_comm(&pi.comm, sizeof(pi.comm));
	bpf_map_update_elem(&pending, &req_ptr, &pi, BPF_ANY);
	return 0;
}

/* ------------------------------------------------------------------ */

/*
 * Track when daemon threads finish reading a request (dequeue time).
 * fuse_dev_do_read(struct fuse_dev *fud, ...)
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
	u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&dequeue_args, &pid_tgid);

	if (ret <= 0)
		return 0;

	/* Record this daemon thread's dequeue timestamp. */
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&dequeue_ts, &pid_tgid, &ts, BPF_ANY);
	return 0;
}

/* ------------------------------------------------------------------ */

/*
 * fuse_request_end(struct fuse_req *req)
 * Look up the pending entry; emit event only if Q->R latency >= min_lat_ns.
 */
SEC("kprobe/fuse_request_end")
int BPF_KPROBE(fuse_request_end_entry)
{
	u64 req_ptr = PT_REGS_PARM1_CORE(ctx);
	struct fuse_req *req = (struct fuse_req *)req_ptr;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_info *pip;
	struct event e = {};
	u64 now, total;

	pip = bpf_map_lookup_elem(&pending, &req_ptr);
	if (!pip)
		return 0;

	now   = bpf_ktime_get_ns();
	total = now - pip->ts_ns;

	e.ts_ns   = now;
	e.unique  = BPF_CORE_READ(req, in.h.unique);
	e.opcode  = pip->opcode;
	e.pid     = pip->pid;
	e.conn_id = pip->conn_id;
	e.error   = BPF_CORE_READ(req, out.h.error);
	__builtin_memcpy(e.comm, pip->comm, sizeof(e.comm));

	/*
	 * For synchronous requests, the current task is the daemon thread
	 * that processed this request.  Look up when it last dequeued.
	 */
	u64 *d_tsp = bpf_map_lookup_elem(&dequeue_ts, &pid_tgid);
	if (d_tsp && *d_tsp >= pip->ts_ns && *d_tsp <= now) {
		e.wait_ns    = *d_tsp - pip->ts_ns;
		e.process_ns = now - *d_tsp;
		e.has_split  = 1;
	} else {
		/* Async/background: total only, split unavailable */
		e.wait_ns    = total;
		e.process_ns = 0;
		e.has_split  = 0;
	}

	/*
	 * Apply threshold.  For -w/-r modes fall back to total when the
	 * split is unavailable (has_split == 0), so async requests are
	 * still surfaced when they exceed the total latency.
	 */
	if (min_wait_ns) {
		u64 cmp = e.has_split ? e.wait_ns : total;
		if (cmp < min_wait_ns)
			goto out_delete;
	} else if (min_process_ns) {
		u64 cmp = e.has_split ? e.process_ns : total;
		if (cmp < min_process_ns)
			goto out_delete;
	} else {
		if (total < min_lat_ns)
			goto out_delete;
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

out_delete:
	bpf_map_delete_elem(&pending, &req_ptr);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
