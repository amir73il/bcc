// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 CTERA Networks
//
// Trace FUSE request lifecycle: enqueue, dequeue, and response.
//
// Two probe strategies, selected at runtime by fuseqsnoop.c:
//
// Tracepoint path (preferred, kernel with fuse_request_sent tracepoint):
//   tp/fuse/fuse_request_send  — Q event, fires on app thread after unique assigned
//   tp/fuse/fuse_request_sent  — D event, fires on daemon thread after list_del_init
//   tp/fuse/fuse_request_end   — W+R events, fires at completion
//   D events carry unique+opcode (reliable); pending/dequeue_ts keyed by unique.
//
// Kprobe path (fallback, older kernels without fuse_request_sent):
//   kprobe/kretprobe fuse_dev_queue_req  — Q event
//   kprobe/kretprobe fuse_dev_do_read    — D event (no unique at D time)
//   kprobe/kretprobe fuse_dev_read       — D event (regular read() path)
//   kprobe           fuse_request_end    — W+R events
//   pending/dequeue_ts keyed by req_ptr/pid_tgid respectively.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fuseqsnoop.h"

/*
 * MINOR(dev): lower 20 bits of dev_t.
 * Matches the directory names under /sys/fs/fuse/connections/.
 */
#define FUSE_MINOR_BITS	20
#define FUSE_MINOR(dev)	((unsigned int)((dev) & ((1U << FUSE_MINOR_BITS) - 1)))

#define MAX_ENTRIES	10240
#define MAX_DAEMONS	1024

/*
 * Minimal FUSE kernel struct definitions.
 *
 * The pre-compiled x86/vmlinux.h does not include FUSE types (FUSE may be a
 * module in the kernel that vmlinux.h was generated from).  Define just the
 * fields we access here; __attribute__((preserve_access_index)) tells the
 * compiler to emit CO-RE relocations so libbpf will fix up the actual field
 * offsets at load time using the running kernel's BTF.
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

/*
 * fuse_conn: only dev is accessed; CO-RE resolves its real offset.
 * Defining a single-field struct is enough for the relocation to work.
 */
struct fuse_conn {
	dev_t	dev;
} __attribute__((preserve_access_index));

struct fuse_mount {
	struct fuse_conn *fc;
} __attribute__((preserve_access_index));

/*
 * fuse_req: replicate the anonymous struct wrappers exactly so that
 * BPF_CORE_READ(req, in.h.unique) generates correct relocations.
 */
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

const volatile pid_t target_pid = 0;
const volatile __u32 target_connid = 0;

/*
 * enqueue_args: thread ID -> req pointer
 * Correlates kprobe/kretprobe pair for fuse_dev_queue_req so we can read
 * the unique ID (assigned inside the function) at kretprobe time.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} enqueue_args SEC(".maps");

/*
 * pending: req pointer -> request metadata
 * Holds enqueue timestamp and identifiers until fuse_request_end fires.
 */
struct pending_info {
	__u64	ts_ns;
	__u32	opcode;
	__u32	pid;
	__u32	conn_id;
	char	comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct pending_info);
} pending SEC(".maps");

/*
 * dequeue_args: thread ID -> fud pointer
 * Correlates kprobe/kretprobe pair for fuse_dev_do_read.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DAEMONS);
	__type(key, u64);
	__type(value, u64);
} dequeue_args SEC(".maps");

/*
 * dequeue_ts: daemon thread ID -> timestamp of last successful dequeue.
 * Used to split R event latency into Q→D (wait) and D→R (process) times.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DAEMONS);
	__type(key, u64);
	__type(value, u64);
} dequeue_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* ------------------------------------------------------------------ */

/*
 * fuse_dev_queue_req(struct fuse_iqueue *fiq, struct fuse_req *req)
 *
 * Entry: stash req pointer keyed by tid for the kretprobe.
 * req is PARM2 (second argument).
 */
SEC("kprobe/fuse_dev_queue_req")
int BPF_KPROBE(fuse_dev_queue_req_entry)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 req_ptr = PT_REGS_PARM2_CORE(ctx);

	bpf_map_update_elem(&enqueue_args, &tid, &req_ptr, BPF_ANY);
	return 0;
}

/*
 * fuse_dev_queue_req exit: unique ID has now been assigned.
 * Emit Q event and save in pending map for later R event correlation.
 */
SEC("kretprobe/fuse_dev_queue_req")
int BPF_KRETPROBE(fuse_dev_queue_req_exit)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 *req_ptrp, req_ptr;
	struct fuse_req *req;
	struct pending_info pi = {};
	struct event e = {};
	u32 conn_id;
	dev_t dev;

	req_ptrp = bpf_map_lookup_elem(&enqueue_args, &tid);
	if (!req_ptrp)
		return 0;
	req_ptr = *req_ptrp;
	bpf_map_delete_elem(&enqueue_args, &tid);

	req = (struct fuse_req *)req_ptr;

	/* unique is 0 for FUSE_NOTIFY_REPLY or when fiq is disconnected */
	e.unique = BPF_CORE_READ(req, in.h.unique);
	if (!e.unique)
		return 0;

	e.opcode = BPF_CORE_READ(req, in.h.opcode);
	/*
	 * Use in.h.pid from the FUSE header; fall back to the current task's
	 * tgid for operations where the kernel fills pid=0 (e.g. RELEASEDIR).
	 */
	e.pid = BPF_CORE_READ(req, in.h.pid);
	if (!e.pid)
		e.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	dev      = BPF_CORE_READ(req, fm, fc, dev);
	conn_id  = FUSE_MINOR(dev);

	if (target_pid && e.pid != (u32)target_pid)
		return 0;
	if (target_connid && conn_id != target_connid)
		return 0;

	e.ts_ns   = bpf_ktime_get_ns();
	e.conn_id = conn_id;
	e.evt     = FUSEQ_Q;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	/* Save in pending map for R event */
	pi.ts_ns   = e.ts_ns;
	pi.opcode  = e.opcode;
	pi.pid     = e.pid;
	pi.conn_id = conn_id;
	__builtin_memcpy(pi.comm, e.comm, sizeof(pi.comm));
	bpf_map_update_elem(&pending, &req_ptr, &pi, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

/* ------------------------------------------------------------------ */

/*
 * fuse_dev_do_read(struct fuse_dev *fud, struct file *file, ...)
 *
 * Entry: stash fud pointer (PARM1) keyed by tid.
 * Called in daemon context (the process reading /dev/fuse).
 */
SEC("kprobe/fuse_dev_do_read")
int BPF_KPROBE(fuse_dev_do_read_entry)
{
	u64 tid = bpf_get_current_pid_tgid();
	u64 fud_ptr = PT_REGS_PARM1_CORE(ctx);

	bpf_map_update_elem(&dequeue_args, &tid, &fud_ptr, BPF_ANY);
	return 0;
}

/*
 * fuse_dev_do_read exit: if ret > 0 a request header was successfully
 * copied to the daemon.  Emit D event showing which daemon thread dequeued.
 * Also record dequeue_ts for the Q→D / D→R split at fuse_request_end.
 */
SEC("kretprobe/fuse_dev_do_read")
int BPF_KRETPROBE(fuse_dev_do_read_exit, ssize_t ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *fud_ptrp;
	struct fuse_dev *fud;
	struct event e = {};
	u64 ts;
	dev_t dev;

	if (ret <= 0)
		goto out_clean;

	fud_ptrp = bpf_map_lookup_elem(&dequeue_args, &pid_tgid);
	if (!fud_ptrp)
		return 0;

	fud = (struct fuse_dev *)*fud_ptrp;
	dev = BPF_CORE_READ(fud, fc, dev);
	e.conn_id = FUSE_MINOR(dev);

	if (target_connid && e.conn_id != target_connid)
		goto out_clean;

	ts      = bpf_ktime_get_ns();
	e.ts_ns = ts;
	e.evt   = FUSEQ_D;
	e.pid   = (u32)(pid_tgid >> 32);
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	/* Record dequeue timestamp for Q→D / D→R split at fuse_request_end. */
	bpf_map_update_elem(&dequeue_ts, &pid_tgid, &ts, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

out_clean:
	bpf_map_delete_elem(&dequeue_args, &pid_tgid);
	return 0;
}

/*
 * fuse_dev_read(struct kiocb *iocb, struct iov_iter *to)
 *
 * Regular read() path.  GCC inlines fuse_dev_do_read here (non-constprop),
 * so no separate fuse_dev_do_read symbol exists in kallsyms for this path.
 * Probe fuse_dev_read directly to cover it.
 *
 * fud is recovered from iocb->ki_filp->private_data (same as fuse_get_dev).
 *
 * Entry: stash fud pointer keyed by tid.
 */
SEC("kprobe/fuse_dev_read")
int BPF_KPROBE(fuse_dev_read_entry)
{
	u64 tid = bpf_get_current_pid_tgid();
	struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1_CORE(ctx);
	u64 fud_ptr = (u64)BPF_CORE_READ(iocb, ki_filp, private_data);

	bpf_map_update_elem(&dequeue_args, &tid, &fud_ptr, BPF_ANY);
	return 0;
}

/*
 * Exit: if ret > 0 a request was successfully copied to the daemon.
 * Emit D event and record dequeue_ts for the Q→D / D→R split at R time.
 */
SEC("kretprobe/fuse_dev_read")
int BPF_KRETPROBE(fuse_dev_read_exit, ssize_t ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *fud_ptrp;
	struct fuse_dev *fud;
	struct event e = {};
	u64 ts;
	dev_t dev;

	if (ret <= 0)
		goto out_clean;

	fud_ptrp = bpf_map_lookup_elem(&dequeue_args, &pid_tgid);
	if (!fud_ptrp)
		return 0;

	fud = (struct fuse_dev *)*fud_ptrp;
	dev = BPF_CORE_READ(fud, fc, dev);
	e.conn_id = FUSE_MINOR(dev);

	if (target_connid && e.conn_id != target_connid)
		goto out_clean;

	ts      = bpf_ktime_get_ns();
	e.ts_ns = ts;
	e.evt   = FUSEQ_D;
	e.pid   = (u32)(pid_tgid >> 32);
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	/* Record dequeue timestamp for Q→D / D→R split at fuse_request_end. */
	bpf_map_update_elem(&dequeue_ts, &pid_tgid, &ts, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

out_clean:
	bpf_map_delete_elem(&dequeue_args, &pid_tgid);
	return 0;
}

/* ------------------------------------------------------------------ */

/*
 * fuse_request_end(struct fuse_req *req)
 *
 * Called when the daemon writes the reply (or on error/abort paths).
 * Look up the pending entry and emit R event with total Q->R latency.
 */
SEC("kprobe/fuse_request_end")
int BPF_KPROBE(fuse_request_end_entry)
{
	u64 req_ptr = PT_REGS_PARM1_CORE(ctx);
	struct fuse_req *req = (struct fuse_req *)req_ptr;
	struct pending_info *pip;
	struct event e = {};
	u64 pid_tgid, now;

	pip = bpf_map_lookup_elem(&pending, &req_ptr);
	if (!pip)
		return 0;

	if (target_pid && pip->pid != (u32)target_pid)
		goto out_delete;
	if (target_connid && pip->conn_id != target_connid)
		goto out_delete;

	pid_tgid  = bpf_get_current_pid_tgid();
	now       = bpf_ktime_get_ns();
	e.ts_ns   = now;
	e.unique  = BPF_CORE_READ(req, in.h.unique);
	e.opcode  = pip->opcode;
	e.conn_id = pip->conn_id;

	/*
	 * Split total Q→R latency into Q→D (wait) and D→R (server processing).
	 * This works when fuse_request_end is called by the same daemon thread
	 * that dequeued the request.  For requests where the daemon hands off
	 * the response to a different thread, has_split stays 0 and only the
	 * total latency is available.
	 */
	{
		u64 total = now - pip->ts_ns;
		u64 *d_tsp = bpf_map_lookup_elem(&dequeue_ts, &pid_tgid);

		if (d_tsp && *d_tsp >= pip->ts_ns && *d_tsp <= now) {
			e.wait_ns    = *d_tsp - pip->ts_ns;
			e.process_ns = now - *d_tsp;
			e.has_split  = 1;
		} else {
			e.wait_ns    = total;
			e.process_ns = 0;
			e.has_split  = 0;
		}
	}

	/*
	 * W event: emitted on the daemon thread that completed the request.
	 * Provides a reliable daemon-tid -> unique-id mapping not available
	 * at D time.  Shows only server processing time (D→R).
	 */
	e.evt = FUSEQ_W;
	e.pid = (u32)(pid_tgid >> 32);
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	/* R event: application perspective — requester PID and full latency. */
	e.evt  = FUSEQ_R;
	e.pid  = pip->pid;
	e.error = BPF_CORE_READ(req, out.h.error);
	__builtin_memcpy(e.comm, pip->comm, sizeof(e.comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

out_delete:
	bpf_map_delete_elem(&pending, &req_ptr);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Tracepoint path                                                      */
/* ------------------------------------------------------------------ */

/*
 * Minimal trace_event_raw_* structs for the fuse tracepoints.
 * Only the event-specific fields (after the common 8-byte header) are
 * declared; CO-RE resolves their actual offsets from the fuse module BTF.
 * Field names must exactly match the TP_STRUCT__entry() definitions in
 * fs/fuse/fuse_trace.h.
 */
struct trace_event_raw_fuse_request_send {
	__u64  ent;	/* struct trace_entry common header */
	dev_t  connection;
	__u64  unique;
	__u32  opcode;
	__u32  len;
};

struct trace_event_raw_fuse_request_sent {
	__u64  ent;	/* struct trace_entry common header */
	dev_t  connection;
	__u64  unique;
	__u32  opcode;
};

struct trace_event_raw_fuse_request_end {
	__u64  ent;	/* struct trace_entry common header */
	dev_t  connection;
	__u64  unique;
	__u32  len;
	__s32  error;
};

/*
 * tp/fuse/fuse_request_send — Q event.
 * Fires on the application thread after the unique ID has been assigned,
 * just before the request is added to fiq->pending.
 */
SEC("tp/fuse/fuse_request_send")
int tp_fuse_request_send(struct trace_event_raw_fuse_request_send *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_info pi = {};
	struct event e = {};
	u64 unique;
	u32 opcode, conn_id;
	dev_t connection;

	unique = ctx->unique;
	if (!unique)
		return 0;	/* FUSE_NOTIFY_REPLY */

	opcode     = ctx->opcode;
	connection = ctx->connection;
	conn_id    = FUSE_MINOR(connection);

	e.pid = (u32)(pid_tgid >> 32);
	if (target_pid && e.pid != (u32)target_pid)
		return 0;
	if (target_connid && conn_id != target_connid)
		return 0;

	e.ts_ns   = bpf_ktime_get_ns();
	e.unique  = unique;
	e.opcode  = opcode;
	e.conn_id = conn_id;
	e.evt     = FUSEQ_Q;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	pi.ts_ns   = e.ts_ns;
	pi.opcode  = opcode;
	pi.pid     = e.pid;
	pi.conn_id = conn_id;
	__builtin_memcpy(pi.comm, e.comm, sizeof(pi.comm));
	bpf_map_update_elem(&pending, &unique, &pi, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

/*
 * tp/fuse/fuse_request_sent — D event.
 * Fires on the daemon thread immediately after list_del_init removes the
 * request from fiq->pending.  Unlike the kretprobe path, this carries the
 * unique ID, so D events are properly correlated with their Q events.
 * Only emits for requests already in the pending map (respects pid filter).
 */
SEC("tp/fuse/fuse_request_sent")
int tp_fuse_request_sent(struct trace_event_raw_fuse_request_sent *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_info *pip;
	struct event e = {};
	u64 unique, ts;
	u32 opcode, conn_id;
	dev_t connection;

	unique = ctx->unique;
	pip = bpf_map_lookup_elem(&pending, &unique);
	if (!pip)
		return 0;	/* not a tracked request (filtered out at Q) */

	opcode     = ctx->opcode;
	connection = ctx->connection;
	conn_id    = FUSE_MINOR(connection);

	ts          = bpf_ktime_get_ns();
	e.ts_ns     = ts;
	e.wait_ns   = ts - pip->ts_ns;
	e.has_split = 1;
	e.unique  = unique;
	e.opcode  = opcode;
	e.conn_id = conn_id;
	e.evt     = FUSEQ_D;
	e.pid     = (u32)(pid_tgid >> 32);
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	bpf_map_update_elem(&dequeue_ts, &unique, &ts, BPF_ANY);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

/*
 * tp/fuse/fuse_request_end — W + R events.
 * Fires at request completion; pending and dequeue_ts are keyed by unique.
 */
SEC("tp/fuse/fuse_request_end")
int tp_fuse_request_end(struct trace_event_raw_fuse_request_end *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_info *pip;
	struct event e = {};
	u64 unique, now;

	unique = ctx->unique;
	if (!unique)
		return 0;

	pip = bpf_map_lookup_elem(&pending, &unique);
	if (!pip)
		return 0;

	if (target_pid && pip->pid != (u32)target_pid)
		goto out_delete;
	if (target_connid && pip->conn_id != target_connid)
		goto out_delete;

	now       = bpf_ktime_get_ns();
	e.ts_ns   = now;
	e.unique  = unique;
	e.opcode  = pip->opcode;
	e.conn_id = pip->conn_id;

	{
		u64 total  = now - pip->ts_ns;
		u64 *d_tsp = bpf_map_lookup_elem(&dequeue_ts, &unique);

		if (d_tsp && *d_tsp >= pip->ts_ns && *d_tsp <= now) {
			e.wait_ns    = *d_tsp - pip->ts_ns;
			e.process_ns = now - *d_tsp;
			e.has_split  = 1;
			bpf_map_delete_elem(&dequeue_ts, &unique);
		} else {
			e.wait_ns    = total;
			e.process_ns = 0;
			e.has_split  = 0;
		}
	}

	e.evt = FUSEQ_W;
	e.pid = (u32)(pid_tgid >> 32);
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	e.evt   = FUSEQ_R;
	e.pid   = pip->pid;
	e.error = ctx->error;
	__builtin_memcpy(e.comm, pip->comm, sizeof(e.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

out_delete:
	bpf_map_delete_elem(&pending, &unique);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
