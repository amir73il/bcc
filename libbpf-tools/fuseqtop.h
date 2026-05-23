/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUSEQTOP_H
#define __FUSEQTOP_H

#define TASK_COMM_LEN 16

/*
 * In-flight FUSE request tracked from Q (enqueue) to R (request_end).
 * d_ts == 0: still waiting in the kernel pending queue (Q state).
 * d_ts != 0: dequeued by a daemon thread (D state).
 *
 * d_ts is set by userspace on first detection via the conn_pending_head
 * watermark (earliest possible approximation).  When a kernel-side
 * fuse_request_dequeue tracepoint is available, the BPF handler will set
 * d_ts directly, making it exact.
 */
struct req_info {
	__u64 q_ts;	/* enqueue timestamp (ns) */
	__u64 d_ts;	/* first-detected dequeue timestamp (ns); 0 = Q */
	__u64 unique;	/* FUSE request unique ID */
	__u32 opcode;	/* FUSE opcode */
	__u32 pid;	/* requesting process PID */
	__u32 conn_id;	/* FUSE connection ID (MINOR of fc->dev) */
	__u32 pad;
	char  comm[TASK_COMM_LEN];
};

/*
 * Watermark for the conn_pending_head map: unique ID of the oldest request
 * still in fiq->pending at the moment of the last fuse_dev_read exit, plus
 * the BPF timestamp of that observation.
 * head_unique == 0 means the queue was empty (all in_flight are D).
 */
struct watermark {
	__u64 head_unique;
	__u64 ts;
};

/*
 * Active FUSE daemon thread tracked from D (dequeue) to R (request_end).
 * Stale entries are overwritten on the thread's next dequeue.
 */
struct worker_info {
	__u64 d_ts;	/* dequeue timestamp (ns) */
	__u32 conn_id;	/* FUSE connection ID */
	__u32 tid;	/* daemon thread TID */
	char  comm[TASK_COMM_LEN];
};

#endif /* __FUSEQTOP_H */
