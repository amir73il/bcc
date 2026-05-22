/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUSEQSNOOP_H
#define __FUSEQSNOOP_H

#define TASK_COMM_LEN 16

enum fuseq_evt {
	FUSEQ_Q = 0,	/* request enqueued (inserted into fiq->pending) */
	FUSEQ_D = 1,	/* request dequeued by daemon thread */
	FUSEQ_W = 2,	/* worker: daemon thread that completed the request */
	FUSEQ_R = 3,	/* request completed (fuse_request_end) */
};

struct event {
	__u64 ts_ns;		/* event timestamp from bpf_ktime_get_ns */
	__u64 unique;		/* request unique ID (Q/R); 0 for D */
	/*
	 * R only: Q→D wait time and D→R server processing time.
	 * Both are 0 and has_split==0 when fuse_request_end fires on a
	 * different thread than the daemon thread that dequeued the request
	 * (e.g. daemon hands off response to a separate responder thread).
	 */
	__u64 wait_ns;
	__u64 process_ns;
	__u32 opcode;		/* FUSE opcode (Q/R); 0 for D */
	__u32 pid;		/* requesting PID (Q/R) or daemon PID (D) */
	__u32 conn_id;		/* FUSE connection ID: MINOR(fc->dev) */
	__s32 error;		/* response error (R only) */
	char  comm[TASK_COMM_LEN];
	__u8  evt;		/* enum fuseq_evt */
	__u8  has_split;	/* R only: 1 if wait_ns/process_ns are valid */
	__u8  pad[2];
};

#endif /* __FUSEQSNOOP_H */
