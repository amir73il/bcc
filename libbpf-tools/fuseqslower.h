/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUSEQSLOWER_H
#define __FUSEQSLOWER_H

#define TASK_COMM_LEN 16

struct event {
	__u64	ts_ns;		/* event timestamp from bpf_ktime_get_ns */
	__u64	unique;		/* FUSE request unique ID */
	__u64	wait_ns;	/* Q→D: time waiting in fiq->pending queue */
	__u64	process_ns;	/* D→R: time being processed by daemon */
	__u32	opcode;		/* FUSE opcode */
	__u32	pid;		/* requesting PID */
	__u32	conn_id;	/* FUSE connection ID: MINOR(fc->dev) */
	__s32	error;		/* response error (0 = success) */
	char	comm[TASK_COMM_LEN];
	__u8	has_split;	/* 1 if wait/process split is valid */
	__u8	pad[3];
};

#endif /* __FUSEQSLOWER_H */
