#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# fusenoop  Trace FUSE protocol and print details including daemon PID.
#           For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to match FUSE requests/replies, as well
# as a starting timestamp for calculating I/O latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Sep-2015   Brendan Gregg   Created this.
# 11-Feb-2016   Allan McAleavy  updated for BPF_PERF_OUTPUT
# 13-May-2020   Amir Goldstein  FUSE protocol tracing

from __future__ import print_function
from bcc import BPF
import ctypes as ct
import re
import argparse

# arguments
examples = """examples:
    ./fusesnoop           # trace all FUSE daemons
    ./fusesnoop -p 181    # only trace daemon with PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace FUSE protocol",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
                    help="trace only daemon with this PID")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/fuse.h>

struct val_t {
    u64 ts;
};

struct data_t {
    u32 srvpid;
    u64 reqid;
    u32 opcode;
    u64 nodeid;
    u32 cliuid;
    u32 clipid;
    u64 delta;
    u64 ts;
};

struct fuse_conn {
    u32 dummy;
    /* Interesting fields like num_waiting are in diffferent offsets
       per kernel version and per Kconfig */
};

struct fuse_iqueue {
    u32 connected;
};

struct fuse_req {
    /* Offset of flags is the same between v4.19..v5.7 */
    u64 dummy[6];

    /* Request flags */
    u64 flags;

    /* The request input header */
    struct fuse_in_header ih;

    /* Offset of output header is different before v5.4 */
#ifdef FUSE_MAP_ALIGNMENT
    /* The request output header */
    struct fuse_out_header oh;
#endif
};

BPF_HASH(infobyreq, struct fuse_req *, struct val_t);
BPF_PERF_OUTPUT(events);

// cache daemon PID and timestmap by-req
int trace_req_start(struct pt_regs *ctx, struct fuse_iqueue *fiq, struct fuse_req *req)
{
    struct val_t val = {};

    val.ts = bpf_ktime_get_ns();
    infobyreq.update(&req, &val);
    return 0;
}

int trace_req_end(struct pt_regs *ctx, struct fuse_conn *fc, struct fuse_req *req)
{
    struct val_t *valp;
    struct data_t data = {};
    u64 ts;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    ts = bpf_ktime_get_ns();
    data.delta = 0;

    valp = infobyreq.lookup(&req);
    if (valp != 0)
        data.delta = ts - valp->ts;

    data.ts = ts / 1000;
    data.srvpid = pid;
    data.reqid = req->ih.unique;
    data.nodeid = req->ih.nodeid;
    data.cliuid = req->ih.uid;
    data.clipid = req->ih.pid;

    /*
     * We do not have the daemon pid in req_start context.
     * TODO: match daemon pid to fiq on init and filter in req_start.
     */
    PID_FILTER events.perf_submit(ctx, &data, sizeof(data));
    infobyreq.delete(&req);

    return 0;
}
"""
if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER',
                                'if (pid == %s)' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
# Not exported in mainline v5.7
if BPF.get_kprobe_functions(b'fuse_queue_request_and_unlock'):
    b.attach_kprobe(event="fuse_queue_request_and_unlock", fn_name="trace_req_start")
# Exported since v5.4
b.attach_kprobe(event="fuse_request_end", fn_name="trace_req_end")

class Data(ct.Structure):
    _fields_ = [
        ("srvpid", ct.c_ulonglong),
        ("reqid", ct.c_ulonglong),
        ("opcode", ct.c_ulonglong),
        ("nodeid", ct.c_ulonglong),
        ("cliuid", ct.c_ulonglong),
        ("clipid", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
    ]

# header
print("%-11s %-7s %-7s %-7s %-7s %-7s %-7s" % ("TIME(s)", "SRVPID",
    "REQID", "OPCODE", "NODEID", "CLIUID", "CLIPID"), end="")
print("%7s" % "LAT(ms)")

start_ts = 0
prev_ts = 0
delta = 0

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    global start_ts
    if start_ts == 0:
        start_ts = event.ts

    delta = float(event.ts) - start_ts

    print("%-11.6f %-7s %-7s %-7s %-7s %-7s %-7s" % (
        delta / 1000000, event.srvpid, event.reqid, event.opcode,
        event.nodeid, event.cliuid, event.clipid), end="")
    print("%7.2f" % (float(event.delta) / 1000000))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
