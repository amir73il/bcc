// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 CTERA Networks
//
// fuseqslower - Trace FUSE requests slower than a threshold.
//
// Measures total Q->R latency and splits it into:
//   wait time    (Q->D): time the request sat in the kernel pending queue
//   process time (D->R): time the daemon spent actually processing it
//
// The threshold can be applied to wait, process, or total latency.
//
// 21-May-2026   Created.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/fuse.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fuseqslower.h"
#include "fuseqslower.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	64
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...)		fprintf(stderr, __VA_ARGS__)

#define DEFAULT_MIN_LAT_MS	10

/* Filter modes: exactly one of these will be set. */
enum filter_mode { MODE_TOTAL = 0, MODE_WAIT, MODE_PROCESS };

static volatile sig_atomic_t exiting = 0;

static pid_t		target_pid    = 0;
static __u32		target_connid = 0;
static __u64		min_lat_ms    = DEFAULT_MIN_LAT_MS;
static enum filter_mode	filter_mode   = MODE_TOTAL;
static bool		emit_timestamp = false;
static bool		verbose        = false;

const char *argp_program_version = "fuseqslower 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace FUSE requests slower than a latency threshold.\n"
"\n"
"Each request is timed from enqueue (Q) to completion (R) and split into:\n"
"  WAIT(ms)  - time the request waited in the kernel pending queue (Q->D)\n"
"  PROC(ms)  - time the daemon spent processing it (D->R)\n"
"  LAT(ms)   - total round-trip time (Q->R)\n"
"\n"
"The split requires that fuse_request_end is called by the daemon thread\n"
"that processed the request (true for synchronous libfuse daemons).\n"
"For async/background requests the split is unavailable (-/- shown).\n"
"\n"
"Use -w to filter by wait time or -r to filter by process time instead\n"
"of the default total.  The positional [min_ms] sets the threshold.\n"
"\n"
"The connection ID (-c) is the directory number under\n"
"/sys/fs/fuse/connections/ and the MINOR number of /dev/fuse.\n"
"\n"
"USAGE: fuseqslower [-h] [-t] [-w|-r] [-p PID] [-c CONNID] [min_ms]\n"
"\n"
"EXAMPLES:\n"
"    fuseqslower           # requests with total latency > 10 ms\n"
"    fuseqslower 1         # requests with total latency > 1 ms\n"
"    fuseqslower -w 5      # requests that waited in queue > 5 ms\n"
"    fuseqslower -r 2      # requests where daemon took > 2 ms to respond\n"
"    fuseqslower -t -c 5   # connection 5, with timestamps\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0,
	  "Filter by requesting PID (the process queuing the request)", 0 },
	{ "connid", 'c', "CONNID", 0,
	  "Filter by FUSE connection ID (MINOR of /dev/fuse, directory under "
	  "/sys/fs/fuse/connections/)", 0 },
	{ "wait", 'w', NULL, 0,
	  "Apply threshold to wait time (Q->D) instead of total latency", 0 },
	{ "response", 'r', NULL, 0,
	  "Apply threshold to process time (D->R) instead of total latency", 0 },
	{ "timestamp", 't', NULL, 0, "Include wall-clock timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long val;

	switch (key) {
	case 'p':
		errno = 0;
		val = strtol(arg, NULL, 10);
		if (errno || val <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = (pid_t)val;
		break;
	case 'c':
		errno = 0;
		val = strtol(arg, NULL, 10);
		if (errno || val < 0) {
			warn("Invalid connection ID: %s\n", arg);
			argp_usage(state);
		}
		target_connid = (__u32)val;
		break;
	case 'w':
		if (filter_mode == MODE_PROCESS) {
			warn("Cannot combine -w and -r\n");
			argp_usage(state);
		}
		filter_mode = MODE_WAIT;
		break;
	case 'r':
		if (filter_mode == MODE_WAIT) {
			warn("Cannot combine -w and -r\n");
			argp_usage(state);
		}
		filter_mode = MODE_PROCESS;
		break;
	case 't':
		emit_timestamp = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		val = strtol(arg, NULL, 10);
		if (errno || val < 0) {
			warn("Invalid min latency (ms): %s\n", arg);
			argp_usage(state);
		}
		min_lat_ms = (__u64)val;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char *fuse_opcode_name(__u32 opcode)
{
	switch (opcode) {
	case FUSE_LOOKUP:		return "LOOKUP";
	case FUSE_FORGET:		return "FORGET";
	case FUSE_GETATTR:		return "GETATTR";
	case FUSE_SETATTR:		return "SETATTR";
	case FUSE_READLINK:		return "READLINK";
	case FUSE_SYMLINK:		return "SYMLINK";
	case FUSE_MKNOD:		return "MKNOD";
	case FUSE_MKDIR:		return "MKDIR";
	case FUSE_UNLINK:		return "UNLINK";
	case FUSE_RMDIR:		return "RMDIR";
	case FUSE_RENAME:		return "RENAME";
	case FUSE_LINK:			return "LINK";
	case FUSE_OPEN:			return "OPEN";
	case FUSE_READ:			return "READ";
	case FUSE_WRITE:		return "WRITE";
	case FUSE_STATFS:		return "STATFS";
	case FUSE_RELEASE:		return "RELEASE";
	case FUSE_FSYNC:		return "FSYNC";
	case FUSE_SETXATTR:		return "SETXATTR";
	case FUSE_GETXATTR:		return "GETXATTR";
	case FUSE_LISTXATTR:		return "LISTXATTR";
	case FUSE_REMOVEXATTR:		return "REMOVEXATTR";
	case FUSE_FLUSH:		return "FLUSH";
	case FUSE_INIT:			return "INIT";
	case FUSE_OPENDIR:		return "OPENDIR";
	case FUSE_READDIR:		return "READDIR";
	case FUSE_RELEASEDIR:		return "RELEASEDIR";
	case FUSE_FSYNCDIR:		return "FSYNCDIR";
	case FUSE_GETLK:		return "GETLK";
	case FUSE_SETLK:		return "SETLK";
	case FUSE_SETLKW:		return "SETLKW";
	case FUSE_ACCESS:		return "ACCESS";
	case FUSE_CREATE:		return "CREATE";
	case FUSE_INTERRUPT:		return "INTERRUPT";
	case FUSE_BMAP:			return "BMAP";
	case FUSE_DESTROY:		return "DESTROY";
	case FUSE_IOCTL:		return "IOCTL";
	case FUSE_POLL:			return "POLL";
	case FUSE_NOTIFY_REPLY:		return "NOTIFY_REPLY";
	case FUSE_BATCH_FORGET:		return "BATCH_FORGET";
	case FUSE_FALLOCATE:		return "FALLOCATE";
	case FUSE_READDIRPLUS:		return "READDIRPLUS";
	case FUSE_RENAME2:		return "RENAME2";
	case FUSE_LSEEK:		return "LSEEK";
	case FUSE_COPY_FILE_RANGE:	return "COPY_FILE_RANGE";
	case FUSE_SETUPMAPPING:		return "SETUPMAPPING";
	case FUSE_REMOVEMAPPING:	return "REMOVEMAPPING";
	case FUSE_SYNCFS:		return "SYNCFS";
	case FUSE_TMPFILE:		return "TMPFILE";
#ifdef FUSE_STATX
	case FUSE_STATX:		return "STATX";
#endif
	default: {
		static char buf[16];
		snprintf(buf, sizeof(buf), "OP_%u", opcode);
		return buf;
	}
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	struct tm *tm;
	char ts[16];
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	memcpy(&e, data, sizeof(e));

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}

	double total_ms = (double)(e.wait_ns + e.process_ns) / 1e6;

	printf("%-7u %-16s %-6u %-16s %-20llu",
	       e.pid,
	       e.comm,
	       e.conn_id,
	       fuse_opcode_name(e.opcode),
	       (unsigned long long)e.unique);

	if (e.has_split) {
		printf(" %10.3f %10.3f %10.3f",
		       (double)e.wait_ns / 1e6,
		       (double)e.process_ns / 1e6,
		       total_ms);
	} else {
		printf(" %10s %10s %10.3f", "-", "-", total_ms);
	}

	if (e.error)
		printf(" err=%d", e.error);

	printf("\n");
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	/* Make stdout line-buffered so output appears even when not a tty. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser  = parse_arg,
		.doc     = argp_program_doc,
	};
	struct bpf_link *enqueue_entry_link = NULL;
	struct bpf_link *enqueue_exit_link  = NULL;
	struct bpf_link *dequeue_entry_link = NULL;
	struct bpf_link *dequeue_exit_link  = NULL;
	struct perf_buffer *pb = NULL;
	struct fuseqslower_bpf *obj;
	char enqueue_fn_buf[256];
	char dequeue_fn_buf[256];
	const char *enqueue_fn;
	const char *dequeue_fn;
	struct ksyms *ksyms;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr,
			"failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = fuseqslower_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid    = target_pid;
	obj->rodata->target_connid = target_connid;

	switch (filter_mode) {
	case MODE_WAIT:
		obj->rodata->min_wait_ns    = min_lat_ms * 1000000ULL;
		break;
	case MODE_PROCESS:
		obj->rodata->min_process_ns = min_lat_ms * 1000000ULL;
		break;
	default:
		obj->rodata->min_lat_ns     = min_lat_ms * 1000000ULL;
		break;
	}

	/*
	 * Resolve enqueue and dequeue symbols at runtime:
	 *
	 * Enqueue (Q events):
	 *   fuse_dev_queue_req       — 6.12+, req is PARM2
	 *   queue_request_and_unlock — 5.15,  req is PARM2 (same probe works)
	 *
	 * Dequeue (D events / split):
	 *   fuse_dev_do_read.constprop.N — splice() path, needs manual attach
	 *   fuse_dev_read                — regular read() path, auto-attaches
	 */
	ksyms = ksyms__load();
	if (!ksyms) {
		warn("failed to load /proc/kallsyms\n");
		err = 1;
		goto cleanup_obj;
	}
	{
		const struct ksym *ksym;

		ksym = ksyms__get_symbol(ksyms, "fuse_dev_queue_req");
		if (!ksym)
			ksym = ksyms__get_symbol_prefix(ksyms,
						"queue_request_and_unlock");
		if (ksym) {
			strncpy(enqueue_fn_buf, ksym->name,
				sizeof(enqueue_fn_buf) - 1);
			enqueue_fn_buf[sizeof(enqueue_fn_buf) - 1] = '\0';
			enqueue_fn = enqueue_fn_buf;
		} else {
			enqueue_fn = NULL;
		}

		ksym = ksyms__get_symbol_prefix(ksyms, "fuse_dev_do_read");
		if (ksym) {
			strncpy(dequeue_fn_buf, ksym->name,
				sizeof(dequeue_fn_buf) - 1);
			dequeue_fn_buf[sizeof(dequeue_fn_buf) - 1] = '\0';
			dequeue_fn = dequeue_fn_buf;
		} else {
			dequeue_fn = NULL;
		}
	}
	ksyms__free(ksyms);

	if (!enqueue_fn) {
		warn("WARNING: neither fuse_dev_queue_req nor "
		     "queue_request_and_unlock found; Q events disabled\n");
		bpf_program__set_autoload(obj->progs.fuse_dev_queue_req_entry,
					  false);
		bpf_program__set_autoload(obj->progs.fuse_dev_queue_req_exit,
					  false);
	} else {
		bpf_program__set_autoattach(obj->progs.fuse_dev_queue_req_entry,
					    false);
		bpf_program__set_autoattach(obj->progs.fuse_dev_queue_req_exit,
					    false);
	}

	if (!dequeue_fn) {
		warn("WARNING: fuse_dev_do_read.constprop not found; "
		     "splice() read path split disabled\n");
		bpf_program__set_autoload(obj->progs.fuse_dev_do_read_entry,
					  false);
		bpf_program__set_autoload(obj->progs.fuse_dev_do_read_exit,
					  false);
	} else {
		bpf_program__set_autoattach(obj->progs.fuse_dev_do_read_entry,
					    false);
		bpf_program__set_autoattach(obj->progs.fuse_dev_do_read_exit,
					    false);
	}

	err = fuseqslower_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup_obj;
	}

	err = fuseqslower_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* Manually attach enqueue probes to the resolved symbol. */
	if (enqueue_fn) {
		enqueue_entry_link = bpf_program__attach_kprobe(
			obj->progs.fuse_dev_queue_req_entry, false, enqueue_fn);
		if (!enqueue_entry_link)
			warn("WARNING: failed to attach kprobe on %s: %s\n",
			     enqueue_fn, strerror(errno));

		enqueue_exit_link = bpf_program__attach_kprobe(
			obj->progs.fuse_dev_queue_req_exit, true, enqueue_fn);
		if (!enqueue_exit_link)
			warn("WARNING: failed to attach kretprobe on %s: %s\n",
			     enqueue_fn, strerror(errno));
	}

	/* Manually attach splice-path dequeue probes to the resolved symbol. */
	if (dequeue_fn) {
		dequeue_entry_link = bpf_program__attach_kprobe(
			obj->progs.fuse_dev_do_read_entry, false, dequeue_fn);
		if (!dequeue_entry_link)
			warn("WARNING: failed to attach kprobe on %s: %s\n",
			     dequeue_fn, strerror(errno));
		dequeue_exit_link = bpf_program__attach_kprobe(
			obj->progs.fuse_dev_do_read_exit, true, dequeue_fn);
		if (!dequeue_exit_link)
			warn("WARNING: failed to attach kretprobe on %s: %s\n",
			     dequeue_fn, strerror(errno));
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events),
			      PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	{
		const char *mode_str;
		switch (filter_mode) {
		case MODE_WAIT:    mode_str = "wait";    break;
		case MODE_PROCESS: mode_str = "process"; break;
		default:           mode_str = "total";   break;
		}
		fprintf(stderr,
			"Tracing FUSE requests with %s latency > %llu ms",
			mode_str, min_lat_ms);
	}
	if (target_connid)
		fprintf(stderr, " on connection %u", target_connid);
	if (target_pid)
		fprintf(stderr, " from PID %d", target_pid);
	fprintf(stderr, "... Hit Ctrl-C to end.\n");

	if (emit_timestamp)
		printf("%-8s ", "TIME");
	printf("%-7s %-16s %-6s %-16s %-20s %10s %10s %10s\n",
	       "PID", "COMM", "CONN", "OPCODE", "UNIQUE",
	       "WAIT(ms)", "SERV(ms)", "LAT(ms)");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n",
			     strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	bpf_link__destroy(enqueue_entry_link);
	bpf_link__destroy(enqueue_exit_link);
	bpf_link__destroy(dequeue_entry_link);
	bpf_link__destroy(dequeue_exit_link);
	perf_buffer__free(pb);
cleanup_obj:
	fuseqslower_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
