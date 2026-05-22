// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 CTERA Networks
//
// fuseqsnoop - Trace FUSE request lifecycle: enqueue, dequeue, and response.
//
// For each FUSE request it logs three events:
//   Q  request inserted into fiq->pending (by the requester process)
//   D  request dequeued by a daemon thread (no req correlation)
//   R  request completed via fuse_request_end (with Q→R total latency)
//
// This is useful for diagnosing FUSE daemon pool exhaustion and latency
// regressions by showing exactly when requests queue up and when they complete.
//
// Opcode filtering is applied on the kernel side (-p/-c flags).
// The -p PID refers to the process that queued the request (the application),
// NOT the FUSE daemon.
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
#include "fuseqsnoop.h"
#include "fuseqsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	64
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...)		fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static __u32 target_connid = 0;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "fuseqsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace FUSE request lifecycle (enqueue / dequeue / response).\n"
"\n"
"Four event types are logged per request:\n"
"  Q  request inserted into the pending queue (by the application)\n"
"  D  request dequeued by a daemon thread\n"
"  W  worker daemon thread that completed the request\n"
"  R  request completed, with total Q->R latency in milliseconds\n"
"\n"
"W and R are emitted together at completion time.  W provides a reliable\n"
"map from FUSE daemon TID to unique request ID, which is not available at D.\n"
"\n"
"The connection ID (-c) corresponds to the directory number under\n"
"/sys/fs/fuse/connections/ and the MINOR number of /dev/fuse.\n"
"\n"
"USAGE: fuseqsnoop [-h] [-t] [-p PID] [-c CONNID]\n"
"\n"
"EXAMPLES:\n"
"    fuseqsnoop           # trace all FUSE connections\n"
"    fuseqsnoop -t        # include wall-clock timestamp\n"
"    fuseqsnoop -p 1234   # trace requests from PID 1234 only\n"
"    fuseqsnoop -c 5      # trace FUSE connection 5 only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0,
	  "Filter by requesting PID (the process queuing the request, not the daemon)", 0 },
	{ "connid", 'c', "CONNID", 0,
	  "Filter by FUSE connection ID (MINOR of /dev/fuse, directory under "
	  "/sys/fs/fuse/connections/)", 0 },
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
	case 't':
		emit_timestamp = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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
	const char *evt_str;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data — alignment in the perf buffer is not guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}

	evt_str = (e.evt == FUSEQ_Q) ? "Q" :
		  (e.evt == FUSEQ_D) ? "D" :
		  (e.evt == FUSEQ_W) ? "W" : "R";

	printf("%-3s %-7u %-16s %-6u ",
	       evt_str, e.pid, e.comm, e.conn_id);

	if (e.evt == FUSEQ_D) {
		printf("%-16s %-20s", "-", "-");
	} else {
		printf("%-16s %-20llu",
		       fuse_opcode_name(e.opcode),
		       (unsigned long long)e.unique);
	}

	if (e.evt == FUSEQ_W) {
		/* Daemon perspective: show only server processing time (D→R). */
		if (e.has_split)
			printf(" %10s %10.3f %10s", "", e.process_ns / 1e6, "");
		else
			printf(" %10s %10s %10s", "", "-", "");
	} else if (e.evt == FUSEQ_R) {
		if (e.has_split) {
			printf(" %10.3f %10.3f %10.3f",
			       e.wait_ns    / 1e6,
			       e.process_ns / 1e6,
			       (e.wait_ns + e.process_ns) / 1e6);
		} else {
			/* wait_ns holds total when has_split==0 */
			printf(" %10s %10s %10.3f", "-", "-",
			       e.wait_ns / 1e6);
		}
		if (e.error)
			printf(" err=%d", e.error);
	}

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
	struct fuseqsnoop_bpf *obj;
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

	obj = fuseqsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid    = target_pid;
	obj->rodata->target_connid = target_connid;

	/*
	 * Resolve enqueue and dequeue symbols at runtime:
	 *
	 * Enqueue (Q events):
	 *   fuse_dev_queue_req        — 6.12+, req is PARM2
	 *   queue_request_and_unlock  — 5.15,  req is PARM2 (same probe works)
	 *
	 * Dequeue (D events):
	 *   fuse_dev_do_read.constprop.N — splice() path, needs manual attach
	 *   fuse_dev_read                — regular read() path, auto-attaches
	 */
	ksyms = ksyms__load();
	if (!ksyms) {
		warn("failed to load /proc/kallsyms\n");
		err = 1;
		goto cleanup;
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
		     "splice() read path D events disabled\n");
		bpf_program__set_autoload(obj->progs.fuse_dev_do_read_entry,
					  false);
		bpf_program__set_autoload(obj->progs.fuse_dev_do_read_exit,
					  false);
	}

	err = fuseqsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/*
	 * fuse_dev_read auto-attaches via its SEC() name.
	 * fuse_dev_do_read.constprop.N needs manual attachment since the
	 * symbol name is not stable.
	 */
	if (dequeue_fn) {
		bpf_program__set_autoattach(obj->progs.fuse_dev_do_read_entry,
					    false);
		bpf_program__set_autoattach(obj->progs.fuse_dev_do_read_exit,
					    false);
	}

	err = fuseqsnoop_bpf__attach(obj);
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

	if (emit_timestamp)
		printf("%-8s ", "TIME");
	printf("%-3s %-7s %-16s %-6s %-16s %-20s %10s %10s %10s\n",
	       "EVT", "PID", "COMM", "CONN", "OPCODE", "UNIQUE",
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
	fuseqsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
