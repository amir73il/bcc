// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 CTERA Networks
//
// fuseqtop - Show in-flight FUSE requests sorted by latency.
//
// Maintains a live view of all FUSE requests currently queued or being
// processed by the daemon.  Two sections are displayed on each refresh:
//
//   Requests: each in-flight request with its status (Q=waiting in
//     kernel pending queue, D=being processed by daemon thread), its
//     wait time in queue (Q->D), and server processing time (D->now).
//
//   Workers: daemon threads currently processing a request, sorted by
//     server processing time (D->now).
//
// 22-May-2026   Created.
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
#include "fuseqtop.h"
#include "fuseqtop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...)	fprintf(stderr, __VA_ARGS__)

#define DEFAULT_INTERVAL_S	2
#define DEFAULT_MAX_ROWS	20

/* Sort key for the requests table. */
enum sort_mode { SORT_TOTAL = 0, SORT_WAIT, SORT_SERV };

static volatile sig_atomic_t exiting = 0;

static pid_t		target_pid    = 0;
static __u32		target_connid = 0;
static int		interval_s    = DEFAULT_INTERVAL_S;
static int		max_rows      = DEFAULT_MAX_ROWS;
static enum sort_mode	sort_mode     = SORT_TOTAL;
static bool		no_clear      = false;
static bool		verbose       = false;
static bool		show_stacks   = false;
static bool		have_pstack   = false;

const char *argp_program_version = "fuseqtop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show in-flight FUSE requests sorted by latency.\n"
"\n"
"Every N seconds (default 2) the screen is refreshed with two tables:\n"
"\n"
"  Requests: all requests currently enqueued (Q) or being processed (D),\n"
"    sorted by the longest time in their current state.  Columns:\n"
"      WAIT(ms) - time the request has spent waiting in the kernel queue (Q->D)\n"
"      SERV(ms) - time the daemon has been processing it (D->now)\n"
"\n"
"  Workers: daemon threads currently processing a request, sorted by SERV(ms).\n"
"\n"
"The D state is detected by peeking at the pending queue head at daemon read\n"
"entry time; this is racy in multi-threaded daemons but acceptable for display.\n"
"\n"
"Use -w to sort by wait time or -r to sort by server time instead of total.\n"
"\n"
"The connection ID (-c) is the directory number under\n"
"/sys/fs/fuse/connections/ and the MINOR number of /dev/fuse.\n"
"\n"
"USAGE: fuseqtop [-h] [-w|-r] [-s] [-n ROWS] [-i SECS] [-p PID] [-c CONNID]\n"
"\n"
"EXAMPLES:\n"
"    fuseqtop              # refresh every 2s, sort by total time\n"
"    fuseqtop -w           # sort by wait time in queue\n"
"    fuseqtop -r           # sort by server processing time\n"
"    fuseqtop -s           # also print worker userspace stack traces\n"
"    fuseqtop -i 5         # refresh every 5 seconds\n"
"    fuseqtop -n 30        # show up to 30 requests\n"
"    fuseqtop -c 5         # only FUSE connection 5\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0,
	  "Filter by requesting PID", 0 },
	{ "connid", 'c', "CONNID", 0,
	  "Filter by FUSE connection ID (MINOR of /dev/fuse, directory under "
	  "/sys/fs/fuse/connections/)", 0 },
	{ "wait", 'w', NULL, 0,
	  "Sort requests by wait time (Q->D) instead of total time", 0 },
	{ "response", 'r', NULL, 0,
	  "Sort requests by server processing time (D->now) instead of total", 0 },
	{ "rows", 'n', "ROWS", 0,
	  "Maximum number of requests to display (default 20)", 0 },
	{ "interval", 'i', "SECS", 0,
	  "Refresh interval in seconds (default 2)", 0 },
	{ "noclear", 'C', NULL, 0,
	  "Do not clear screen between updates (scroll mode)", 0 },
	{ "stacks", 's', NULL, 0,
	  "Print worker userspace stack traces via pstack (if available)", 0 },
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
		if (sort_mode == SORT_SERV) {
			warn("Cannot combine -w and -r\n");
			argp_usage(state);
		}
		sort_mode = SORT_WAIT;
		break;
	case 'r':
		if (sort_mode == SORT_WAIT) {
			warn("Cannot combine -w and -r\n");
			argp_usage(state);
		}
		sort_mode = SORT_SERV;
		break;
	case 'n':
		errno = 0;
		val = strtol(arg, NULL, 10);
		if (errno || val <= 0) {
			warn("Invalid row count: %s\n", arg);
			argp_usage(state);
		}
		max_rows = (int)val;
		break;
	case 'i':
		errno = 0;
		val = strtol(arg, NULL, 10);
		if (errno || val <= 0) {
			warn("Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		interval_s = (int)val;
		break;
	case 'C':
		no_clear = true;
		break;
	case 's':
		show_stacks = true;
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

/* Return current CLOCK_MONOTONIC time in nanoseconds (same source as bpf_ktime_get_ns). */
static __u64 get_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* Snapshot structures used for sorting and display.                   */

struct req_display {
	__u64 req_ptr;		/* map key */
	struct req_info ri;
	bool  is_D;		/* true: D state (being processed); false: Q state */
	double wait_ms;		/* Q->D duration (D) or elapsed Q time (Q) */
	double serv_ms;		/* D->now duration (D) or 0 (Q) */
	double total_ms;	/* now - q_ts */
};


struct worker_display {
	__u64 pid_tgid;		/* map key */
	struct worker_info wi;
	double serv_ms;		/* now - d_ts */
};

static int cmp_req_total(const void *a, const void *b)
{
	const struct req_display *ra = a, *rb = b;

	if (rb->total_ms > ra->total_ms) return  1;
	if (rb->total_ms < ra->total_ms) return -1;
	return 0;
}

static int cmp_req_wait(const void *a, const void *b)
{
	const struct req_display *ra = a, *rb = b;

	if (rb->wait_ms > ra->wait_ms) return  1;
	if (rb->wait_ms < ra->wait_ms) return -1;
	return 0;
}

static int cmp_req_serv(const void *a, const void *b)
{
	const struct req_display *ra = a, *rb = b;

	if (rb->serv_ms > ra->serv_ms) return  1;
	if (rb->serv_ms < ra->serv_ms) return -1;
	return 0;
}

static int cmp_worker_serv(const void *a, const void *b)
{
	const struct worker_display *wa = a, *wb = b;

	if (wb->serv_ms > wa->serv_ms) return  1;
	if (wb->serv_ms < wa->serv_ms) return -1;
	return 0;
}

/* ------------------------------------------------------------------ */

/*
 * Print the userspace stack of a daemon worker thread via pstack.
 * Called at display time so the trace reflects what the thread is doing now.
 * pstack uses ptrace internally (brief stop, negligible for long requests).
 */
static void print_worker_stack(pid_t tid)
{
	char cmd[64];
	char line[256];
	FILE *f;

	snprintf(cmd, sizeof(cmd), "pstack %d 2>/dev/null", tid);
	f = popen(cmd, "r");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		size_t len = strlen(line);

		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		printf("         %s\n", line);
	}
	pclose(f);
}

static void display_snapshot(struct fuseqtop_bpf *obj)
{
	__u64 now = get_now_ns();
	__u64 prev_key, cur_key;
	struct req_info ri;
	struct worker_info wi;
	int in_flight_fd         = bpf_map__fd(obj->maps.in_flight);
	int workers_fd           = bpf_map__fd(obj->maps.workers);
	int conn_pending_head_fd = bpf_map__fd(obj->maps.conn_pending_head);

	/* --- collect requests ----------------------------------------- */
	struct req_display *reqs = NULL;
	struct worker_display *wds = NULL;
	int nreqs = 0, reqs_cap = 0;

	{
		bool has_prev = false;

		while (bpf_map_get_next_key(in_flight_fd,
					    has_prev ? &prev_key : NULL,
					    &cur_key) == 0) {
			if (bpf_map_lookup_elem(in_flight_fd,
						&cur_key, &ri) != 0)
				goto next_req;

			/*
			 * If d_ts is not yet set, check the watermark to see
			 * if this request has been dequeued.  On first D
			 * detection, write d_ts = wm.ts back into the BPF map
			 * so that the timestamp is the BPF ktime observation
			 * (much finer-grained than a userspace poll interval).
			 * Subsequent refreshes will read d_ts directly.
			 */
			if (!ri.d_ts) {
				struct watermark wm;

				if (bpf_map_lookup_elem(conn_pending_head_fd,
							&ri.conn_id,
							&wm) == 0) {
					bool is_D = (wm.head_unique == 0) ||
						    (ri.unique < wm.head_unique);

					/*
					 * Guard against stale watermarks from
					 * a previous request batch: wm.ts must
					 * be at or after enqueue time, otherwise
					 * d_ts - q_ts would underflow.
					 */
					if (is_D && wm.ts >= ri.q_ts) {
						ri.d_ts = wm.ts;
						bpf_map_update_elem(
							in_flight_fd,
							&cur_key, &ri,
							BPF_EXIST);
					}
				}
			}

			if (nreqs >= reqs_cap) {
				reqs_cap = reqs_cap ? reqs_cap * 2 : 64;
				reqs = realloc(reqs,
					       reqs_cap * sizeof(*reqs));
				if (!reqs) {
					warn("out of memory\n");
					goto out;
				}
			}

			{
				struct req_display *rd = &reqs[nreqs++];

				rd->req_ptr  = cur_key;
				rd->ri       = ri;
				rd->is_D     = (ri.d_ts != 0);
				rd->total_ms = (double)(now - ri.q_ts) / 1e6;

				if (ri.d_ts) {
					rd->wait_ms = (double)(ri.d_ts - ri.q_ts)
						      / 1e6;
					rd->serv_ms = (double)(now - ri.d_ts)
						      / 1e6;
				} else {
					rd->wait_ms = rd->total_ms;
					rd->serv_ms = 0.0;
				}
			}
next_req:
			prev_key = cur_key;
			has_prev = true;
		}
	}

	/* --- collect workers ------------------------------------------ */
	int nwds = 0, wds_cap = 0;

	{
		bool has_prev = false;

		while (bpf_map_get_next_key(workers_fd,
					    has_prev ? &prev_key : NULL,
					    &cur_key) == 0) {
			if (bpf_map_lookup_elem(workers_fd,
						&cur_key, &wi) != 0)
				goto next_worker;

			/* Remove stale entries for dead daemon threads. */
			if (kill(wi.tid, 0) < 0 && errno == ESRCH) {
				bpf_map_delete_elem(workers_fd, &cur_key);
				goto next_worker;
			}

			if (nwds >= wds_cap) {
				wds_cap = wds_cap ? wds_cap * 2 : 32;
				wds = realloc(wds, wds_cap * sizeof(*wds));
				if (!wds) {
					warn("out of memory\n");
					free(reqs);
					return;
				}
			}
			{
				struct worker_display *wd = &wds[nwds++];

				wd->pid_tgid = cur_key;
				wd->wi       = wi;
				wd->serv_ms  = (double)(now - wi.d_ts) / 1e6;
			}
next_worker:
			prev_key = cur_key;
			has_prev = true;
		}
	}

	/* --- sort ----------------------------------------------------- */
	switch (sort_mode) {
	case SORT_WAIT:
		qsort(reqs, nreqs, sizeof(*reqs), cmp_req_wait);
		break;
	case SORT_SERV:
		qsort(reqs, nreqs, sizeof(*reqs), cmp_req_serv);
		break;
	default:
		qsort(reqs, nreqs, sizeof(*reqs), cmp_req_total);
		break;
	}
	qsort(wds, nwds, sizeof(*wds), cmp_worker_serv);

	/* --- display -------------------------------------------------- */
	if (!no_clear && isatty(STDOUT_FILENO))
		printf("\033[2J\033[H");

	{
		char ts[64];
		const char *sort_str;

		if (str_timestamp("%H:%M:%S", ts, sizeof(ts)) > 0)
			printf("%8s\n", ts);

		switch (sort_mode) {
		case SORT_WAIT: sort_str = "wait time";  break;
		case SORT_SERV: sort_str = "serv time";  break;
		default:        sort_str = "total time"; break;
		}
		printf("FUSE in-flight requests [sorted by %s, %ds interval]"
		       " — Ctrl-C to stop\n", sort_str, interval_s);
	}

	printf("%-6s %-16s %-20s ST  %-7s %-16s %10s %10s\n",
	       "CONN", "OPCODE", "UNIQUE", "PID", "COMM",
	       "WAIT(ms)", "SERV(ms)");

	{
		int show = nreqs < max_rows ? nreqs : max_rows;

		for (int i = 0; i < show; i++) {
			struct req_display *rd = &reqs[i];
			char uniq_str[24];

			snprintf(uniq_str, sizeof(uniq_str), "%llu",
				 (unsigned long long)rd->ri.unique);
			printf("%-6u %-16s %-20s %-3s %-7u %-16s",
			       rd->ri.conn_id,
			       fuse_opcode_name(rd->ri.opcode),
			       uniq_str,
			       rd->is_D ? "D" : "Q",
			       rd->ri.pid,
			       rd->ri.comm);

			if (rd->is_D) {
				printf(" %10.3f %10.3f\n",
				       rd->wait_ms, rd->serv_ms);
			} else {
				printf(" %10.3f %10s\n", rd->wait_ms, "-");
			}
		}

		if (nreqs > max_rows)
			printf("  ... (%d more)\n", nreqs - max_rows);
		else if (nreqs == 0)
			printf("  (no in-flight requests)\n");
	}

	printf("\nFUSE daemon workers [sorted by serv time]:\n");
	printf("%-8s %-16s %-6s %10s\n",
	       "TID", "COMM", "CONN", "SERV(ms)");

	for (int i = 0; i < nwds; i++) {
		struct worker_display *wd = &wds[i];

		printf("%-8u %-16s %-6u %10.3f\n",
		       wd->wi.tid, wd->wi.comm,
		       wd->wi.conn_id, wd->serv_ms);
		if (have_pstack)
			print_worker_stack(wd->wi.tid);
	}
	if (nwds == 0)
		printf("  (no active workers)\n");

	if (no_clear || !isatty(STDOUT_FILENO))
		printf("\n");

out:
	free(reqs);
	free(wds);
}

/* ------------------------------------------------------------------ */

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
	struct bpf_link *enqueue_entry_link  = NULL;
	struct bpf_link *enqueue_exit_link   = NULL;
	struct bpf_link *dequeue_entry_link  = NULL;
	struct bpf_link *dequeue_exit_link   = NULL;
	struct fuseqtop_bpf *obj;
	char enqueue_fn_buf[256];
	char dequeue_fn_buf[256];
	const char *enqueue_fn;
	const char *dequeue_fn;
	struct ksyms *ksyms;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (show_stacks) {
		have_pstack = (access("/usr/bin/pstack", X_OK) == 0);
		if (!have_pstack)
			warn("pstack not found; -s ignored\n");
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr,
			"failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = fuseqtop_bpf__open_opts(&open_opts);
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
	 *   fuse_dev_queue_req       — 6.12+, req is PARM2
	 *   queue_request_and_unlock — 5.15,  req is PARM2 (same probe works)
	 *
	 * Dequeue (D events):
	 *   fuse_dev_do_read.constprop.N — splice() path, needs manual attach
	 *   fuse_dev_read                — regular read() path, auto-attaches
	 *
	 * Both dequeue probes require entry+exit pairs.  The entry stashes
	 * fud for the exit; the exit (ret>0) does the FIFO pop and D-marking.
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
		     "splice() read path D events disabled\n");
		bpf_program__set_autoload(obj->progs.fuse_dev_do_read_entry,
					  false);
		bpf_program__set_autoload(obj->progs.fuse_dev_do_read_exit,
					  false);
	} else {
		/*
		 * fuse_dev_read auto-attaches via its SEC() name.
		 * fuse_dev_do_read.constprop.N needs manual attachment.
		 */
		bpf_program__set_autoattach(obj->progs.fuse_dev_do_read_entry,
					    false);
		bpf_program__set_autoattach(obj->progs.fuse_dev_do_read_exit,
					    false);
	}

	err = fuseqtop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup_obj;
	}

	err = fuseqtop_bpf__attach(obj);
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

	/* Manually attach splice-path dequeue entry+exit probes. */
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

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	fprintf(stderr, "Tracing in-flight FUSE requests");
	if (target_connid)
		fprintf(stderr, " on connection %u", target_connid);
	if (target_pid)
		fprintf(stderr, " from PID %d", target_pid);
	fprintf(stderr, "... Hit Ctrl-C to end.\n");

	while (!exiting) {
		sleep(interval_s);
		display_snapshot(obj);
	}

cleanup:
	bpf_link__destroy(enqueue_entry_link);
	bpf_link__destroy(enqueue_exit_link);
	bpf_link__destroy(dequeue_entry_link);
	bpf_link__destroy(dequeue_exit_link);
cleanup_obj:
	fuseqtop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
