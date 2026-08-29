// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "zayosentry.h"
#include "zayosentry.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "zayosentry 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF zayosentry demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./zayosentry [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'v':
			env.verbose = true;
			break;
		case 'd':
			errno = 0;
			env.min_duration_ms = strtol(arg, NULL, 10);
			if (errno || env.min_duration_ms <= 0) {
				fprintf(stderr, "Invalid duration: %s\n", arg);
				argp_usage(state);
			}
			break;
		case ARGP_KEY_ARG:
			argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (e->is_open_event) {
		if ((e->open_flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) &&
			(strstr(e->open_filename, "/etc/init.d/") ||
			strstr(e->open_filename, "/etc/rc.d/") ||
			strstr(e->open_filename, "/etc/systemd/system/"))) {
			if (strcmp(e->comm, "systemd") != 0 && strcmp(e->comm, "dbus-daemon") != 0) {
				printf("\033[1;34m[TELEMETRY]\033[0m Persistence Mechanism (Boot Script Modification) Detected! | "
				"PID: %d | COMM: %s | PATH: %s\n", e->pid, e->comm, e->open_filename);
			}
		}
		return 0;
	}

	if (e->is_unlink_event) {
		char exe_path[512];
		char proc_path[256];
		ssize_t len;
		snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", e->pid);
		len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
		if (len > 0) {
			exe_path[len] = '\0';
			if (strstr(exe_path, " (deleted)")) {
				printf("\033[1;34m[TELEMETRY]\033[0m Self-Deletion (Running from Memory) Detected! | "
				"PID: %d, COMM: %s, EXE: %s\n", e->pid, e->comm, exe_path);
			}
		}
		return 0;
	}

	if (e->is_ptrace_event) {
		printf("\033[1;34m[TELEMETRY]\033[0m Ptrace Activity (Process Injection/Debugging) Detected! | "
		"Source PID: %d, Process Name: %s, Ptrace Request: %ld, Target PID: %ld\n",
		 e->pid, e->comm, e->ptrace_request, e->ptrace_target_pid);
		return 0;
	}

	if (e->is_socket_event) {
		printf("\033[1;34m[TELEMETRY]\033[0m AF_PACKET Raw Socket Detected! | "
		"PID: %d, COMM: %s, DOMAIN: %d, TYPE: %d\n", e->pid, e->comm,
		 e->sock_domain, e->sock_type);
		return 0;
	}

	/* YENI EKLENEN KANCALARIN C TARAFINDA YAZILMASI */
	if (e->is_connect_event) {
		struct in_addr addr = { .s_addr = e->daddr_ip };
		printf("\033[1;34m[TELEMETRY]\033[0m Outbound Connection Detected! | "
		"PID: %d, COMM: %s, DEST IP: %s, PORT: %d\n",
		 e->pid, e->comm, inet_ntoa(addr), ntohs(e->daddr_port));
		return 0;
	}

	if (e->is_setsockopt_event) {
		printf("\033[1;34m[TELEMETRY]\033[0m Classic BPF Socket Filter Attached | "
		"PID: %d, COMM: %s, OPTLEVEL: %d, OPTNAME: %d\n",
		 e->pid, e->comm, e->optlevel, e->optname);
		return 0;
	}

	if (e->is_prctl_event) {
		printf("\033[1;34m[TELEMETRY]\033[0m Process Renaming (PR_SET_NAME) Detected! | "
		"PID: %d, COMM: %s, NEW_NAME: %s\n",
		 e->pid, e->comm, e->prctl_arg2);
		return 0;
	}

	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->exit_event) {
		printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
		if (e->duration_ns) printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else {
		if (!strcmp(e->filename, "/bin/sh") || !strcmp(e->filename, "/usr/bin/sh") ||
			!strcmp(e->filename, "/bin/bash") || !strcmp(e->filename, "/usr/bin/bash")) {
			printf("\033[1;34m[TELEMETRY]\033[0m Suspicious Shell Execution Detected! | "
			"PID: %d, COMM: %s, FILENAME: %s\n", e->pid, e->comm, e->filename);
			}
			if (!strncmp(e->filename, "/tmp/", 5) || !strncmp(e->filename, "/var/tmp/", 9) ||
				!strncmp(e->filename, "/dev/shm/", 9)) {
				printf("\033[1;34m[TELEMETRY]\033[0m Executable launched from writable directory! | "
				"PID: %d, COMM: %s, FILENAME: %s\n", e->pid, e->comm, e->filename);
				}
				printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
	}

	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	struct ring_buffer *rb = NULL;
	struct zayosentry_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = zayosentry_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	err = zayosentry_bpf__load(skel);
	if (err) goto cleanup;

	err = zayosentry_bpf__attach(skel);
	if (err) goto cleanup;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		goto cleanup;
	}

	printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

	cleanup:
	ring_buffer__free(rb);
	zayosentry_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
