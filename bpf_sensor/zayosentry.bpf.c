// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "zayosentry.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	task = (struct task_struct *)bpf_get_current_task();
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;
	if (pid != tid) return 0;

	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts) duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns) return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	if (min_duration_ns && duration_ns < min_duration_ns) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	task = (struct task_struct *)bpf_get_current_task();
	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx)
{
	int domain = (int)ctx->args[0];
	int type = (int)ctx->args[1];
	struct event *e;

	if (domain != 17) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->is_socket_event = true;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->sock_domain = domain;
	e->sock_type = type;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	long request = (long)ctx->args[0];
	long target_pid = (long)ctx->args[1];
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->is_ptrace_event = true;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->ptrace_request = request;
	e->ptrace_target_pid = target_pid;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->is_unlink_event = true;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

struct open_how_local {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

static __always_inline int handle_open(void *ctx, const char *filename, int flags)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	if (bpf_probe_read_user_str(&e->open_filename, sizeof(e->open_filename), filename) <= 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->is_open_event = true;
	e->exit_event = false;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->open_flags = flags;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
	return handle_open(ctx, (const char *)ctx->args[0], ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_open(ctx, (const char *)ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tracepoint__syscalls__sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
	struct open_how_local how = {};
	int flags = 0;
	if (bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]) == 0)
		flags = (int)how.flags;
	return handle_open(ctx, (const char *)ctx->args[1], flags);
}

/* YENI EKLENEN AĞ VE DAVRANIŞ KANCALARI */

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr_in addr = {};
	struct event *e;

	if (bpf_probe_read_user(&addr, sizeof(addr), (void *)ctx->args[1]) != 0)
		return 0;

	// Sadece IPv4 yakalayalim (AF_INET = 2)
	if (addr.sin_family != 2) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->is_connect_event = true;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->daddr_ip = addr.sin_addr.s_addr;
	e->daddr_port = addr.sin_port;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int handle_setsockopt(struct trace_event_raw_sys_enter *ctx)
{
	int level = (int)ctx->args[1];
	int optname = (int)ctx->args[2];
	struct event *e;

	// SOL_SOCKET = 1, SO_ATTACH_FILTER = 26
	if (level != 1 || optname != 26) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->is_setsockopt_event = true;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->optlevel = level;
	e->optname = optname;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int handle_prctl(struct trace_event_raw_sys_enter *ctx)
{
	int option = (int)ctx->args[0];
	struct event *e;

	// PR_SET_NAME = 15
	if (option != 15) return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->is_prctl_event = true;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->prctl_option = option;
	bpf_probe_read_user_str(&e->prctl_arg2, sizeof(e->prctl_arg2), (void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
