/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
	bool is_socket_event;
	int sock_domain;
	int sock_type;
	bool is_ptrace_event;
	long ptrace_request;
	long ptrace_target_pid;
	bool is_unlink_event;
	bool is_open_event;
	int open_flags;
	char open_filename[256];

	/* YENI EKLENEN KANCALAR */
	bool is_connect_event;
	unsigned int daddr_ip;
	unsigned short daddr_port;

	bool is_setsockopt_event;
	int optlevel;
	int optname;

	bool is_prctl_event;
	int prctl_option;
	char prctl_arg2[16];
};

#endif /* __BOOTSTRAP_H */
