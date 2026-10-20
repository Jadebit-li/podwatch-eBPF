// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <bpf/bpf_endian.h>
#define AF_INET 2
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

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

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->open_event = false;
        e->connect_event = false;
        e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
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

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
        e->open_event = false;
        e->connect_event = false;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline bool starts_with(const char *s, const char *prefix, int len)
{
        for (int i = 0; i < len; i++) {
                if (s[i] != prefix[i])
                        return false;
        }
        return true;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
        struct task_struct *task;
        struct event *e;
        pid_t pid;

        pid = bpf_get_current_pid_tgid() >> 32;

        /* 1. reserve space in the ring buffer (copy from exec) */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
        /* 2. fill in: open_event, cgroup_id, pid, comm */
	task = (struct task_struct *)bpf_get_current_task();
	
	e->open_event = true;
	e->exit_event = false;
        e->connect_event = false;
        e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
        
	/* 3. read the filename (see below) */
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)ctx->args[1]);
        const char tok[] = "/var/run/secrets/kubernetes.io/serviceaccount";
        const char shadow[] = "/etc/shadow";

        if (!starts_with(e->filename, tok, sizeof(tok) - 1) &&
            !starts_with(e->filename, shadow, sizeof(shadow) - 1)) {
                bpf_ringbuf_discard(e, 0);
                return 0;
        }

	/* 4. submit (copy from exec) */
	bpf_ringbuf_submit(e, 0);
        return 0;
}


SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
        struct sockaddr_in sa = {};
        struct task_struct *task;
        struct event *e;
        pid_t pid;

        /* get pid (copy from openat) */
        pid = bpf_get_current_pid_tgid() >> 32;
        /* copy the address struct from user memory */
        bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
        if (sa.sin_family != AF_INET)
                return 0;

        /* reserve space, get task (copy from openat) */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
                return 0;

        /* set the 3 labels: exit_event=false, open_event=false, connect_event=true */
	task = (struct task_struct *)bpf_get_current_task();
        e->open_event = false;
        e->exit_event = false;
        e->connect_event = true;

	/* set cgroup_id, pid, ppid, comm (copy from openat) */
	e->cgroup_id = bpf_get_current_cgroup_id();
        e->pid = pid;
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->daddr = sa.sin_addr.s_addr;
        e->dport = bpf_ntohs(sa.sin_port);

        /* submit (copy from openat) */
	bpf_ringbuf_submit(e, 0);
        return 0;
}
