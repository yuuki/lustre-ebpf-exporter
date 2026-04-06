//go:build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define OP_LOOKUP 1
#define OP_OPEN 2
#define OP_READ 3
#define OP_WRITE 4
#define OP_FSYNC 5
#define OP_QUEUE_WAIT 6
#define OP_SEND_NEW_REQ 7
#define OP_FREE_REQ 8
#define PLANE_LLITE 1
#define PLANE_PTLRPC 2

#define ACTOR_USER          0
#define ACTOR_CLIENT_WORKER 1
#define ACTOR_BATCH_JOB     2
#define ACTOR_SYSTEM_DAEMON 3

#define INTENT_NAMESPACE_READ     0
#define INTENT_NAMESPACE_MUTATION 1
#define INTENT_DATA_READ          2
#define INTENT_DATA_WRITE         3
#define INTENT_SYNC               4
#define INTENT_UNKNOWN            0xFF

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct super_block {
  __u32 s_dev;
};

struct inode {
  struct super_block *i_sb;
};

struct file {
  struct inode *f_inode;
};

struct kiocb {
  struct file *ki_filp;
};
#pragma clang attribute pop

struct mount_key {
  __u32 major;
  __u32 minor;
};

struct start_info {
  __u64 start_ns;
  __u32 uid;
  __u32 pid;
  char comm[TASK_COMM_LEN];
  __u64 request_ptr;
  __u8 mount_idx;
};

struct observer_event {
  __u8 plane;
  __u8 op;
  __u8 pad[6];
  __u32 uid;
  __u32 pid;
  __u32 mount_idx;
  __u64 duration_us;
  __u64 size_bytes;
  __u64 request_ptr;
  char comm[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, struct mount_key);
  __type(value, __u8);
} config_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct start_info);
} ll_lookup_map SEC(".maps"), ll_open_map SEC(".maps"), ll_read_map SEC(".maps"),
    ll_write_map SEC(".maps"), ll_fsync_map SEC(".maps"), rpc_wait_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, __u8);
} selected_mount_tids SEC(".maps"), tracked_reqs SEC(".maps");

struct agg_key {
  __u32 uid;
  __u8  op;
  __u8  mount_idx;
  __u8  actor_type;
  __u8  intent;
  char  comm[TASK_COMM_LEN];
};

struct counter_val {
  __u64 ops_count;
  __u64 bytes_sum;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 16384);
  __type(key, struct agg_key);
  __type(value, struct counter_val);
} llite_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct agg_key);
  __type(value, struct counter_val);
} rpc_counters SEC(".maps");

static __always_inline __u8 classify_actor_type(const char comm[TASK_COMM_LEN]) {
  if (comm[0]=='p' && comm[1]=='t' && comm[2]=='l' && comm[3]=='r' &&
      comm[4]=='p' && comm[5]=='c' && comm[6]=='d' && comm[7]=='_')
    return ACTOR_CLIENT_WORKER;
  if (comm[0]=='s' && comm[1]=='l' && comm[2]=='u' && comm[3]=='r' && comm[4]=='m')
    return ACTOR_BATCH_JOB;
  if (comm[0]=='p' && comm[1]=='b' && comm[2]=='s' && comm[3]=='_')
    return ACTOR_BATCH_JOB;
  if (comm[0]=='s' && comm[1]=='g' && comm[2]=='e' && comm[3]=='_')
    return ACTOR_BATCH_JOB;
  if (comm[0]=='l' && comm[1]=='s' && comm[2]=='f' && comm[3]=='_')
    return ACTOR_BATCH_JOB;
  return ACTOR_USER;
}

static __always_inline __u8 intent_for_op(__u8 op) {
  switch (op) {
  case OP_LOOKUP: case OP_OPEN:  return INTENT_NAMESPACE_READ;
  case OP_READ:                  return INTENT_DATA_READ;
  case OP_WRITE:                 return INTENT_DATA_WRITE;
  case OP_FSYNC:                 return INTENT_SYNC;
  default:                       return INTENT_UNKNOWN;
  }
}

static __always_inline void increment_counter(void *map, struct start_info *info,
                                               __u8 op, __u8 actor_type, __u8 intent,
                                               __u64 size_bytes) {
  struct agg_key key = {};
  key.uid = info->uid;
  key.op = op;
  key.mount_idx = info->mount_idx;
  key.actor_type = actor_type;
  key.intent = intent;
  __builtin_memcpy(key.comm, info->comm, TASK_COMM_LEN);

  struct counter_val *val = bpf_map_lookup_elem(map, &key);
  if (val) {
    __sync_fetch_and_add(&val->ops_count, 1);
    __sync_fetch_and_add(&val->bytes_sum, size_bytes);
  } else {
    struct counter_val new_val = {.ops_count = 1, .bytes_sum = size_bytes};
    bpf_map_update_elem(map, &key, &new_val, BPF_NOEXIST);
  }
}

static __always_inline __u64 current_tid(void) {
  return bpf_get_current_pid_tgid();
}

static __always_inline void fill_start_info(struct start_info *info, __u64 request_ptr) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 uid_gid = bpf_get_current_uid_gid();
  info->start_ns = bpf_ktime_get_ns();
  info->uid = uid_gid;
  info->pid = pid_tgid >> 32;
  info->request_ptr = request_ptr;
  bpf_get_current_comm(&info->comm, sizeof(info->comm));
}

static __always_inline int lookup_mount(__u32 s_dev, __u8 *mount_idx) {
  struct mount_key key = {};
  key.major = s_dev >> 20;
  key.minor = s_dev & 1048575;
  __u8 *val = bpf_map_lookup_elem(&config_map, &key);
  if (!val) {
    return 0;
  }
  *mount_idx = *val;
  return 1;
}

static __always_inline int read_inode_dev(struct inode *inode, __u32 *s_dev) {
  if (!inode) {
    return 0;
  }
  struct super_block *sb = BPF_CORE_READ(inode, i_sb);
  if (!sb) {
    return 0;
  }
  *s_dev = BPF_CORE_READ(sb, s_dev);
  return 1;
}

static __always_inline int read_file_dev(struct file *file, __u32 *s_dev) {
  if (!file) {
    return 0;
  }
  struct inode *inode = BPF_CORE_READ(file, f_inode);
  return read_inode_dev(inode, s_dev);
}

static __always_inline int read_kiocb_dev(struct kiocb *kiocb, __u32 *s_dev) {
  if (!kiocb) {
    return 0;
  }
  struct file *file = BPF_CORE_READ(kiocb, ki_filp);
  return read_file_dev(file, s_dev);
}

static __always_inline int emit_from_start(void *ctx, struct start_info *info, __u8 plane, __u8 op, __u64 duration_us, __u64 size_bytes, __u64 request_ptr) {
  struct observer_event event = {};
  event.plane = plane;
  event.op = op;
  event.uid = info->uid;
  event.pid = info->pid;
  event.mount_idx = (__u32)info->mount_idx;
  event.duration_us = duration_us;
  event.size_bytes = size_bytes;
  event.request_ptr = request_ptr;
  __builtin_memcpy(event.comm, info->comm, sizeof(event.comm));
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}

#if defined(__TARGET_ARCH_x86)
#define SYSCALL_OPENAT "__x64_sys_openat"
#define SYSCALL_OPENAT2 "__x64_sys_openat2"
#define SYSCALL_READ "__x64_sys_read"
#define SYSCALL_WRITE "__x64_sys_write"
#define SYSCALL_FSYNC "__x64_sys_fsync"
#elif defined(__TARGET_ARCH_arm64)
#define SYSCALL_OPENAT "__arm64_sys_openat"
#define SYSCALL_OPENAT2 "__arm64_sys_openat2"
#define SYSCALL_READ "__arm64_sys_read"
#define SYSCALL_WRITE "__arm64_sys_write"
#define SYSCALL_FSYNC "__arm64_sys_fsync"
#else
#error Unsupported target architecture
#endif

SEC("kprobe/ll_lookup_nd")
int ll_lookup_nd_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 mount_idx = 0;
  if (!read_inode_dev(inode, &s_dev) || !lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  bpf_map_update_elem(&ll_lookup_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &mount_idx, BPF_ANY);
  return 0;
}

SEC("kprobe/ll_file_open")
int ll_file_open_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 mount_idx = 0;
  if (!read_inode_dev(inode, &s_dev) || !lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  bpf_map_update_elem(&ll_open_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &mount_idx, BPF_ANY);
  return 0;
}

SEC("kprobe/ll_file_read_iter")
int ll_file_read_iter_enter(struct pt_regs *ctx) {
  struct kiocb *kiocb = (struct kiocb *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 mount_idx = 0;
  if (!read_kiocb_dev(kiocb, &s_dev) || !lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  bpf_map_update_elem(&ll_read_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &mount_idx, BPF_ANY);
  return 0;
}

SEC("kprobe/ll_file_write_iter")
int ll_file_write_iter_enter(struct pt_regs *ctx) {
  struct kiocb *kiocb = (struct kiocb *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 mount_idx = 0;
  if (!read_kiocb_dev(kiocb, &s_dev) || !lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  bpf_map_update_elem(&ll_write_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &mount_idx, BPF_ANY);
  return 0;
}

SEC("kprobe/ll_fsync")
int ll_fsync_enter(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 mount_idx = 0;
  if (!read_file_dev(file, &s_dev) || !lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  bpf_map_update_elem(&ll_fsync_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &mount_idx, BPF_ANY);
  return 0;
}

static __always_inline int emit_llite_event(void *ctx, struct start_info *info, __u8 op, long ret, int emit_bytes) {
  __u64 duration_us = (bpf_ktime_get_ns() - info->start_ns) / 1000;
  __u64 size_bytes = (emit_bytes && ret > 0) ? (__u64)ret : 0;

  __u8 actor_type = classify_actor_type(info->comm);
  __u8 intent = intent_for_op(op);
  increment_counter(&llite_counters, info, op, actor_type, intent, size_bytes);

  emit_from_start(ctx, info, PLANE_LLITE, op, duration_us, size_bytes, 0);
  return 0;
}

SEC("kretprobe/" SYSCALL_OPENAT)
int sys_exit_openat(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  long ret = PT_REGS_RC(ctx);
  struct start_info *lookup_info = bpf_map_lookup_elem(&ll_lookup_map, &tid);
  struct start_info *open_info = bpf_map_lookup_elem(&ll_open_map, &tid);
  if (lookup_info) {
    emit_llite_event(ctx, lookup_info, OP_LOOKUP, ret, 0);
    bpf_map_delete_elem(&ll_lookup_map, &tid);
  }
  if (open_info) {
    emit_llite_event(ctx, open_info, OP_OPEN, ret, 0);
    bpf_map_delete_elem(&ll_open_map, &tid);
  }
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kretprobe/" SYSCALL_OPENAT2)
int sys_exit_openat2(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  long ret = PT_REGS_RC(ctx);
  struct start_info *lookup_info = bpf_map_lookup_elem(&ll_lookup_map, &tid);
  struct start_info *open_info = bpf_map_lookup_elem(&ll_open_map, &tid);
  if (lookup_info) {
    emit_llite_event(ctx, lookup_info, OP_LOOKUP, ret, 0);
    bpf_map_delete_elem(&ll_lookup_map, &tid);
  }
  if (open_info) {
    emit_llite_event(ctx, open_info, OP_OPEN, ret, 0);
    bpf_map_delete_elem(&ll_open_map, &tid);
  }
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kretprobe/" SYSCALL_READ)
int sys_exit_read(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  long ret = PT_REGS_RC(ctx);
  struct start_info *info = bpf_map_lookup_elem(&ll_read_map, &tid);
  if (!info) {
    return 0;
  }
  emit_llite_event(ctx, info, OP_READ, ret, 1);
  bpf_map_delete_elem(&ll_read_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kretprobe/" SYSCALL_WRITE)
int sys_exit_write(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  long ret = PT_REGS_RC(ctx);
  struct start_info *info = bpf_map_lookup_elem(&ll_write_map, &tid);
  if (!info) {
    return 0;
  }
  emit_llite_event(ctx, info, OP_WRITE, ret, 1);
  bpf_map_delete_elem(&ll_write_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kretprobe/" SYSCALL_FSYNC)
int sys_exit_fsync(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  long ret = PT_REGS_RC(ctx);
  struct start_info *info = bpf_map_lookup_elem(&ll_fsync_map, &tid);
  if (!info) {
    return 0;
  }
  emit_llite_event(ctx, info, OP_FSYNC, ret, 0);
  bpf_map_delete_elem(&ll_fsync_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kprobe/ptlrpc_send_new_req")
int ptlrpc_send_new_req_enter(struct pt_regs *ctx) {
  __u64 req_ptr = PT_REGS_PARM1(ctx);
  __u64 tid = current_tid();
  __u8 *midx = bpf_map_lookup_elem(&selected_mount_tids, &tid);
  struct start_info info = {};
  if (!midx) {
    return 0;
  }
  __u8 mount_idx = *midx;
  fill_start_info(&info, req_ptr);
  info.mount_idx = mount_idx;
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  bpf_map_update_elem(&tracked_reqs, &info.request_ptr, &mount_idx, BPF_ANY);
  emit_from_start(ctx, &info, PLANE_PTLRPC, OP_SEND_NEW_REQ, 0, 0, info.request_ptr);
  return 0;
}

SEC("kprobe/ptlrpc_queue_wait")
int ptlrpc_queue_wait_enter(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  __u64 req_ptr = PT_REGS_PARM1(ctx);
  struct start_info info = {};
  __u8 mount_idx = 0;

  __u8 *selected = bpf_map_lookup_elem(&selected_mount_tids, &tid);
  if (selected) {
    mount_idx = *selected;
    bpf_map_delete_elem(&selected_mount_tids, &tid);
  } else {
    __u8 *tracked = bpf_map_lookup_elem(&tracked_reqs, &req_ptr);
    if (!tracked) {
      return 0;
    }
    mount_idx = *tracked;
  }

  fill_start_info(&info, req_ptr);
  info.mount_idx = mount_idx;
  bpf_map_update_elem(&rpc_wait_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&tracked_reqs, &req_ptr, &mount_idx, BPF_ANY);
  return 0;
}

SEC("kretprobe/ptlrpc_queue_wait")
int ptlrpc_queue_wait_exit(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  struct start_info *info = bpf_map_lookup_elem(&rpc_wait_map, &tid);
  if (!info) {
    return 0;
  }
  __u8 actor_type = classify_actor_type(info->comm);
  increment_counter(&rpc_counters, info, OP_QUEUE_WAIT, actor_type, INTENT_UNKNOWN, 0);

  emit_from_start(ctx, info, PLANE_PTLRPC, OP_QUEUE_WAIT, (bpf_ktime_get_ns() - info->start_ns) / 1000, 0, info->request_ptr);
  bpf_map_delete_elem(&rpc_wait_map, &tid);
  return 0;
}

SEC("kprobe/__ptlrpc_free_req")
int ptlrpc_free_req_enter(struct pt_regs *ctx) {
  __u64 req_ptr = PT_REGS_PARM1(ctx);
  __u8 *tracked = bpf_map_lookup_elem(&tracked_reqs, &req_ptr);
  struct start_info info = {};
  if (!tracked) {
    return 0;
  }
  fill_start_info(&info, req_ptr);
  info.mount_idx = *tracked;
  emit_from_start(ctx, &info, PLANE_PTLRPC, OP_FREE_REQ, 0, 0, req_ptr);
  bpf_map_delete_elem(&tracked_reqs, &req_ptr);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
