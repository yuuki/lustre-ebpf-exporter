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
#define OP_CLOSE 9
#define OP_GETATTR 10
#define OP_GETXATTR 11
#define OP_MKDIR 12
#define OP_MKNOD 13
#define OP_RENAME 14
#define OP_RMDIR 15
#define OP_SETATTR 16
#define OP_SETXATTR 17
#define OP_STATFS 18
#define PLANE_LLITE 1
#define PLANE_PTLRPC 2
#define PLANE_PCC 3

/* PCC-specific operation codes. PCC I/O ops use a separate range (22-26)
 * from their llite counterparts (1-5) to avoid inflight_map key collisions:
 * ll_file_read_iter calls pcc_file_read_iter internally, so both kprobes
 * fire on the same thread — distinct op codes ensure distinct inflight_keys. */
#define OP_PCC_ATTACH     19
#define OP_PCC_DETACH     20
#define OP_PCC_INVALIDATE 21
#define OP_PCC_READ       22
#define OP_PCC_WRITE      23
#define OP_PCC_OPEN       24
#define OP_PCC_LOOKUP     25
#define OP_PCC_FSYNC      26

/* PCC attach mode (packed into request_ptr high byte). */
#define PCC_MODE_RO  1
#define PCC_MODE_RW  2
/* PCC attach trigger (packed into request_ptr low byte). */
#define PCC_TRIGGER_MANUAL 1
#define PCC_TRIGGER_AUTO   2

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

#define ERRNO_CLASS_NONE     0
#define ERRNO_CLASS_TIMEOUT  1
#define ERRNO_CLASS_NOTCONN  2
#define ERRNO_CLASS_PERM     3
#define ERRNO_CLASS_NOTFOUND 4
#define ERRNO_CLASS_IO       5
#define ERRNO_CLASS_AGAIN    6
#define ERRNO_CLASS_OTHER    7

#define RPC_EVENT_RESEND   1
#define RPC_EVENT_RESTART  2
#define RPC_EVENT_EXPIRE   3
#define RPC_EVENT_NOTCONN  4

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

struct vfsmount;

struct dentry {
  struct inode *d_inode;
};

struct path {
  struct vfsmount *mnt;
  struct dentry *dentry;
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

struct inflight_key {
  __u64 tid;
  __u8  op;
  __u8  pad[7];
};

struct observer_event {
  __u8 plane;
  __u8 op;
  __u8 errno_class;
  __u8 pad[5];
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
  __uint(max_entries, 65536);
  __type(key, struct inflight_key);
  __type(value, struct start_info);
} inflight_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, __u8);
} selected_mount_tids SEC(".maps");

/* Preserved identity of the original request submitter. PtlRPC recovery
 * functions (resend, restart, expire, notconn) run in ptlrpcd worker
 * context, so bpf_get_current_uid_gid/comm would return the worker's
 * identity instead of the affected user. Storing the submitter's identity
 * at send_new_req/queue_wait time lets error probes attribute events to
 * the right user. */
struct tracked_req_info {
  __u32 uid;
  __u32 pid;
  __u8  mount_idx;
  __u8  pad[7];
  char  comm[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u64);
  __type(value, struct tracked_req_info);
} tracked_reqs SEC(".maps");

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
  __uint(max_entries, 2048);
  __type(key, struct agg_key);
  __type(value, struct counter_val);
} llite_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 2048);
  __type(key, struct agg_key);
  __type(value, struct counter_val);
} rpc_counters SEC(".maps");

struct error_agg_key {
  __u32 uid;
  __u8  op;
  __u8  mount_idx;
  __u8  actor_type;
  __u8  intent;
  __u8  reason;
  __u8  pad[7];
  char  comm[TASK_COMM_LEN];
};

struct error_counter_val {
  __u64 ops_count;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 1024);
  __type(key, struct error_agg_key);
  __type(value, struct error_counter_val);
} llite_error_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 512);
  __type(key, struct error_agg_key);
  __type(value, struct error_counter_val);
} rpc_error_counters SEC(".maps");

/* PCC counter maps — same key/value schemas as llite_counters / llite_error_counters
 * but for operations routed through the PCC cache layer. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 2048);
  __type(key, struct agg_key);
  __type(value, struct counter_val);
} pcc_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 512);
  __type(key, struct error_agg_key);
  __type(value, struct error_counter_val);
} pcc_error_counters SEC(".maps");

static __always_inline __u8 classify_errno(long ret) {
  if (ret >= 0) return ERRNO_CLASS_NONE;
  long e = -ret;
  switch (e) {
  case 110: return ERRNO_CLASS_TIMEOUT;
  case 107: return ERRNO_CLASS_NOTCONN;
  case 1: case 13: return ERRNO_CLASS_PERM;
  case 2: case 20: return ERRNO_CLASS_NOTFOUND;
  case 5: case 121: return ERRNO_CLASS_IO;
  case 11: return ERRNO_CLASS_AGAIN;
  default: return ERRNO_CLASS_OTHER;
  }
}

static __always_inline void increment_error_counter(void *map,
    struct start_info *info, __u8 op, __u8 actor_type, __u8 intent,
    __u8 reason) {
  struct error_agg_key key = {};
  key.uid = info->uid;
  key.op = op;
  key.mount_idx = info->mount_idx;
  key.actor_type = actor_type;
  key.intent = intent;
  key.reason = reason;
  __builtin_memcpy(key.comm, info->comm, TASK_COMM_LEN);

  struct error_counter_val *val = bpf_map_lookup_elem(map, &key);
  if (val) {
    __sync_fetch_and_add(&val->ops_count, 1);
  } else {
    struct error_counter_val new_val = {.ops_count = 1};
    bpf_map_update_elem(map, &key, &new_val, BPF_NOEXIST);
  }
}

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
  case OP_LOOKUP: case OP_OPEN:
  case OP_CLOSE: case OP_GETATTR: case OP_GETXATTR: case OP_STATFS:
  case OP_PCC_LOOKUP: case OP_PCC_OPEN:
    return INTENT_NAMESPACE_READ;
  case OP_MKDIR: case OP_MKNOD: case OP_RENAME: case OP_RMDIR:
  case OP_SETATTR: case OP_SETXATTR:
  case OP_PCC_ATTACH: case OP_PCC_DETACH: case OP_PCC_INVALIDATE:
    return INTENT_NAMESPACE_MUTATION;
  case OP_READ:     case OP_PCC_READ:  return INTENT_DATA_READ;
  case OP_WRITE:    case OP_PCC_WRITE: return INTENT_DATA_WRITE;
  case OP_FSYNC:    case OP_PCC_FSYNC: return INTENT_SYNC;
  default:                             return INTENT_UNKNOWN;
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

static __always_inline int read_dentry_dev(struct dentry *dentry, __u32 *s_dev) {
  if (!dentry) {
    return 0;
  }
  struct inode *inode = BPF_CORE_READ(dentry, d_inode);
  return read_inode_dev(inode, s_dev);
}

static __always_inline int read_path_dev(struct path *path, __u32 *s_dev) {
  if (!path) {
    return 0;
  }
  struct dentry *dentry = BPF_CORE_READ(path, dentry);
  return read_dentry_dev(dentry, s_dev);
}

static __always_inline int track_llite_enter(__u8 op, __u32 s_dev) {
  __u8 mount_idx = 0;
  if (!lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  __u64 tid = current_tid();
  struct start_info info = {};
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  struct inflight_key key = {.tid = tid, .op = op};
  bpf_map_update_elem(&inflight_map, &key, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &mount_idx, BPF_ANY);
  return 0;
}

static __always_inline int emit_from_start(void *ctx, struct start_info *info, __u8 plane, __u8 op, __u64 duration_us, __u64 size_bytes, __u64 request_ptr, __u8 errno_class) {
  struct observer_event event = {};
  event.plane = plane;
  event.op = op;
  event.errno_class = errno_class;
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
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_LOOKUP, s_dev);
}

SEC("kprobe/ll_file_open")
int ll_file_open_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_OPEN, s_dev);
}

SEC("kprobe/ll_file_read_iter")
int ll_file_read_iter_enter(struct pt_regs *ctx) {
  struct kiocb *kiocb = (struct kiocb *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_kiocb_dev(kiocb, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_READ, s_dev);
}

SEC("kprobe/ll_file_write_iter")
int ll_file_write_iter_enter(struct pt_regs *ctx) {
  struct kiocb *kiocb = (struct kiocb *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_kiocb_dev(kiocb, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_WRITE, s_dev);
}

SEC("kprobe/ll_fsync")
int ll_fsync_enter(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_file_dev(file, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_FSYNC, s_dev);
}

static __always_inline int emit_llite_event(void *ctx, struct start_info *info, __u8 op, long ret, int emit_bytes) {
  __u64 duration_us = (bpf_ktime_get_ns() - info->start_ns) / 1000;
  __u64 size_bytes = (emit_bytes && ret > 0) ? (__u64)ret : 0;

  __u8 actor_type = classify_actor_type(info->comm);
  __u8 intent = intent_for_op(op);
  __u8 errno_class = classify_errno(ret);

  increment_counter(&llite_counters, info, op, actor_type, intent, size_bytes);

  if (errno_class != ERRNO_CLASS_NONE) {
    increment_error_counter(&llite_error_counters, info, op,
        actor_type, intent, errno_class);
  }

  emit_from_start(ctx, info, PLANE_LLITE, op, duration_us, size_bytes, 0, errno_class);
  return 0;
}

static __always_inline int finish_llite_op(void *ctx, __u8 op, long ret, int emit_bytes) {
  __u64 tid = current_tid();
  struct inflight_key key = {.tid = tid, .op = op};
  struct start_info *info = bpf_map_lookup_elem(&inflight_map, &key);
  if (!info) {
    return 0;
  }
  emit_llite_event(ctx, info, op, ret, emit_bytes);
  bpf_map_delete_elem(&inflight_map, &key);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

static __always_inline int finish_openat(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  long ret = PT_REGS_RC(ctx);
  struct inflight_key lk = {.tid = tid, .op = OP_LOOKUP};
  struct inflight_key ok = {.tid = tid, .op = OP_OPEN};
  struct start_info *lookup_info = bpf_map_lookup_elem(&inflight_map, &lk);
  struct start_info *open_info = bpf_map_lookup_elem(&inflight_map, &ok);
  if (lookup_info) {
    emit_llite_event(ctx, lookup_info, OP_LOOKUP, ret, 0);
    bpf_map_delete_elem(&inflight_map, &lk);
  }
  if (open_info) {
    emit_llite_event(ctx, open_info, OP_OPEN, ret, 0);
    bpf_map_delete_elem(&inflight_map, &ok);
  }
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kretprobe/" SYSCALL_OPENAT)
int sys_exit_openat(struct pt_regs *ctx) {
  return finish_openat(ctx);
}

SEC("kretprobe/" SYSCALL_OPENAT2)
int sys_exit_openat2(struct pt_regs *ctx) {
  return finish_openat(ctx);
}

SEC("kretprobe/" SYSCALL_READ)
int sys_exit_read(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_READ, PT_REGS_RC(ctx), 1);
}

SEC("kretprobe/" SYSCALL_WRITE)
int sys_exit_write(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_WRITE, PT_REGS_RC(ctx), 1);
}

SEC("kretprobe/" SYSCALL_FSYNC)
int sys_exit_fsync(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_FSYNC, PT_REGS_RC(ctx), 0);
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

  /* Snapshot the submitter's identity so recovery probes running in
   * ptlrpcd worker context can attribute events to the right user. */
  struct tracked_req_info tri = {};
  tri.uid = info.uid;
  tri.pid = info.pid;
  tri.mount_idx = mount_idx;
  __builtin_memcpy(tri.comm, info.comm, TASK_COMM_LEN);
  bpf_map_update_elem(&tracked_reqs, &info.request_ptr, &tri, BPF_ANY);

  emit_from_start(ctx, &info, PLANE_PTLRPC, OP_SEND_NEW_REQ, 0, 0, info.request_ptr, 0);
  return 0;
}

SEC("kprobe/ptlrpc_queue_wait")
int ptlrpc_queue_wait_enter(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  __u64 req_ptr = PT_REGS_PARM1(ctx);
  struct start_info info = {};
  __u8 mount_idx = 0;
  int is_submitter = 0;

  __u8 *selected = bpf_map_lookup_elem(&selected_mount_tids, &tid);
  if (selected) {
    mount_idx = *selected;
    is_submitter = 1;
  } else {
    struct tracked_req_info *tri = bpf_map_lookup_elem(&tracked_reqs, &req_ptr);
    if (!tri) {
      return 0;
    }
    mount_idx = tri->mount_idx;
  }

  fill_start_info(&info, req_ptr);
  info.mount_idx = mount_idx;
  struct inflight_key key = {.tid = tid, .op = OP_QUEUE_WAIT};
  bpf_map_update_elem(&inflight_map, &key, &info, BPF_ANY);

  /* Only update tracked_reqs when running in the original submitter's
   * context (selected_mount_tids hit). In the fallback path the current
   * task is not the submitter, so writing here would overwrite the
   * stored identity and cause downstream recovery probes to mis-attribute
   * the error to ptlrpcd. */
  if (is_submitter) {
    struct tracked_req_info tri = {};
    tri.uid = info.uid;
    tri.pid = info.pid;
    tri.mount_idx = mount_idx;
    __builtin_memcpy(tri.comm, info.comm, TASK_COMM_LEN);
    bpf_map_update_elem(&tracked_reqs, &req_ptr, &tri, BPF_ANY);
  }
  return 0;
}

SEC("kretprobe/ptlrpc_queue_wait")
int ptlrpc_queue_wait_exit(struct pt_regs *ctx) {
  __u64 tid = current_tid();
  struct inflight_key key = {.tid = tid, .op = OP_QUEUE_WAIT};
  struct start_info *info = bpf_map_lookup_elem(&inflight_map, &key);
  if (!info) {
    return 0;
  }
  __u8 actor_type = classify_actor_type(info->comm);
  increment_counter(&rpc_counters, info, OP_QUEUE_WAIT, actor_type, INTENT_UNKNOWN, 0);

  emit_from_start(ctx, info, PLANE_PTLRPC, OP_QUEUE_WAIT, (bpf_ktime_get_ns() - info->start_ns) / 1000, 0, info->request_ptr, 0);
  bpf_map_delete_elem(&inflight_map, &key);
  return 0;
}

SEC("kprobe/__ptlrpc_free_req")
int ptlrpc_free_req_enter(struct pt_regs *ctx) {
  __u64 req_ptr = PT_REGS_PARM1(ctx);
  struct tracked_req_info *tri = bpf_map_lookup_elem(&tracked_reqs, &req_ptr);
  if (!tri) {
    return 0;
  }
  /* Use stored submitter identity instead of current task context,
   * since free_req may run from a different thread. */
  struct start_info info = {};
  info.uid = tri->uid;
  info.pid = tri->pid;
  info.mount_idx = tri->mount_idx;
  info.request_ptr = req_ptr;
  __builtin_memcpy(info.comm, tri->comm, TASK_COMM_LEN);
  emit_from_start(ctx, &info, PLANE_PTLRPC, OP_FREE_REQ, 0, 0, req_ptr, 0);
  bpf_map_delete_elem(&tracked_reqs, &req_ptr);
  return 0;
}

/*
 * Metadata-op kprobe/kretprobe group.
 *
 * Kernel assumption: Linux 5.12+ idmapped-mount inode_operation signatures
 * (mnt_idmap or user_namespace pointer in PARM1, inode/dentry/path in
 * PARM2). On older kernels the parameter positions shift and s_dev
 * extraction silently yields no event. All probes are optional and
 * graceful skips are handled by internal/goexporter/runtime_linux.go.
 */

SEC("kprobe/ll_file_release")
int ll_file_release_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_CLOSE, s_dev);
}

SEC("kretprobe/ll_file_release")
int ll_file_release_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_CLOSE, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_getattr")
int ll_getattr_enter(struct pt_regs *ctx) {
  struct path *path = (struct path *)PT_REGS_PARM2(ctx);
  __u32 s_dev = 0;
  if (!read_path_dev(path, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_GETATTR, s_dev);
}

SEC("kretprobe/ll_getattr")
int ll_getattr_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_GETATTR, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_xattr_get_common")
int ll_getxattr_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM3(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_GETXATTR, s_dev);
}

SEC("kretprobe/ll_xattr_get_common")
int ll_getxattr_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_GETXATTR, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_xattr_set_common")
int ll_setxattr_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM3(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_SETXATTR, s_dev);
}

SEC("kretprobe/ll_xattr_set_common")
int ll_setxattr_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_SETXATTR, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_mkdir")
int ll_mkdir_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM2(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_MKDIR, s_dev);
}

SEC("kretprobe/ll_mkdir")
int ll_mkdir_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_MKDIR, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_mknod")
int ll_mknod_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM2(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_MKNOD, s_dev);
}

SEC("kretprobe/ll_mknod")
int ll_mknod_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_MKNOD, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_rename")
int ll_rename_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM2(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_RENAME, s_dev);
}

SEC("kretprobe/ll_rename")
int ll_rename_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_RENAME, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_rmdir")
int ll_rmdir_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM2(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_RMDIR, s_dev);
}

SEC("kretprobe/ll_rmdir")
int ll_rmdir_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_RMDIR, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_setattr")
int ll_setattr_enter(struct pt_regs *ctx) {
  struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
  __u32 s_dev = 0;
  if (!read_dentry_dev(dentry, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_SETATTR, s_dev);
}

SEC("kretprobe/ll_setattr")
int ll_setattr_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_SETATTR, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/ll_statfs")
int ll_statfs_enter(struct pt_regs *ctx) {
  struct dentry *dentry = (struct dentry *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_dentry_dev(dentry, &s_dev)) {
    return 0;
  }
  return track_llite_enter(OP_STATFS, s_dev);
}

SEC("kretprobe/ll_statfs")
int ll_statfs_exit(struct pt_regs *ctx) {
  return finish_llite_op(ctx, OP_STATFS, PT_REGS_RC(ctx), 0);
}

/*
 * PtlRPC error/recovery event kprobes.
 *
 * These entry-only probes fire on PtlRPC recovery actions: resend,
 * restart, request expiry, and ENOTCONN handling. All are optional
 * and degrade gracefully when the symbols are missing.
 */

static __always_inline int record_rpc_error_event(void *ctx, __u8 event_type, __u64 req_ptr) {
  struct tracked_req_info *tri = bpf_map_lookup_elem(&tracked_reqs, &req_ptr);
  if (!tri) {
    /* Request not tracked — we have no submitter identity to attribute
     * the error to. Dropping this event is preferable to mis-attributing
     * it to the current (worker) task. The selected_mount_tids fallback
     * is not useful here because the current thread is typically ptlrpcd,
     * not the original submitter. */
    return 0;
  }

  /* Use the original submitter's identity stored at send_new_req /
   * queue_wait time, not the current task (which is often ptlrpcd). */
  struct start_info info = {};
  info.uid = tri->uid;
  info.pid = tri->pid;
  info.mount_idx = tri->mount_idx;
  info.request_ptr = req_ptr;
  __builtin_memcpy(info.comm, tri->comm, TASK_COMM_LEN);

  __u8 actor_type = classify_actor_type(info.comm);
  increment_error_counter(&rpc_error_counters, &info, 0,
      actor_type, INTENT_UNKNOWN, event_type);
  return 0;
}

SEC("kprobe/ptlrpc_resend_req")
int ptlrpc_resend_req_enter(struct pt_regs *ctx) {
  return record_rpc_error_event(ctx, RPC_EVENT_RESEND, PT_REGS_PARM1(ctx));
}

SEC("kprobe/ptlrpc_restart_req")
int ptlrpc_restart_req_enter(struct pt_regs *ctx) {
  return record_rpc_error_event(ctx, RPC_EVENT_RESTART, PT_REGS_PARM1(ctx));
}

SEC("kprobe/ptlrpc_expire_one_request")
int ptlrpc_expire_one_request_enter(struct pt_regs *ctx) {
  return record_rpc_error_event(ctx, RPC_EVENT_EXPIRE, PT_REGS_PARM1(ctx));
}

SEC("kprobe/ptlrpc_request_handle_notconn")
int ptlrpc_request_handle_notconn_enter(struct pt_regs *ctx) {
  return record_rpc_error_event(ctx, RPC_EVENT_NOTCONN, PT_REGS_PARM1(ctx));
}

/*
 * PCC (Persistent Client Cache) kprobes.
 *
 * PCC is a client-local persistent cache with RO/RW modes. When PCC is
 * active, ll_file_read_iter calls pcc_file_read_iter internally, so both
 * kprobes fire on the same thread. PCC ops use a dedicated op-code range
 * (OP_PCC_READ=22, etc.) to avoid inflight_map key collisions with the
 * llite ops (OP_READ=3, etc.).
 *
 * All PCC probes are optional: the PCC module may not be loaded.
 */

/* ---------- PCC helpers ---------- */

static __always_inline int track_pcc_enter(__u8 op, __u32 s_dev) {
  __u8 mount_idx = 0;
  if (!lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  __u64 tid = current_tid();
  struct start_info info = {};
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  struct inflight_key key = {.tid = tid, .op = op};
  bpf_map_update_elem(&inflight_map, &key, &info, BPF_ANY);
  /* No selected_mount_tids update: PCC bypasses PtlRPC. */
  return 0;
}

static __always_inline int emit_pcc_event(void *ctx, struct start_info *info,
    __u8 op, long ret, int emit_bytes) {
  __u64 duration_us = (bpf_ktime_get_ns() - info->start_ns) / 1000;
  __u64 size_bytes = (emit_bytes && ret > 0) ? (__u64)ret : 0;

  __u8 actor_type = classify_actor_type(info->comm);
  __u8 intent = intent_for_op(op);
  __u8 errno_class = classify_errno(ret);

  increment_counter(&pcc_counters, info, op, actor_type, intent, size_bytes);

  if (errno_class != ERRNO_CLASS_NONE) {
    increment_error_counter(&pcc_error_counters, info, op,
        actor_type, intent, errno_class);
  }

  emit_from_start(ctx, info, PLANE_PCC, op, duration_us, size_bytes,
      info->request_ptr, errno_class);
  return 0;
}

static __always_inline int finish_pcc_op(void *ctx, __u8 op, long ret, int emit_bytes) {
  __u64 tid = current_tid();
  struct inflight_key key = {.tid = tid, .op = op};
  struct start_info *info = bpf_map_lookup_elem(&inflight_map, &key);
  if (!info) {
    return 0;
  }
  emit_pcc_event(ctx, info, op, ret, emit_bytes);
  bpf_map_delete_elem(&inflight_map, &key);
  return 0;
}

/* ---------- Phase 1: PCC I/O kprobes ---------- */

SEC("kprobe/pcc_file_read_iter")
int pcc_file_read_iter_enter(struct pt_regs *ctx) {
  struct kiocb *kiocb = (struct kiocb *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_kiocb_dev(kiocb, &s_dev)) return 0;
  return track_pcc_enter(OP_PCC_READ, s_dev);
}

SEC("kretprobe/pcc_file_read_iter")
int pcc_file_read_iter_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_READ, PT_REGS_RC(ctx), 1);
}

SEC("kprobe/pcc_file_write_iter")
int pcc_file_write_iter_enter(struct pt_regs *ctx) {
  struct kiocb *kiocb = (struct kiocb *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_kiocb_dev(kiocb, &s_dev)) return 0;
  return track_pcc_enter(OP_PCC_WRITE, s_dev);
}

SEC("kretprobe/pcc_file_write_iter")
int pcc_file_write_iter_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_WRITE, PT_REGS_RC(ctx), 1);
}

SEC("kprobe/pcc_file_open")
int pcc_file_open_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) return 0;
  return track_pcc_enter(OP_PCC_OPEN, s_dev);
}

SEC("kretprobe/pcc_file_open")
int pcc_file_open_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_OPEN, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/pcc_lookup")
int pcc_lookup_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) return 0;
  return track_pcc_enter(OP_PCC_LOOKUP, s_dev);
}

SEC("kretprobe/pcc_lookup")
int pcc_lookup_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_LOOKUP, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/pcc_fsync")
int pcc_fsync_enter(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_file_dev(file, &s_dev)) return 0;
  return track_pcc_enter(OP_PCC_FSYNC, s_dev);
}

SEC("kretprobe/pcc_fsync")
int pcc_fsync_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_FSYNC, PT_REGS_RC(ctx), 0);
}

/* ---------- Phase 2: PCC attach/detach kprobes ---------- */

/* Helper to enter an attach/detach operation. Packs mode and trigger
 * into request_ptr so they can be decoded in Go userspace. */
static __always_inline int track_pcc_attach_enter(__u8 op, __u32 s_dev,
    __u8 mode, __u8 trigger) {
  __u8 mount_idx = 0;
  if (!lookup_mount(s_dev, &mount_idx)) {
    return 0;
  }
  __u64 tid = current_tid();
  struct start_info info = {};
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  info.request_ptr = ((__u64)mode << 8) | (__u64)trigger;
  struct inflight_key key = {.tid = tid, .op = op};
  bpf_map_update_elem(&inflight_map, &key, &info, BPF_ANY);
  return 0;
}

SEC("kprobe/pcc_ioctl_attach")
int pcc_ioctl_attach_enter(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_file_dev(file, &s_dev)) return 0;
  /* ioctl attach: mode is unknown at entry (determined by userspace args);
   * use 0 as placeholder — Go side will show "unknown". */
  return track_pcc_attach_enter(OP_PCC_ATTACH, s_dev, 0, PCC_TRIGGER_MANUAL);
}

SEC("kretprobe/pcc_ioctl_attach")
int pcc_ioctl_attach_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_ATTACH, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/pcc_ioctl_detach")
int pcc_ioctl_detach_enter(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_file_dev(file, &s_dev)) return 0;
  return track_pcc_attach_enter(OP_PCC_DETACH, s_dev, 0, PCC_TRIGGER_MANUAL);
}

SEC("kretprobe/pcc_ioctl_detach")
int pcc_ioctl_detach_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_DETACH, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/pcc_try_auto_attach")
int pcc_try_auto_attach_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) return 0;
  return track_pcc_attach_enter(OP_PCC_ATTACH, s_dev, 0, PCC_TRIGGER_AUTO);
}

SEC("kretprobe/pcc_try_auto_attach")
int pcc_try_auto_attach_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_ATTACH, PT_REGS_RC(ctx), 0);
}

SEC("kprobe/pcc_try_readonly_open_attach")
int pcc_try_readonly_open_attach_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) return 0;
  return track_pcc_attach_enter(OP_PCC_ATTACH, s_dev, PCC_MODE_RO, PCC_TRIGGER_AUTO);
}

SEC("kretprobe/pcc_try_readonly_open_attach")
int pcc_try_readonly_open_attach_exit(struct pt_regs *ctx) {
  return finish_pcc_op(ctx, OP_PCC_ATTACH, PT_REGS_RC(ctx), 0);
}

/* pcc_readonly_attach_sync and pcc_readwrite_attach are internal functions
 * called by pcc_try_auto_attach / pcc_try_readonly_open_attach. Probing them
 * would cause inflight_map key collisions (same tid + OP_PCC_ATTACH) leading
 * to event loss. Only top-level entry points are probed. */

SEC("kprobe/pcc_layout_invalidate")
int pcc_layout_invalidate_enter(struct pt_regs *ctx) {
  struct inode *inode = (struct inode *)PT_REGS_PARM1(ctx);
  __u32 s_dev = 0;
  if (!read_inode_dev(inode, &s_dev)) return 0;
  /* Entry-only counter probe: emit an event with zero duration. */
  __u8 mount_idx = 0;
  if (!lookup_mount(s_dev, &mount_idx)) return 0;
  struct start_info info = {};
  fill_start_info(&info, 0);
  info.mount_idx = mount_idx;
  __u8 actor_type = classify_actor_type(info.comm);
  increment_counter(&pcc_counters, &info, OP_PCC_INVALIDATE,
      actor_type, INTENT_NAMESPACE_MUTATION, 0);
  emit_from_start(ctx, &info, PLANE_PCC, OP_PCC_INVALIDATE, 0, 0, 0,
      ERRNO_CLASS_NONE);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
