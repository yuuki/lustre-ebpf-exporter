#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
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

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

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

struct observer_config {
  __u32 target_major;
  __u32 target_minor;
};

struct start_info {
  __u64 start_ns;
  __u32 uid;
  __u32 pid;
  char comm[TASK_COMM_LEN];
  __u64 request_ptr;
};

struct observer_event {
  __u8 plane;
  __u8 op;
  __u8 pad[6];
  __u32 uid;
  __u32 pid;
  __u32 pad2;
  __u64 duration_us;
  __u64 size_bytes;
  __u64 request_ptr;
  char comm[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct observer_config);
} config_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
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

static __always_inline int mount_matches(__u32 s_dev) {
  __u32 zero = 0;
  struct observer_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
  if (!cfg) {
    return 0;
  }
  return ((s_dev >> 20) == cfg->target_major) && ((s_dev & 1048575) == cfg->target_minor);
}

static __always_inline int read_inode_dev(struct inode *inode, __u32 *s_dev) {
  struct super_block *sb = 0;
  if (!inode) {
    return 0;
  }
  if (bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb)) {
    return 0;
  }
  if (!sb) {
    return 0;
  }
  if (bpf_probe_read_kernel(s_dev, sizeof(*s_dev), &sb->s_dev)) {
    return 0;
  }
  return 1;
}

static __always_inline int read_file_dev(struct file *file, __u32 *s_dev) {
  struct inode *inode = 0;
  if (!file) {
    return 0;
  }
  if (bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode)) {
    return 0;
  }
  return read_inode_dev(inode, s_dev);
}

static __always_inline int read_kiocb_dev(struct kiocb *kiocb, __u32 *s_dev) {
  struct file *file = 0;
  if (!kiocb) {
    return 0;
  }
  if (bpf_probe_read_kernel(&file, sizeof(file), &kiocb->ki_filp)) {
    return 0;
  }
  return read_file_dev(file, s_dev);
}

static __always_inline int emit_from_start(struct start_info *info, __u8 plane, __u8 op, __u64 duration_us, __u64 size_bytes, __u64 request_ptr) {
  struct observer_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    return 0;
  }
  event->plane = plane;
  event->op = op;
  event->uid = info->uid;
  event->pid = info->pid;
  event->duration_us = duration_us;
  event->size_bytes = size_bytes;
  event->request_ptr = request_ptr;
  __builtin_memcpy(event->comm, info->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/ll_lookup_nd")
int ll_lookup_nd_enter(struct inode *inode) {
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 selected = 1;
  if (!read_inode_dev(inode, &s_dev) || !mount_matches(s_dev)) {
    return 0;
  }
  fill_start_info(&info, 0);
  bpf_map_update_elem(&ll_lookup_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &selected, BPF_ANY);
  return 0;
}

SEC("kretprobe/ll_lookup_nd")
int ll_lookup_nd_exit(void *ctx) {
  __u64 tid = current_tid();
  struct start_info *info = bpf_map_lookup_elem(&ll_lookup_map, &tid);
  if (!info) {
    return 0;
  }
  emit_from_start(info, PLANE_LLITE, OP_LOOKUP, (bpf_ktime_get_ns() - info->start_ns) / 1000, 0, 0);
  bpf_map_delete_elem(&ll_lookup_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kprobe/ll_file_open")
int ll_file_open_enter(struct inode *inode) {
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 selected = 1;
  if (!read_inode_dev(inode, &s_dev) || !mount_matches(s_dev)) {
    return 0;
  }
  fill_start_info(&info, 0);
  bpf_map_update_elem(&ll_open_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &selected, BPF_ANY);
  return 0;
}

SEC("kretprobe/ll_file_open")
int ll_file_open_exit(void *ctx) {
  __u64 tid = current_tid();
  struct start_info *info = bpf_map_lookup_elem(&ll_open_map, &tid);
  if (!info) {
    return 0;
  }
  emit_from_start(info, PLANE_LLITE, OP_OPEN, (bpf_ktime_get_ns() - info->start_ns) / 1000, 0, 0);
  bpf_map_delete_elem(&ll_open_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kprobe/ll_file_read_iter")
int ll_file_read_iter_enter(struct kiocb *kiocb) {
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 selected = 1;
  if (!read_kiocb_dev(kiocb, &s_dev) || !mount_matches(s_dev)) {
    return 0;
  }
  fill_start_info(&info, 0);
  bpf_map_update_elem(&ll_read_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &selected, BPF_ANY);
  return 0;
}

SEC("kretprobe/ll_file_read_iter")
int ll_file_read_iter_exit(void *ctx) {
  __u64 tid = current_tid();
  struct start_info *info = bpf_map_lookup_elem(&ll_read_map, &tid);
  __u64 bytes = PT_REGS_RC(ctx);
  if (!info) {
    return 0;
  }
  emit_from_start(info, PLANE_LLITE, OP_READ, (bpf_ktime_get_ns() - info->start_ns) / 1000, bytes > 0 ? bytes : 0, 0);
  bpf_map_delete_elem(&ll_read_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kprobe/ll_file_write_iter")
int ll_file_write_iter_enter(struct kiocb *kiocb) {
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 selected = 1;
  if (!read_kiocb_dev(kiocb, &s_dev) || !mount_matches(s_dev)) {
    return 0;
  }
  fill_start_info(&info, 0);
  bpf_map_update_elem(&ll_write_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &selected, BPF_ANY);
  return 0;
}

SEC("kretprobe/ll_file_write_iter")
int ll_file_write_iter_exit(void *ctx) {
  __u64 tid = current_tid();
  struct start_info *info = bpf_map_lookup_elem(&ll_write_map, &tid);
  __u64 bytes = PT_REGS_RC(ctx);
  if (!info) {
    return 0;
  }
  emit_from_start(info, PLANE_LLITE, OP_WRITE, (bpf_ktime_get_ns() - info->start_ns) / 1000, bytes > 0 ? bytes : 0, 0);
  bpf_map_delete_elem(&ll_write_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kprobe/ll_fsync")
int ll_fsync_enter(struct file *file) {
  __u32 s_dev = 0;
  __u64 tid = current_tid();
  struct start_info info = {};
  __u8 selected = 1;
  if (!read_file_dev(file, &s_dev) || !mount_matches(s_dev)) {
    return 0;
  }
  fill_start_info(&info, 0);
  bpf_map_update_elem(&ll_fsync_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&selected_mount_tids, &tid, &selected, BPF_ANY);
  return 0;
}

SEC("kretprobe/ll_fsync")
int ll_fsync_exit(void *ctx) {
  __u64 tid = current_tid();
  struct start_info *info = bpf_map_lookup_elem(&ll_fsync_map, &tid);
  if (!info) {
    return 0;
  }
  emit_from_start(info, PLANE_LLITE, OP_FSYNC, (bpf_ktime_get_ns() - info->start_ns) / 1000, 0, 0);
  bpf_map_delete_elem(&ll_fsync_map, &tid);
  bpf_map_delete_elem(&selected_mount_tids, &tid);
  return 0;
}

SEC("kprobe/ptlrpc_send_new_req")
int ptlrpc_send_new_req_enter(void *req) {
  __u64 tid = current_tid();
  __u8 *selected = bpf_map_lookup_elem(&selected_mount_tids, &tid);
  struct start_info info = {};
  __u8 tracked = 1;
  if (!selected) {
    return 0;
  }
  fill_start_info(&info, (__u64)req);
  bpf_map_update_elem(&tracked_reqs, &info.request_ptr, &tracked, BPF_ANY);
  emit_from_start(&info, PLANE_PTLRPC, OP_SEND_NEW_REQ, 0, 0, info.request_ptr);
  return 0;
}

SEC("kprobe/ptlrpc_queue_wait")
int ptlrpc_queue_wait_enter(void *req) {
  __u64 tid = current_tid();
  __u64 req_ptr = (__u64)req;
  __u8 *selected = bpf_map_lookup_elem(&selected_mount_tids, &tid);
  __u8 *tracked = bpf_map_lookup_elem(&tracked_reqs, &req_ptr);
  struct start_info info = {};
  __u8 tracked_value = 1;
  if (!selected && !tracked) {
    return 0;
  }
  fill_start_info(&info, req_ptr);
  bpf_map_update_elem(&rpc_wait_map, &tid, &info, BPF_ANY);
  bpf_map_update_elem(&tracked_reqs, &req_ptr, &tracked_value, BPF_ANY);
  return 0;
}

SEC("kretprobe/ptlrpc_queue_wait")
int ptlrpc_queue_wait_exit(void *ctx) {
  __u64 tid = current_tid();
  struct start_info *info = bpf_map_lookup_elem(&rpc_wait_map, &tid);
  if (!info) {
    return 0;
  }
  emit_from_start(info, PLANE_PTLRPC, OP_QUEUE_WAIT, (bpf_ktime_get_ns() - info->start_ns) / 1000, 0, info->request_ptr);
  bpf_map_delete_elem(&rpc_wait_map, &tid);
  return 0;
}

SEC("kprobe/__ptlrpc_free_req")
int ptlrpc_free_req_enter(void *req) {
  __u64 req_ptr = (__u64)req;
  __u8 *tracked = bpf_map_lookup_elem(&tracked_reqs, &req_ptr);
  struct start_info info = {};
  if (!tracked) {
    return 0;
  }
  fill_start_info(&info, req_ptr);
  emit_from_start(&info, PLANE_PTLRPC, OP_FREE_REQ, 0, 0, req_ptr);
  bpf_map_delete_elem(&tracked_reqs, &req_ptr);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
