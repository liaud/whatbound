#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

#define TASK_RUNNING 0x0000
#define TASK_INTERRUPTIBLE 0x0001
#define TASK_UNINTERRUPTIBLE 0x0002

const volatile struct {
  pid_t target_tgid;
  bool verbose;
} args = {.target_tgid = -1};

enum task_last_state {
  STATE_UNKNOWN = 0,
  STATE_RUNNING,
  STATE_NOT_RUNNING,
};

struct switch_event {
  enum task_last_state state;
  u64 start;
};

struct aggregate {
  u8 comm[16];

  u64 total_running;
  u64 total_waiting;
  u64 total_sleeping;
};

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __type(key, int);
  __type(value, struct switch_event);
  __uint(max_entries, 0);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} switch_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, struct aggregate);
  __uint(max_entries, 4096);
  __uint(map_flags, 0);
} aggregates SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum task_last_state task_last_state_from_state(int state) {
  if (state > 0) {
    return STATE_NOT_RUNNING;
  } else {
    return STATE_RUNNING;
  }
}

static __always_inline struct aggregate *
lookup_or_create_agg(struct task_struct *task) {
  long err = 0;
  struct aggregate *agg = NULL;
  u32 pid = task->pid;

  agg = bpf_map_lookup_elem(&aggregates, &pid);
  if (agg == NULL) {
    struct aggregate init_val = {
        .total_running = 0,
        .total_sleeping = 0,
        .total_waiting = 0,
    };
    err =
        bpf_probe_read_kernel(init_val.comm, sizeof(init_val.comm), task->comm);
    if (err != 0) {
      return NULL;
    }

    bpf_map_update_elem(&aggregates, &pid, &init_val, BPF_NOEXIST);
    agg = bpf_map_lookup_elem(&aggregates, &pid);
  }

  return agg;
}

static __always_inline int task_switched_off(u64 now, struct task_struct *prev,
                                             unsigned int prev_state) {
  struct switch_event *last_event = bpf_task_storage_get(
      &switch_events, prev, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!last_event)
    return -1;

  struct aggregate *agg = lookup_or_create_agg(prev);
  if (agg == NULL)
    return -1;
  /* Accounts for the time that the task has run on the cpu. It
   * is either going to sleep or it is replaced by another task
   * and it'll run again latter.
   */
  u64 amount = (now - last_event->start);
  if (last_event->start > 0 && last_event->state == STATE_RUNNING) {
    __sync_fetch_and_add(&agg->total_running, amount);

    if (args.verbose) {
      bpf_printk("switched-off (ran). total=%lu amount=%lu", agg->total_running,
                 amount);
    }
  } else if (last_event->start > 0) {
    bpf_printk("switched-off (unhandled). prev_state=%d last_event_state=%d",
               prev_state, last_event->state);
  } else if (args.verbose) {
    bpf_printk("switched-off. previous state unknown");
  }

  last_event->state = task_last_state_from_state(prev_state);
  last_event->start = now;
  return 0;
}

static __always_inline int task_switched_in(u64 now, struct task_struct *new) {
  struct switch_event *last_event = bpf_task_storage_get(
      &switch_events, new, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!last_event)
    return -1;

  struct aggregate *agg = lookup_or_create_agg(new);
  if (agg == NULL)
    return -1;

  u64 amount = (now - last_event->start);
  if (last_event->start > 0 && new->__state == TASK_RUNNING &&
      last_event->state == STATE_RUNNING) {

    __sync_fetch_and_add(&agg->total_waiting, amount);
    if (args.verbose) {
      bpf_printk("switched-in (waited). total=%lu amount=%lu",
                 agg->total_waiting, amount);
    }

  } else if (last_event->start > 0 && new->__state == TASK_RUNNING &&
             last_event->state != STATE_RUNNING) {

    __sync_fetch_and_add(&agg->total_sleeping, amount);
    if (args.verbose) {
      bpf_printk("switched-in (slept). total=%lu amount=%lu",
                 agg->total_sleeping, amount);
    }

  } else if (last_event->start > 0) {
    bpf_printk("switched in (unhandled). new->__state=%d last_event_state=%d",
               new->__state, last_event->state);
  } else if (args.verbose) {
    bpf_printk("switched-in. previous state unknown");
  }

  last_event->state = task_last_state_from_state(new->__state);
  last_event->start = now;
  return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle__sched_switch, bool preempted, struct task_struct *prev,
             struct task_struct *new, unsigned int prev_state) {

  if (prev->tgid != args.target_tgid && new->tgid != args.target_tgid)
    return 0;

  if (args.verbose) {
    bpf_printk(
        "sched_switch preempted=%d prev=%u prev_state=%u, new=%u new_state=%lu",
        preempted, prev->pid, prev_state, new->pid, new->__state);
  }

  u64 now = bpf_ktime_get_ns();
  if (prev->tgid == args.target_tgid) {
    return task_switched_off(now, prev, prev_state);
  } else {
    return task_switched_in(now, new);
  }
}
