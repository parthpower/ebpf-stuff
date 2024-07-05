#include "common.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#ifdef DEBUG
#define DEBUG_PRINT(...)                                                      \
  do                                                                          \
    {                                                                         \
      bpf_printk (__VA_ARGS__);                                               \
    }                                                                         \
  while (0)
#else
#define DEBUG_PRINT(fmt, ...)                                                 \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

struct
{
  __uint (type, BPF_MAP_TYPE_ARRAY);
  __type (key, __u32);
  __type (value, __u64);
  __uint (max_entries, TIME_DELTAS_KEY_MAX);
} time_deltas SEC (".maps");

static __always_inline __u64
atomic_max (__u64 *ptr, __u64 val)
{
  __u64 old, current;

  current = __sync_fetch_and_add (ptr, 0); // Atomic read

  if (current >= val)
    return current; // No update needed

  old = __sync_val_compare_and_swap (ptr, current, val);

  return old;
}

static __always_inline __u64
atomic_min (__u64 *ptr, __u64 val)
{
  __u64 old, current;

  current = __sync_fetch_and_add (ptr, 0); // Atomic read
  if (current <= val)
    return current; // No update needed

  old = __sync_val_compare_and_swap (ptr, current, val);

  return old;
}

/**
 * @brief get value from map
 * @attr type
 * @attr[out] val
 * @return 0 on success, -1 on fail
 */
__always_inline static int
fetch_val (time_deltas_key type, void **val)
{
  __u32 key = (__u32)type;
  if (!val)
    {
      DEBUG_PRINT ("nil val");
      return -1;
    }
  *val = bpf_map_lookup_elem (&time_deltas, &key);
  if (!(*val))
    {
      DEBUG_PRINT ("failed to fetch: %d", type);
      return -1;
    }
  return 0;
}

SEC ("classifier")
int
count_packets (struct __sk_buff *skb)
{
  __u64 *pkt_cnt, *first_ts, *last_ts, *total_delta, *min_delta, *max_delta;

  // fail if we can't fetch stuff
  if (unlikely (fetch_val (TIME_DELTAS_KEY_TOTAL_PKT, (void **)&pkt_cnt) < 0))
    {
      return TC_ACT_OK;
    }
  if (unlikely (fetch_val (TIME_DELTAS_KEY_FIRST_TS, (void **)&first_ts) < 0))
    {
      return TC_ACT_OK;
    }
  if (unlikely (fetch_val (TIME_DELTAS_KEY_LAST_TS, (void **)&last_ts) < 0))
    {
      return TC_ACT_OK;
    }
  if (unlikely (
          fetch_val (TIME_DELTAS_KEY_TOTAL_TS_DELTA, (void **)&total_delta)
          < 0))
    {
      return TC_ACT_OK;
    }
  if (fetch_val (TIME_DELTAS_KEY_MIN_TS_DELTA, (void **)&min_delta) < 0)
    {
      return TC_ACT_OK;
    }
  if (unlikely (fetch_val (TIME_DELTAS_KEY_MAX_TS_DELTA, (void **)&max_delta)
                < 0))
    {
      return TC_ACT_OK;
    }

  // initial condition for min delta
  __u64 skbts = skb->tstamp;
  // do some calc
  // first ts
  __u64 first_ts_val = __sync_val_compare_and_swap (first_ts, (__u64)0, skbts);
  // last ts
  __u64 last_ts_val = __sync_lock_test_and_set (last_ts, skbts);

  // get delta
  __u64 delta = skbts - last_ts_val;

  if (unlikely (last_ts_val == 0))
    {
      delta = 0;
    }
  if (likely (!__sync_bool_compare_and_swap (min_delta, 0, -1)))
    {
      atomic_min (min_delta, delta);
    }

  atomic_max (max_delta, delta);
  // add the delta
  __u64 total_delta_val = __sync_add_and_fetch (total_delta, delta);

  // total pkt
  __u64 cnt = __sync_add_and_fetch (pkt_cnt, 1);

  DEBUG_PRINT ("cnt: %llu delta: %llu total_delta: %llu", cnt, delta,
               total_delta_val);
  __u64 avg = total_delta_val / cnt;
  __u64 min_delta_val = __sync_add_and_fetch (min_delta, 0);
  __u64 max_delta_val = __sync_add_and_fetch (max_delta, 0);
  DEBUG_PRINT ("max_delta: %lluns min_delta: %lluns", max_delta_val,
               min_delta_val);
  DEBUG_PRINT ("avg_delta: %lluns = %lluus = %llums", avg, avg / 1000,
               avg / 1000 / 1000);
  DEBUG_PRINT ("skbts: %llu last_ts: %llu first_ts: %llu", skbts, last_ts_val,
               first_ts_val);
  return TC_ACT_OK;
}

char _license[] SEC ("license") = "GPL";
