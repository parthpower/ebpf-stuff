#include "common.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef DEBUG
#define DEBUG_PRINT(...)                                                      \
  do                                                                          \
    {                                                                         \
      fprintf (stderr, __VA_ARGS__);                                          \
    }                                                                         \
  while (0)
#else
#define DEBUG_PRINT(...)                                                      \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

int
fetch_val (int map_fd, time_deltas_key key, __u64 *val)
{
  int ret = bpf_map_lookup_elem (map_fd, &key, val);
  if (ret < 0)
    {
      DEBUG_PRINT ("failed to fetch from map: %d", key);
      exit (1);
    }
  return ret;
}

int
main ()
{
  struct bpf_object *obj;
  int map_fd;
  __u64 last_ts, first_ts, total_delta, total_pkt;

  obj = bpf_object__open_file ("ebpf_nfilter.o", NULL);
  if (libbpf_get_error (obj))
    {
      fprintf (stderr, "ERROR: opening BPF object file failed\n");
      return 1;
    }

  if (bpf_object__load (obj))
    {
      fprintf (stderr, "ERROR: loading BPF object file failed\n");
      return 1;
    }

  map_fd = bpf_object__find_map_fd_by_name (obj, "time_deltas");
  if (map_fd < 0)
    {
      fprintf (stderr, "ERROR: finding BPF map failed\n");
      return 1;
    }

  fetch_val (map_fd, TIME_DELTAS_KEY_LAST_TS, &last_ts);
  fetch_val (map_fd, TIME_DELTAS_KEY_FIRST_TS, &first_ts);
  fetch_val (map_fd, TIME_DELTAS_KEY_TOTAL_TS_DELTA, &total_delta);
  fetch_val (map_fd, TIME_DELTAS_KEY_TOTAL_PKT, &total_pkt);

  double avg_delta = (double)total_delta / (double)total_pkt;
  fprintf (stdout,
           "last_ts: %lluns first_ts: %lluns total_delta: %lluns total_pkt: "
           "%llu avg_delta: %fns == %fms == %fus\n",
           last_ts, first_ts, total_delta, total_pkt, avg_delta,
           avg_delta / 1000.0, avg_delta / 1000.0 / 1000.0);
  return 0;
}
