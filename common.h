#ifndef COMMON_H
#define COMMON_H
// yoinked from somewhere...
#define unlikely(x) __builtin_expect (!!(x), 0)
#define likely(x) __builtin_expect (!!(x), 1)

typedef enum
{
  TIME_DELTAS_KEY_FIRST_TS,
  TIME_DELTAS_KEY_LAST_TS,
  TIME_DELTAS_KEY_TOTAL_TS_DELTA,
  TIME_DELTAS_KEY_TOTAL_PKT,
  TIME_DELTAS_KEY_MIN_TS_DELTA,
  TIME_DELTAS_KEY_MAX_TS_DELTA,
  TIME_DELTAS_KEY_MAX
} time_deltas_key;

#endif
