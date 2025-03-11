/*
 * mock_bpf.h - BPF compatibility definitions for non-Linux platforms
 * Used for simulation mode on macOS and other platforms without native BPF support
 */

#ifndef MOCK_BPF_H
#define MOCK_BPF_H

#include <stdint.h>

/* Basic types for BPF compatibility */
typedef uint32_t __u32;
typedef uint64_t __u64;

/* Mock section attribute for BPF programs */
#define SEC(NAME) __attribute__((section(NAME)))

/* Mock BPF helper functions that will be replaced in simulation mode */
static inline __u64 bpf_get_current_pid_tgid(void) { return 0; }
static inline __u64 bpf_get_current_uid_gid(void) { return 0; }
static inline int bpf_probe_read_user(void *dst, int size, const void *src) { return 0; }
static inline int bpf_probe_read_user_str(void *dst, int size, const void *src) { return 0; }
static inline int bpf_get_current_comm(void *buf, int size_of_buf) { return 0; }
static inline __u64 bpf_ktime_get_ns(void) { return 0; }
static inline int bpf_perf_event_output(void *ctx, void *map, int index, void *data, int size) { return 0; }

/* BPF map definitions for mocking */
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_F_CURRENT_CPU 0

/* Map definition helpers */
#define __uint(name, val) int name __attribute__((unused)) = val

#endif /* MOCK_BPF_H */ 