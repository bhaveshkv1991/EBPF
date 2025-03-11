#ifndef SECURITY_MONITOR_H
#define SECURITY_MONITOR_H

/* Platform-specific includes */
#ifdef __APPLE__
  /* macOS compatibility */
  #include <stdint.h>
  typedef uint32_t __u32;
  typedef uint64_t __u64;
#else
  /* Linux includes */
  #include <linux/types.h>
#endif

#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define MAX_FILENAME_BUFFER 128

/* Event types for communicating between kernel and user space */
enum event_type {
    EVENT_FILE_OPEN = 1,
    EVENT_PROCESS_EXEC = 2,
    EVENT_SUSPICIOUS_ACTIVITY = 3,
};

/* Severity levels for events */
enum severity_level {
    SEV_INFO = 1,
    SEV_WARNING = 2,
    SEV_CRITICAL = 3,
};

/* Data structure for passing events from kernel to user space */
struct event_data {
    __u32 event_type;
    __u32 severity;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp;
    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char args[MAX_PATH_LEN]; // For execve args
};

/* Arrays are now defined in security_monitor.c */
extern const char* sensitive_files[];
extern const char* suspicious_commands[];

#endif /* SECURITY_MONITOR_H */ 