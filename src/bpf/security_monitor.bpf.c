#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Handle cross-platform compatibility */
#ifdef __APPLE__
  #include "../../include/mock_bpf.h"
  #define MOCK_MODE 1
#else
  #include <linux/fs.h>
  #include <linux/sched.h>
  
  /* Handle potential missing cred.h header */
  #if defined(__has_include)
    #if __has_include(<linux/cred.h>)
      #include <linux/cred.h>
    #else
      /* Minimal definition if cred.h isn't available */
      struct cred {
        uid_t uid;
        gid_t gid;
      };
    #endif
    
    /* Handle potential missing tracing types */
    #if __has_include(<linux/trace_events.h>)
      #include <linux/trace_events.h>
    #else
      /* Add necessary definitions if trace_events.h isn't available */
      #define MAX_SYSCALL_ARGS 6
      struct trace_event_raw_sys_enter {
        unsigned long long args[MAX_SYSCALL_ARGS];
        int __syscall_nr;
      };
    #endif
    
    /* String includes */
    #if __has_include(<stubs-32.h>)
      /* For BPF target, we use our own string comparison functions */
      /* No need to include string.h which might require stubs-32.h */
      #define strstr(haystack, needle) NULL /* We'll implement our own if needed */
    #else
      /* For regular compilation, include string.h normally */
      #include <string.h>
    #endif
  #endif /* defined(__has_include) */
  
  /* If __has_include isn't supported, define essential structures */
  #ifndef MAX_SYSCALL_ARGS
    #define MAX_SYSCALL_ARGS 6
    struct trace_event_raw_sys_enter {
      unsigned long long args[MAX_SYSCALL_ARGS];
      int __syscall_nr;
    };
    /* Use builtin functions for string operations */
    #define strstr(haystack, needle) __builtin_strstr(haystack, needle)
  #endif
#endif /* __APPLE__ */

#include "../../include/security_monitor.h"

/* Define string constants properly using SEC("rodata") */
char LICENSE[] SEC("license") = "GPL";

/* Define a BPF map for storing string constants */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, char[16]); /* Use smaller buffer size */
} string_map SEC(".maps");

/* Additional string map for URL prefixes and other strings */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, char[16]); /* Use smaller buffer size */
} extra_strings SEC(".maps");

/* String map indices for sensitive paths */
#define STR_ETC_SHADOW      0
#define STR_ETC_PASSWD      1
#define STR_ETC_SSH         2
#define STR_ETC_SUDOERS     3
#define STR_ROOT_SSH        4
#define STR_AUTH_LOG        5

/* String map indices for commands */
#define STR_CMD_WGET        10
#define STR_CMD_CURL        11
#define STR_CMD_NC          12
#define STR_CMD_NETCAT      13
#define STR_CMD_CHMOD777    14
#define STR_CMD_BASE64      15
#define STR_CMD_PYTHON      16

/* String map indices for other strings */
#define STR_ROOT            20
#define STR_ETC             21
#define STR_HTTP            22
#define STR_HTTPS           23
#define STR_FTP             24

/* Define maximum args for syscalls */
#define MAX_SYSCALL_ARGS 6
#define MAX_ARG_SIZE 256
#define MAX_FILENAME_BUFFER 128 /* Small buffer to avoid stack size issues */

/* Define boolean type for BPF context if not available */
#ifndef bool
typedef _Bool bool;
#define true 1
#define false 0
#endif

/* Sensitive file paths - using regular const char arrays instead of SECs */
const char path_etc_shadow[] = "/etc/shadow";
const char path_etc_passwd[] = "/etc/passwd";
const char path_etc_ssh[] = "/etc/ssh";
const char path_etc_sudoers[] = "/etc/sudoers";
const char path_root_ssh[] = "/root/.ssh";
const char path_auth_log[] = "/var/log/auth.log";

/* Suspicious command names - using regular const char arrays */
const char cmd_wget[] = "wget";
const char cmd_curl[] = "curl";
const char cmd_nc[] = "nc";
const char cmd_netcat[] = "netcat";
const char cmd_chmod777[] = "chmod 777";
const char cmd_base64[] = "base64";
const char cmd_python[] = "python";

/* Define sensitive file patterns to monitor */
#define SENSITIVE_FILE_SHADOW        0
#define SENSITIVE_FILE_PASSWD        1 
#define SENSITIVE_FILE_SSH           2
#define SENSITIVE_FILE_SUDOERS       3
#define SENSITIVE_FILE_ROOT_SSH      4
#define SENSITIVE_FILE_AUTH_LOG      5
#define MAX_SENSITIVE_FILES          6

/* Define suspicious command patterns to monitor */
#define SUSPICIOUS_CMD_WGET         0
#define SUSPICIOUS_CMD_CURL         1
#define SUSPICIOUS_CMD_NC           2
#define SUSPICIOUS_CMD_NETCAT       3
#define SUSPICIOUS_CMD_CHMOD_777    4
#define SUSPICIOUS_CMD_BASE64       5
#define SUSPICIOUS_CMD_PYTHON       6
#define SUSPICIOUS_CMD_PERL         7
#define SUSPICIOUS_CMD_BASH_I       8
#define MAX_SUSPICIOUS_COMMANDS     9

/* Use BPF maps for large structures to avoid stack limitations */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct event_data));
    __uint(max_entries, 1);
} event_map SEC(".maps");

/* Map for storing large path buffers to avoid stack limits */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, MAX_PATH_LEN);
    __uint(max_entries, 2); /* Two slots for filename and args */
} path_map SEC(".maps");

/* BPF map to communicate events to user space */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* Read a string into the path map to avoid stack limits */
static char *get_path_buffer(int slot) {
    if (slot < 0 || slot >= 2)
        return NULL;
    
    return bpf_map_lookup_elem(&path_map, &slot);
}

/* Simplified string comparisons for BPF - minimal parameters to reduce stack usage */
static __always_inline bool match_string(const char *filename, int pattern_idx) {
    char *pattern;
    int idx = pattern_idx;
    
    pattern = bpf_map_lookup_elem(&string_map, &idx);
    if (!pattern)
        return false;
        
    /* Simple prefix matching with minimal stack variables */
    char c1, c2;
    int i;
    #pragma unroll
    for (i = 0; i < 16; i++) {
        /* Safely read characters */
        bpf_probe_read_user(&c1, 1, &filename[i]);
        bpf_probe_read(&c2, 1, &pattern[i]);
        
        /* If pattern ended, it's a match */
        if (c2 == '\0')
            return true;
            
        /* If filename ended or mismatch, not a match */
        if (c1 != c2 || c1 == '\0')
            return false;
    }
    
    /* If we've checked 16 characters and still matching, consider it a match */
    return true;
}

/* Function to check if a file path is sensitive - single check implementation */
static __always_inline bool is_sensitive_file(const char *filename) {
    if (match_string(filename, 0) || 
        match_string(filename, 1) || 
        match_string(filename, 2) || 
        match_string(filename, 3) || 
        match_string(filename, 4)) {
        return true;
    }
    return false;
}

/* Function to check if a command is suspicious - single check implementation */
static __always_inline bool is_suspicious_command(const char *command) {
    if (match_string(command, 5) || 
        match_string(command, 6) || 
        match_string(command, 7) || 
        match_string(command, 8) || 
        match_string(command, 9)) {
        return true;
    }
    return false;
}

/* Simplified string prefix check for BPF programs */
static __always_inline bool bpf_str_startswith(const char *str, const char *prefix, size_t max_len) {
    char c1 = 0, c2 = 0;
    
    /* Loop with bounds to satisfy the verifier */
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= max_len)
            break;
        
        bpf_probe_read_user(&c1, 1, &str[i]);
        bpf_probe_read(&c2, 1, &prefix[i]);
        
        /* If we reach the end of the prefix, it's a match */
        if (c2 == '\0')
            return true;
            
        /* If characters don't match or we hit the end of str before prefix, it's not a match */
        if (c1 != c2 || c1 == '\0')
            return false;
    }
    
    return false;
}

/* Check if string starts with one of the sensitive prefixes */
static __always_inline bool is_root_access(const char *filename) {
    int idx;
    char *pattern;
    
    /* Check /etc/shadow */
    idx = STR_ETC_SHADOW;
    pattern = bpf_map_lookup_elem(&string_map, &idx);
    if (pattern && bpf_str_startswith(filename, pattern, 16))
        return true;
        
    /* Check /etc/sudoers */
    idx = STR_ETC_SUDOERS;
    pattern = bpf_map_lookup_elem(&string_map, &idx);
    if (pattern && bpf_str_startswith(filename, pattern, 16))
        return true;
        
    /* Check /root */
    idx = STR_ROOT;
    pattern = bpf_map_lookup_elem(&extra_strings, &idx);
    if (pattern && bpf_str_startswith(filename, pattern, 16))
        return true;
        
    return false;
}

/* Check if string is an URL */
static __always_inline bool is_url(const char *str) {
    int idx;
    char *pattern;
    
    /* Check http:// */
    idx = STR_HTTP;
    pattern = bpf_map_lookup_elem(&extra_strings, &idx);
    if (pattern && bpf_str_startswith(str, pattern, 16))
        return true;
        
    /* Check https:// */
    idx = STR_HTTPS;
    pattern = bpf_map_lookup_elem(&extra_strings, &idx);
    if (pattern && bpf_str_startswith(str, pattern, 16))
        return true;
        
    /* Check ftp:// */
    idx = STR_FTP;
    pattern = bpf_map_lookup_elem(&extra_strings, &idx);
    if (pattern && bpf_str_startswith(str, pattern, 16))
        return true;
        
    return false;
}

/* Handle openat syscall */
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    int zero = 0;
    struct event_data *event;
    void *filename_ptr = NULL;
    __u64 pid_tgid, uid_gid;
    char *filename;
    char path_small[MAX_FILENAME_BUFFER] = {0};  /* Small buffer for initial check */
    
    /* Get per-cpu array for the event data */
    event = bpf_map_lookup_elem(&event_map, &zero);
    if (!event)
        return 0;
    
    /* Read filename pointer safely */
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[1]);
    if (!filename_ptr)
        return 0;
    
    /* Read a small portion of the filename first to do initial check */
    bpf_probe_read_user_str(path_small, sizeof(path_small), filename_ptr);
    
    /* Only proceed if it appears to be a sensitive file */
    if (!is_sensitive_file(path_small))
        return 0;
    
    /* Now get the full path from our path map buffer */
    int slot = 0;
    filename = get_path_buffer(slot);
    if (!filename)
        return 0;
    
    /* Read the full path into our map buffer */
    bpf_probe_read_user_str(filename, MAX_PATH_LEN, filename_ptr);
    
    /* Get process context */
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    
    /* Fill event data */
    event->event_type = EVENT_FILE_OPEN;
    event->severity = SEV_INFO; /* Default severity */
    event->pid = pid_tgid >> 32;
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    /* Copy filename from our map buffer to the event */
    bpf_probe_read(event->filename, sizeof(event->filename), filename);
    
    /* Set higher severity if root files accessed by non-root */
    if (event->uid != 0 && is_root_access(filename)) {
        event->severity = SEV_CRITICAL;
    }
    
    /* Send event to userspace */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    
    return 0;
}

/* Handle execve syscall */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    int zero = 0;
    struct event_data *event;
    __u64 pid_tgid, uid_gid;
    char cmd_small[MAX_FILENAME_BUFFER] = {0};  /* Small buffer for initial check */
    void *filename_ptr = NULL, *args_ptr = NULL;
    char *cmd, *arg_buf;
    
    /* Get per-cpu array for the event data */
    event = bpf_map_lookup_elem(&event_map, &zero);
    if (!event)
        return 0;
    
    /* Read command pointer safely */
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), &ctx->args[0]);
    if (!filename_ptr)
        return 0;
    
    /* Read a small portion of the command first to do initial check */
    bpf_probe_read_user_str(cmd_small, sizeof(cmd_small), filename_ptr);
    
    /* Only proceed if it appears to be a suspicious command */
    if (!is_suspicious_command(cmd_small))
        return 0;
    
    /* Now get the full command from our path map buffer */
    int cmd_slot = 0, arg_slot = 1;
    cmd = get_path_buffer(cmd_slot);
    arg_buf = get_path_buffer(arg_slot);
    if (!cmd || !arg_buf)
        return 0;
    
    /* Read the full command into our map buffer */
    bpf_probe_read_user_str(cmd, MAX_PATH_LEN, filename_ptr);
    
    /* Read arguments safely */
    bpf_probe_read(&args_ptr, sizeof(args_ptr), &ctx->args[1]);
    if (args_ptr) {
        void *first_arg_ptr = NULL;
        bpf_probe_read(&first_arg_ptr, sizeof(first_arg_ptr), args_ptr);
        if (first_arg_ptr) {
            bpf_probe_read_user_str(arg_buf, MAX_PATH_LEN, first_arg_ptr);
        }
    }
    
    /* Get process context */
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    
    /* Fill event data */
    event->event_type = EVENT_PROCESS_EXEC;
    event->severity = SEV_WARNING; /* Default for suspicious commands */
    event->pid = pid_tgid >> 32;
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    /* Copy command and args from our map buffers to the event */
    bpf_probe_read(event->filename, sizeof(event->filename), cmd);
    bpf_probe_read(event->args, sizeof(event->args), arg_buf);
    
    /* Set severity based on context */
    /* If non-root running suspicious command with sensitive args or from suspicious location */
    if (event->uid != 0 && (is_root_access(cmd) || is_url(arg_buf))) {
        event->severity = SEV_CRITICAL;
    }
    
    /* Send event to userspace */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    
    return 0;
}

/* Handle security-related syscalls */
SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
    int zero = 0;
    struct event_data *event;
    __u64 pid_tgid, uid_gid;
    __u32 new_uid;
    
    /* Get per-cpu array for the event data */
    event = bpf_map_lookup_elem(&event_map, &zero);
    if (!event)
        return 0;
    
    /* Get process context */
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    __u32 current_uid = uid_gid & 0xFFFFFFFF;
    
    /* Read the new UID from argument */
    bpf_probe_read(&new_uid, sizeof(new_uid), &ctx->args[0]);
    
    /* Only track privilege escalation events */
    if (current_uid != 0 && new_uid == 0) {
        /* This is a privilege escalation attempt */
        event->event_type = EVENT_SUSPICIOUS_ACTIVITY;
        event->severity = SEV_CRITICAL;
        event->pid = pid_tgid >> 32;
        event->uid = current_uid;
        event->gid = uid_gid >> 32;
        event->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(event->comm, sizeof(event->comm));
        
        /* Set descriptive information */
        char info[] = "Privilege escalation attempt (setuid to root)";
        __builtin_memcpy(event->filename, info, sizeof(info));
        
        /* Send event to userspace */
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    
    return 0;
} 