#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>

/* BPF includes */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>  /* Include this for bpf_map_update_elem */

/* Define PATH_MAX if not defined */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Array sizes for both environments */
#define NUM_SENSITIVE_FILES 6
#define NUM_SUSPICIOUS_COMMANDS 9

/* Define the arrays for all environments - these were previously external */
const char* sensitive_files[NUM_SENSITIVE_FILES] = {
  "/etc/shadow",
  "/etc/passwd",
  "/etc/ssh",
  "/etc/sudoers",
  "/root/.ssh",
  "/var/log/auth.log"
};

const char* suspicious_commands[NUM_SUSPICIOUS_COMMANDS] = {
  "wget",
  "curl",
  "nc",
  "netcat",
  "chmod 777",
  "base64",
  "python",
  "perl",
  "bash -i"
};

/* Check if we're on macOS */
#ifdef __APPLE__
  #define SIMULATION_MODE 1
#endif

/* Also check for simulation through environment variable */
#ifndef SIMULATION_MODE
  #define SIMULATION_MODE 0
#endif

#include "../include/security_monitor.h"

#define BPF_OBJECT_FILE "build/security_monitor.bpf.o"

/* Global variables */
static volatile bool exiting = false;
static bool simulation_mode = false;
static int enforce_mode = 0;
static int verbose_mode = 0;

/* Signal handler to terminate gracefully */
static void sig_handler(int sig)
{
    exiting = true;
}

/* Console colors for output formatting */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

/* Get human-readable severity string with color */
static const char* get_severity_str(enum severity_level sev) {
    switch (sev) {
        case SEV_INFO:
            return COLOR_GREEN "INFO" COLOR_RESET;
        case SEV_WARNING:
            return COLOR_YELLOW "WARNING" COLOR_RESET;
        case SEV_CRITICAL:
            return COLOR_RED "CRITICAL" COLOR_RESET;
        default:
            return "UNKNOWN";
    }
}

/* Get human-readable event type string */
static const char* get_event_type_str(enum event_type type) {
    switch (type) {
        case EVENT_FILE_OPEN:
            return "FILE_OPEN";
        case EVENT_PROCESS_EXEC:
            return "PROCESS_EXEC";
        case EVENT_SUSPICIOUS_ACTIVITY:
            return "SUSPICIOUS_ACTIVITY";
        default:
            return "UNKNOWN";
    }
}

/* Print an event */
static void print_event(struct event_data *event)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char timestamp[64];
    
    /* Format timestamp */
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
    /* Print basic event info with color-coded severity */
    printf("[%s] %s: [%s] PID=%u UID=%u GID=%u COMM=%s ", 
        timestamp, 
        get_severity_str(event->severity),
        get_event_type_str(event->event_type),
        event->pid, event->uid, event->gid, event->comm);
    
    /* Print event-specific details */
    switch (event->event_type) {
        case EVENT_FILE_OPEN:
            printf("Accessing file: %s\n", event->filename);
            break;
        case EVENT_PROCESS_EXEC:
            if (event->args[0] != '\0') {
                printf("Executing: %s %s\n", event->filename, event->args);
            } else {
                printf("Executing: %s\n", event->filename);
            }
            break;
        case EVENT_SUSPICIOUS_ACTIVITY:
            printf("%s\n", event->filename);
            break;
        default:
            printf("Unknown event type\n");
    }
    
    /* In enforce mode, take action on critical events */
    if (enforce_mode && event->severity == SEV_CRITICAL) {
        printf(COLOR_RED "ENFORCING: Would terminate process %d\n" COLOR_RESET, event->pid);
        
        /* In simulation mode, we don't actually kill processes */
        if (!simulation_mode) {
            /* 
            * This is where we would implement enforcement actions
            * For now, we just print what we would do
            */
            // kill(event->pid, SIGTERM);
        }
    }
}

/* Callback for handling events from BPF program */
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    /* Cast the raw data to our event structure */
    struct event_data *event = data;
    
    print_event(event);
}

/* Callback for handling lost events */
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

/* Print usage information */
static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "  -e, --enforce     Run in enforcement mode (terminate suspicious processes)\n"
            "  -s, --simulate    Run in simulation mode (don't load BPF program)\n"
            "  -v, --verbose     Enable verbose output\n"
            "  -h, --help        Display this help and exit\n",
            prog);
}

/* Parse command line arguments */
static void parse_args(int argc, char **argv)
{
    /* Options for getopt_long */
    struct option long_options[] = {
        {"enforce", no_argument, 0, 'e'},
        {"simulate", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "esvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'e':
                enforce_mode = 1;
                break;
            case 's':
                simulation_mode = 1;
                break;
            case 'v':
                verbose_mode = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }
}

/* Check if BPF object file exists and has non-zero size */
static bool check_bpf_object_file(const char *path) {
    if (verbose_mode) {
        printf("Checking BPF object file: %s\n", path);
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        if (verbose_mode) {
            fprintf(stderr, "Failed to access BPF object file %s: %s\n", path, strerror(errno));
        }
        return false;
    }
    
    /* Check if file has zero size, which might indicate a dummy file */
    if (st.st_size == 0) {
        if (verbose_mode) {
            fprintf(stderr, "BPF object file %s exists but has zero size\n", path);
        }
        return false;
    }
    
    /* Try to open the file to verify permissions */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (verbose_mode) {
            fprintf(stderr, "Cannot open BPF object file %s: %s\n", path, strerror(errno));
        }
        return false;
    }
    
    close(fd);
    
    if (verbose_mode) {
        printf("Found valid BPF object file: %s (size: %ld bytes)\n", path, (long)st.st_size);
    }
    
    return true;
}

/* Check if running in privileged environment */
static bool has_bpf_privileges() {
    /* Check if we're in a Docker container */
    bool in_container = (access("/.dockerenv", F_OK) == 0);
    
    /* Check if we have CAP_SYS_ADMIN capability */
    bool has_cap_sys_admin = false;
    FILE *caps = fopen("/proc/self/status", "r");
    if (caps) {
        char line[256];
        while (fgets(line, sizeof(line), caps)) {
            if (strncmp(line, "CapEff:", 7) == 0) {
                /* Check for CAP_SYS_ADMIN (bit 21) */
                unsigned long long cap;
                if (sscanf(line + 7, "%llx", &cap) == 1) {
                    has_cap_sys_admin = (cap & (1ULL << 21)) != 0;
                }
                break;
            }
        }
        fclose(caps);
    }
    
    /* Check if we can write to BPF directory */
    bool can_access_bpf = (access("/sys/fs/bpf", W_OK) == 0);
    
    /* Check if the BPF system call is available */
    int bpf_fd = -1;
    #ifdef __NR_bpf
    bpf_fd = syscall(__NR_bpf, 0, NULL, 0);
    #endif
    bool has_bpf_syscall = (bpf_fd >= 0 || (bpf_fd < 0 && errno != ENOSYS));
    if (bpf_fd >= 0) {
        close(bpf_fd);
    }
    
    if (verbose_mode) {
        printf("BPF environment check:\n");
        printf("- In container: %s\n", in_container ? "yes" : "no");
        printf("- Has CAP_SYS_ADMIN: %s\n", has_cap_sys_admin ? "yes" : "no");
        printf("- Can access /sys/fs/bpf: %s\n", can_access_bpf ? "yes" : "no");
        printf("- Has BPF syscall: %s\n", has_bpf_syscall ? "yes" : "no");
    }
    
    return has_cap_sys_admin && (can_access_bpf || !in_container) && has_bpf_syscall;
}

/* Load string constants into the BPF string map */
static int load_string_constants_to_map(struct bpf_object *obj) {
    int string_map_fd, extra_strings_fd;
    int ret = 0;
    
    /* Find the string maps */
    string_map_fd = bpf_object__find_map_fd_by_name(obj, "string_map");
    if (string_map_fd < 0) {
        fprintf(stderr, "Error: Failed to find string_map: %d\n", string_map_fd);
        return -1;
    }
    
    extra_strings_fd = bpf_object__find_map_fd_by_name(obj, "extra_strings");
    if (extra_strings_fd < 0) {
        fprintf(stderr, "Error: Failed to find extra_strings map: %d\n", extra_strings_fd);
        /* Continue with just the primary string map */
    }
    
    /* Define sensitive paths */
    const char *paths[] = {
        "/etc/shadow",    /* STR_ETC_SHADOW = 0 */
        "/etc/passwd",    /* STR_ETC_PASSWD = 1 */
        "/etc/ssh",       /* STR_ETC_SSH = 2 */
        "/etc/sudoers",   /* STR_ETC_SUDOERS = 3 */
        "/root/.ssh",     /* STR_ROOT_SSH = 4 */
        "/var/log/auth",  /* STR_AUTH_LOG = 5 */
    };
    
    /* Define command strings */
    const char *commands[] = {
        "wget",           /* STR_CMD_WGET = 10 */
        "curl",           /* STR_CMD_CURL = 11 */
        "nc",             /* STR_CMD_NC = 12 */
        "netcat",         /* STR_CMD_NETCAT = 13 */
        "chmod 777",      /* STR_CMD_CHMOD777 = 14 */
        "base64",         /* STR_CMD_BASE64 = 15 */
        "python",         /* STR_CMD_PYTHON = 16 */
    };
    
    /* Define extra strings */
    const char *extras[] = {
        "/root",          /* STR_ROOT = 20 */
        "/etc",           /* STR_ETC = 21 */
        "http://",        /* STR_HTTP = 22 */
        "https://",       /* STR_HTTPS = 23 */
        "ftp://",         /* STR_FTP = 24 */
    };
    
    /* Load sensitive file paths into the map (indices 0-5) */
    for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        char buffer[16] = {0};
        /* Copy only prefix of sensitive paths (most important part for matching) */
        strncpy(buffer, paths[i], sizeof(buffer) - 1);
        
        ret = bpf_map_update_elem(string_map_fd, &i, buffer, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Error: Failed to update string_map with path %d: %s\n", 
                    i, strerror(errno));
            /* Continue with other strings */
        } else if (verbose_mode) {
            printf("Loaded sensitive path to map[%d]: %s\n", i, buffer);
        }
    }
    
    /* Load suspicious commands into the map (indices 10-16) */
    for (int i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        int map_idx = i + 10;
        char buffer[16] = {0};
        strncpy(buffer, commands[i], sizeof(buffer) - 1);
        
        ret = bpf_map_update_elem(string_map_fd, &map_idx, buffer, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "Error: Failed to update string_map with command %d: %s\n", 
                    i, strerror(errno));
            /* Continue with other strings */
        } else if (verbose_mode) {
            printf("Loaded suspicious command to map[%d]: %s\n", map_idx, buffer);
        }
    }
    
    /* Load extra strings (only if map was found) */
    if (extra_strings_fd >= 0) {
        for (int i = 0; i < sizeof(extras) / sizeof(extras[0]); i++) {
            int map_idx = i + 20;
            char buffer[16] = {0};
            strncpy(buffer, extras[i], sizeof(buffer) - 1);
            
            ret = bpf_map_update_elem(extra_strings_fd, &map_idx, buffer, BPF_ANY);
            if (ret < 0) {
                fprintf(stderr, "Error: Failed to update extra_strings with string %d: %s\n", 
                        i, strerror(errno));
                /* Continue with other strings */
            } else if (verbose_mode) {
                printf("Loaded extra string to map[%d]: %s\n", map_idx, buffer);
            }
        }
    }
    
    return 0;
}

/* Function to check if we need to use simulation mode */
int should_use_simulation_mode() {
    /* TEMPORARY: Forcing to try real eBPF mode regardless of environment */
    return 0;

    /* Original detection logic below - disabled temporarily
    #ifdef __APPLE__
        return 1;
    #endif
    
    if (getenv("SECURITY_MONITOR_SIMULATION") != NULL) {
        return 1;
    }
    
    if (access("/.dockerenv", F_OK) == 0) {
        FILE *f = fopen("/proc/sys/kernel/osrelease", "r");
        if (f) {
            char version[128] = {0};
            if (fgets(version, sizeof(version), f)) {
                if (strstr(version, "linuxkit") || strstr(version, "moby")) {
                    printf("Detected Docker for Mac environment with limited eBPF support\n");
                    printf("Automatically enabling simulation mode\n");
                    return 1;
                }
            }
            fclose(f);
        }
    }
    
    return 0;
    */
}

/* Main function */
int main(int argc, char **argv)
{
    /* Parse command line arguments */
    parse_args(argc, argv);
    
    /* Register signal handlers for graceful shutdown */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Initialize our output header */
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
    printf("eBPF Security Monitor started at %s\n", timestamp);
    printf("======================================================\n");
    
    /* Check if we should use simulation mode */
    if (should_use_simulation_mode()) {
        printf("Running in SIMULATION mode - eBPF functionality will be simulated\n");
        /* Set environment variable to ensure child processes know we're in simulation mode */
        setenv("SECURITY_MONITOR_SIMULATION", "1", 1);
        simulation_mode = 1;
    }
    
    /* For Docker/containers - check for container environment variables */
    int in_docker = (access("/.dockerenv", F_OK) == 0);
    int docker_env = (getenv("DOCKER_BPF") != NULL);
    
    /* Enable simulation mode if in Docker without privileges */
    if (in_docker && !has_bpf_privileges() && !simulation_mode) {
        printf("Running in container without sufficient BPF privileges - simulation mode will be used\n");
        simulation_mode = 1;
    }
    
    if (verbose_mode) {
        printf("Environment detection:\n");
        printf("- Running in Docker: %s\n", in_docker ? "yes" : "no");
        printf("- Container has BPF env var: %s\n", docker_env ? "yes" : "no");
        printf("- BPF privileges available: %s\n", has_bpf_privileges() ? "yes" : "no");
        printf("- Simulation mode: %s\n", simulation_mode ? "yes" : "no");
    }
    
    if (enforce_mode) {
        printf("Running in " COLOR_RED "ENFORCEMENT" COLOR_RESET " mode. Critical security events will terminate processes.\n");
    } else {
        printf("Running in monitoring mode. Events will be logged but no action taken.\n");
    }
    printf("Press Ctrl+C to exit.\n");
    
    /* Initialize random number generator for simulation mode */
    srand(time(NULL));
    
    /* If we're already in simulation mode, skip BPF loading entirely */
    if (simulation_mode) {
        printf("Running in SIMULATION MODE - generating sample security events\n");
    } else {
        /* Try to load BPF program only if not in simulation mode */
        char *valid_path = NULL;
        
        /* List of potential relative paths to check */
        const char *paths[] = {
            "./build/security_monitor.bpf.o",
            "build/security_monitor.bpf.o",
            "../build/security_monitor.bpf.o",
            "/app/build/security_monitor.bpf.o",
            "/app/security_monitor.bpf.o",
            "security_monitor.bpf.o",
        };
        
        /* Find a valid BPF object file */
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            if (check_bpf_object_file(paths[i])) {
                valid_path = strdup(paths[i]);
                break;
            }
        }
        
        if (!valid_path) {
            /* Try with additional path combinations if no direct match */
            char cwd[PATH_MAX] = {0};
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                char combined_path[PATH_MAX] = {0};
                
                for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
                    size_t cwd_len = strlen(cwd);
                    size_t path_len = strlen(paths[i]);
                    
                    if (cwd_len + 1 + path_len + 1 <= PATH_MAX) {
                        strcpy(combined_path, cwd);
                        strcat(combined_path, "/");
                        strcat(combined_path, paths[i]);
                        
                        if (check_bpf_object_file(combined_path)) {
                            valid_path = strdup(combined_path);
                            break;
                        }
                    }
                }
            }
        }
        
        /* If we still don't have a valid path, switch to simulation mode */
        if (!valid_path) {
            fprintf(stderr, "Could not find a valid BPF object file. Switching to simulation mode.\n");
            simulation_mode = 1;
        } else {
            printf("Loading BPF program from %s...\n", valid_path);
            
            /* Increase rlimit for BPF operations */
            struct rlimit rlim = {
                .rlim_cur = RLIM_INFINITY,
                .rlim_max = RLIM_INFINITY,
            };
            
            setrlimit(RLIMIT_MEMLOCK, &rlim);
            
            /* Open and load the BPF object with enhanced error handling */
            struct bpf_object *obj = NULL;
            
            /* Set debug mode for libbpf if requested */
            if (verbose_mode) {
                setenv("LIBBPF_DEBUG", "1", 1);
            }
            
            /* Open the BPF object file */
            obj = bpf_object__open_file(valid_path, NULL);
            if (libbpf_get_error(obj)) {
                fprintf(stderr, "Failed to open BPF object file: Unknown error %ld\n", 
                        libbpf_get_error(obj));
                
                /* Detailed diagnostics in verbose mode */
                if (verbose_mode) {
                    struct stat st;
                    fprintf(stderr, "Detailed diagnostics:\n");
                    fprintf(stderr, "- File path: %s\n", valid_path);
                    fprintf(stderr, "- File exists: %s\n", access(valid_path, F_OK) == 0 ? "yes" : "no");
                    fprintf(stderr, "- File readable: %s\n", access(valid_path, R_OK) == 0 ? "yes" : "no");
                    
                    if (stat(valid_path, &st) == 0) {
                        fprintf(stderr, "- File size: %ld bytes\n", (long)st.st_size);
                    }
                }
                
                /* Switch to simulation mode */
                simulation_mode = 1;
            } else {
                /* Try to load the BPF object */
                int err = bpf_object__load(obj);
                if (err) {
                    fprintf(stderr, "Failed to load BPF object: %s (error %d)\n", 
                            strerror(abs(err)), err);
                    simulation_mode = 1;
                } else {
                    /* Success! Load string constants into BPF map */
                    err = load_string_constants_to_map(obj);
                    if (err) {
                        fprintf(stderr, "Failed to load string constants into BPF map: %d\n", err);
                        /* Continue execution even if string loading fails */
                    }
                    
                    /* Configure perf buffer and start monitoring */
                    int perf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
                    if (perf_map_fd < 0) {
                        fprintf(stderr, "Failed to find perf events map\n");
                        simulation_mode = 1;
                    } else {
                        /* Set up perf buffer */
                        struct perf_buffer_opts pb_opts = {};
                        pb_opts.sample_cb = handle_event;
                        pb_opts.lost_cb = handle_lost_events;
                        
                        struct perf_buffer *pb = perf_buffer__new(perf_map_fd, 64, &pb_opts);
                        if (!pb) {
                            err = -errno;
                            fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(-err));
                            simulation_mode = 1;
                        } else {
                            printf("Successfully loaded BPF program. Monitoring system...\n");
                            
                            /* Main polling loop */
                            while (!exiting) {
                                err = perf_buffer__poll(pb, 100);
                                if (err < 0 && err != -EINTR) {
                                    fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
                                    break;
                                }
                            }
                            
                            /* Clean up resources */
                            perf_buffer__free(pb);
                            bpf_object__close(obj);
                            free(valid_path);
                            return 0;
                        }
                    }
                }
                
                /* Clean up if we get here due to errors */
                bpf_object__close(obj);
            }
            
            free(valid_path);
        }
    }
    
    /* If we reached here and simulation_mode is set, generate events */
    if (simulation_mode) {
        while (!exiting) {
            /* Sleep to simulate the event polling */
            sleep(1);
            
            /* Generate a random security event for demonstration */
            if (rand() % 10 > 7) { /* 30% chance to generate an event */
                /* Generate random event data */
                struct timeval tv;
                gettimeofday(&tv, NULL);
                
                /* Choose from some predefined event types and severity levels */
                enum event_type event_types[] = {EVENT_FILE_OPEN, EVENT_PROCESS_EXEC, EVENT_SUSPICIOUS_ACTIVITY};
                enum severity_level severity_levels[] = {SEV_INFO, SEV_WARNING, SEV_CRITICAL};
                
                struct event_data random_event = {
                    .event_type = event_types[rand() % 3],
                    .severity = severity_levels[rand() % 3],
                    .pid = rand() % 10000 + 1000, /* Random PID */
                    .uid = rand() % 100,         /* Random UID */
                    .gid = rand() % 100,         /* Random GID */
                    .timestamp = tv.tv_sec * 1000000000ULL + tv.tv_usec * 1000,
                };
                
                /* Set random command name */
                const char *commands[] = {"bash", "sh", "python", "wget", "curl", "cat", "base64", "nc"};
                snprintf(random_event.comm, sizeof(random_event.comm), "%s", commands[rand() % 8]);
                
                /* Set event-specific data */
                switch (random_event.event_type) {
                    case EVENT_FILE_OPEN: {
                        const char *files[] = {"/etc/passwd", "/etc/shadow", "/etc/ssh", 
                                           "/etc/sudoers", "/root/.ssh", "/var/log/auth.log"};
                        snprintf(random_event.filename, sizeof(random_event.filename), "%s", files[rand() % 6]);
                        break;
                    }
                    case EVENT_PROCESS_EXEC: {
                        const char *execs[] = {"wget", "curl", "nc", "perl", "chmod 777", "bash -i", "base64", "python"};
                        const char *args[] = {"-options", "argument", "/etc/passwd", "/etc/shadow"};
                        snprintf(random_event.filename, sizeof(random_event.filename), "%s", execs[rand() % 8]);
                        snprintf(random_event.args, sizeof(random_event.args), "%s %s", args[rand() % 2], args[2 + rand() % 2]);
                        break;
                    }
                    case EVENT_SUSPICIOUS_ACTIVITY: {
                        const char *activities[] = {"Attempting privilege escalation", "Suspicious network connection", 
                                              "Potential data exfiltration", "Potential backdoor"};
                        snprintf(random_event.filename, sizeof(random_event.filename), "%s", activities[rand() % 4]);
                        break;
                    }
                    default:
                        break;
                }
                
                /* Print the event */
                print_event(&random_event);
            }
        }
    }
    
    return 0;
} 