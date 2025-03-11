#!/bin/bash
# ensure_bpf_headers.sh - Installs necessary headers and tools for eBPF development

set -e

echo "=== Installing necessary headers and dependencies for eBPF development ==="

# Update package lists
apt-get update -qq

# Install essential build tools
apt-get install -y build-essential cmake clang llvm libelf-dev

# Install LLVM/Clang for BPF compilation
apt-get install -y llvm clang

# Install Linux headers
apt-get install -y linux-headers-generic

# Install libbpf development files
apt-get install -y libbpf-dev

# Create symlinks for headers if needed
if [ ! -d "/usr/include/bpf" ]; then
    echo "Creating BPF include directory..."
    mkdir -p /usr/include/bpf
fi

# Create symlinks if needed
if [ ! -f "/usr/include/bpf/bpf_helpers.h" ]; then
    echo "Looking for bpf_helpers.h..."
    if [ -f "/usr/include/linux/bpf_helpers.h" ]; then
        ln -sf /usr/include/linux/bpf_helpers.h /usr/include/bpf/bpf_helpers.h
    elif [ -f "/usr/local/include/bpf/bpf_helpers.h" ]; then
        ln -sf /usr/local/include/bpf/bpf_helpers.h /usr/include/bpf/bpf_helpers.h
    else
        echo "Warning: bpf_helpers.h not found. Creating minimal version..."
        cat > /usr/include/bpf/bpf_helpers.h << 'EOF'
/* Minimal BPF helpers header */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>

/* BPF helper functions */
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *) BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) = (void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_probe_read_user)(void *dst, int size, const void *src) = (void *) BPF_FUNC_probe_read_user;
static int (*bpf_probe_read_user_str)(void *dst, int size, const void *src) = (void *) BPF_FUNC_probe_read_user_str;
static int (*bpf_get_current_comm)(void *buf, int size_of_buf) = (void *) BPF_FUNC_get_current_comm;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_perf_event_output)(void *ctx, void *map, int, void *data, int size) = (void *) BPF_FUNC_perf_event_output;

#endif /* __BPF_HELPERS_H */
EOF
    fi
fi

# Create other necessary headers if they don't exist
if [ ! -f "/usr/include/bpf/bpf_tracing.h" ]; then
    echo "Creating minimal bpf_tracing.h..."
    cat > /usr/include/bpf/bpf_tracing.h << 'EOF'
/* Minimal BPF tracing header */
#ifndef __BPF_TRACING_H
#define __BPF_TRACING_H

#include <linux/types.h>

#endif /* __BPF_TRACING_H */
EOF
fi

if [ ! -f "/usr/include/bpf/bpf_core_read.h" ]; then
    echo "Creating minimal bpf_core_read.h..."
    cat > /usr/include/bpf/bpf_core_read.h << 'EOF'
/* Minimal BPF core read header */
#ifndef __BPF_CORE_READ_H
#define __BPF_CORE_READ_H

#include <linux/types.h>

#endif /* __BPF_CORE_READ_H */
EOF
fi

echo "=== Setup complete. eBPF development environment is ready. ===" 