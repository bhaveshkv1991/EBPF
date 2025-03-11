# eBPF Security Monitor

An eBPF-based security monitoring tool that detects suspicious activities on Linux systems.

## Overview

This project uses eBPF (Extended Berkeley Packet Filter) to monitor system calls and detect various security threats, including:

- Access to sensitive files (`/etc/shadow`, `/etc/passwd`, etc.)
- Execution of suspicious commands and processes
- Privilege escalation attempts
- Suspicious network activity

The monitor can run in two modes:
- **Monitoring Mode**: Detects and logs suspicious activities
- **Enforcement Mode**: Additionally terminates processes when critical threats are detected

## Requirements

- **Linux**: Kernel 5.8+ (for full eBPF support)
- **macOS/Other**: Docker and Docker Compose with simulation mode support
- Docker and Docker Compose for the containerized environment
- BCC tools (automatically installed in the container)
- clang, libelf, libbpf (automatically installed in the container)

## Cross-Platform Support

The security monitor has been designed to work in multiple environments:

- **Linux**: Full eBPF functionality with kernel-level monitoring
- **macOS/Other**: Simulation mode that runs the suspicious activities script to demonstrate what would be detected

## Compilation Methods

The project supports two compilation approaches:

### 1. Container-Based Compilation (Recommended)

This approach compiles the eBPF code inside a Linux container, which ensures all necessary kernel headers and tools are available:

```bash
# Use the provided script to compile inside the container
./compile-in-container.sh
```

This method works on both Linux and macOS hosts, and guarantees the most reliable eBPF compilation.

### 2. Native Compilation

For Linux systems with eBPF support, you can compile directly:

```bash
make clean && make
```

On non-Linux systems (like macOS), this will automatically fall back to simulation mode.

## Running the Monitor

### Inside Container (Recommended for macOS)

```bash
# Run in standard mode
docker-compose exec ebpf-dev /app/build/security_monitor

# Run with verbose output
docker-compose exec ebpf-dev /app/build/security_monitor -v

# Run in enforcement mode
docker-compose exec ebpf-dev /app/build/security_monitor -e

# Explicitly enable simulation mode (for macOS/Windows)
docker-compose exec -e SECURITY_MONITOR_SIMULATION=1 ebpf-dev /app/build/security_monitor -v

# Run simulation with test script
docker-compose exec -e SECURITY_MONITOR_SIMULATION=1 ebpf-dev bash -c 'cd /app && ./build/security_monitor -v & sleep 2 && ./test/simulate_suspicious.sh; wait'
```

### Native Execution (Linux only)

```bash
./build/security_monitor
```

## Deployment on Linux with Full eBPF Support

For full eBPF functionality without simulation, follow these steps on a Linux system with kernel 5.8+:

### 1. System Prerequisites

Install the required dependencies:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential clang llvm libelf-dev libbpf-dev bpfcc-tools linux-headers-$(uname -r)

# Fedora/CentOS/RHEL
sudo dnf install -y clang llvm elfutils-libelf-devel libbpf-devel bcc-devel kernel-devel make gcc
```

### 2. Clone and Compile

```bash
# Clone the repository
git clone https://github.com/your-username/ebpf-security-monitor.git
cd ebpf-security-monitor

# Compile natively
make clean && make
```

### 3. Run with Elevated Privileges

eBPF programs require elevated privileges to load and attach to system events:

```bash
# Run with sudo
sudo ./build/security_monitor

# Run with verbose output
sudo ./build/security_monitor -v

# Run in enforcement mode
sudo ./build/security_monitor -e
```

### 4. Run as a Service (Optional)

To run as a systemd service:

```bash
# Create a systemd service file
sudo bash -c 'cat > /etc/systemd/system/ebpf-security-monitor.service << EOF
[Unit]
Description=eBPF Security Monitor
After=network.target

[Service]
ExecStart=/path/to/ebpf-security-monitor/build/security_monitor -e
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF'

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable ebpf-security-monitor
sudo systemctl start ebpf-security-monitor

# Check status
sudo systemctl status ebpf-security-monitor
```

## Troubleshooting eBPF on Different Environments

### Docker on macOS/Windows

When running in Docker on macOS or Windows, you'll likely see errors like:

```
libbpf: Error in bpf_create_map_xattr(string_map):Invalid argument(-22). Retrying without BTF.
libbpf: map 'string_map': failed to create: Invalid argument(-22)
libbpf: failed to load object './build/security_monitor.bpf.o'
```

This is expected because Docker on these platforms runs in a VM with limited eBPF support. The program will automatically fall back to simulation mode.

### Linux VMs

For development on non-Linux systems, using a Linux VM provides better eBPF support than Docker:

1. **UTM** (for Apple Silicon Macs): Install Ubuntu 22.04+ 
2. **VirtualBox/Parallels/VMware**: Install a recent Linux distribution

### Cloud-Based Development

For the best eBPF development experience on non-Linux systems:

1. **GitHub Codespaces**: Configure with appropriate dependencies
2. **Remote SSH to Linux host**: Connect to a proper Linux server
3. **Cloud VM instances**: Use a Linux-based VM in AWS/GCP/Azure

## License

This project is licensed under the GPL License. # EBPF
