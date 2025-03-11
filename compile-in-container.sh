#!/bin/bash

# Script to compile eBPF security monitor inside the Linux container
# This ensures proper compilation with all required Linux headers and tools

set -e

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo "Error: Docker is not running or not accessible"
  exit 1
fi

# Build the container if it doesn't exist
echo "Building/updating the Docker container..."
docker-compose build

# Check if the container is running
if ! docker-compose ps | grep -q "ebpf-security-monitor"; then
  echo "Starting Docker container..."
  docker-compose up -d
fi

echo "=== Compiling eBPF security monitor inside Linux container ==="

# Make sure kernel headers are available in the container
docker-compose exec -T ebpf-dev bash -c "apt-get update && apt-get install -y linux-headers-\$(uname -r) || echo 'Using generic headers'"

# Install any missing dependencies
docker-compose exec -T ebpf-dev bash -c "if [ ! -f /usr/include/bpf/libbpf.h ]; then apt-get install -y libbpf-dev; fi"

# Execute the compilation inside the container
docker-compose exec -T ebpf-dev bash -c "cd /app && make clean && make"

# Check if the compilation was successful
if [ $? -eq 0 ]; then
  echo "=== Compilation successful ==="
  echo "BPF object file is now available at: ./build/security_monitor.bpf.o"
  echo "Userspace program is available at: ./build/security_monitor"
else
  echo "=== Compilation failed ==="
  exit 1
fi

# Print usage instructions
echo ""
echo "To run the security monitor inside the container:"
echo "docker-compose exec ebpf-dev /app/build/security_monitor"
echo ""
echo "To run with verbose debugging:"
echo "docker-compose exec ebpf-dev /app/build/security_monitor -v"
echo ""
echo "To run the security monitor with the simulation script:"
echo "docker-compose exec ebpf-dev bash -c 'cd /app && ./build/security_monitor -v & sleep 2 && ./test/simulate_suspicious.sh; fg'" 