FROM ubuntu:22.04

# Install dependencies for eBPF development
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    bpfcc-tools \
    bpftrace \
    gcc-multilib \
    linux-tools-generic \
    pkg-config \
    git \
    make \
    curl \
    wget \
    ca-certificates \
    zip unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up work directory
WORKDIR /app

# Set environment variable to indicate Docker eBPF environment
ENV DOCKER_BPF=1

# Default command to keep container running
CMD ["sleep", "infinity"]
