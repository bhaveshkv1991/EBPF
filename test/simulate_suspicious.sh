#!/bin/bash

# Security Monitor Attack Simulation Script
# This script simulates various suspicious activities to test the security monitor

echo "===== Security Monitor Attack Simulation ====="
echo "This script will simulate various suspicious activities"
echo "Run the security monitor in another terminal to observe detections"
echo ""

# Function to simulate an attack with a delay
simulate_attack() {
    echo -e "\n[+] Simulating: $1"
    echo "    Command: $2"
    sleep 1
    eval $2
    sleep 2  # Give the monitor time to detect and report
}

# 1. Attempt to access sensitive files
simulate_attack "Accessing /etc/shadow" "cat /etc/shadow 2>/dev/null || echo 'Access denied (expected)'"
simulate_attack "Accessing /etc/passwd" "cat /etc/passwd | head -n 3"
simulate_attack "Accessing SSH configuration" "ls -la /etc/ssh/ 2>/dev/null || echo 'Directory not found'"

# 2. Execute suspicious commands
simulate_attack "Running wget" "wget --version | head -n 1 || echo 'wget not installed'"
simulate_attack "Running curl with suspicious URL" "curl --version | head -n 1 || echo 'curl not installed'"
simulate_attack "Using netcat" "which nc && echo 'nc found' || echo 'nc not installed'"
simulate_attack "Base64 encoding/decoding" "echo 'suspicious data' | base64"

# 3. Privilege escalation attempts
simulate_attack "Attempting to change file permissions" "touch /tmp/test_file && chmod 777 /tmp/test_file && ls -la /tmp/test_file && rm /tmp/test_file"
simulate_attack "Attempting to run sudo" "sudo -l || echo 'sudo check failed (expected in container)'"

# 4. Suspicious process behavior
simulate_attack "Running bash with interactive flag" "bash -i -c 'echo This is an interactive shell; exit' 2>/dev/null"
simulate_attack "Python executing a command" "python3 -c 'print(\"Executing Python one-liner\")' || python -c 'print(\"Executing Python one-liner\")' || echo 'Python not installed'"

# 5. Simulating file operations in sensitive locations
simulate_attack "Creating files in /tmp" "echo 'potentially malicious script' > /tmp/suspicious.sh && chmod +x /tmp/suspicious.sh && ls -la /tmp/suspicious.sh && rm /tmp/suspicious.sh"
simulate_attack "Accessing system logs" "ls -la /var/log/ | grep auth || echo 'Auth logs not found'"

echo -e "\n===== Attack Simulation Completed ====="
echo "Check the security monitor output for detected events" 