#!/bin/sh
# Records the host the experiments ran on (paper: Experimental Setup)
{
echo "cpu: $(lscpu | sed -n 's/^Model name:[ \t]*//p')"
echo "vcpus: $(nproc)"
echo "mem_GB: $(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo)"
echo "os: $(. /etc/os-release; echo $PRETTY_NAME)"
echo "kernel: $(uname -r)"
echo "virt: $(systemd-detect-virt 2>/dev/null || echo unknown)"
echo "gcc: $(gcc -dumpfullversion)"
echo "openssl: $(openssl version)"
} 
