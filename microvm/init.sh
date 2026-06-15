#!/bin/sh
# PID 1 inside the chef microVM. Minimal init: mount the essentials, mount the
# I/O disk (vdb), run the payload it carries, then power the VM off so the host
# 'qemu' call returns. busybox provides mount/poweroff in the slim rootfs.
BB=/bin/busybox
$BB mount -t proc proc /proc 2>/dev/null
$BB mount -t sysfs sysfs /sys 2>/dev/null
$BB mkdir -p /io
$BB mount -t ext4 /dev/vdb /io 2>/dev/null

if [ -f /io/run.sh ]; then
    /bin/sh /io/run.sh > /io/console.log 2>&1
    echo "run.sh exit=$?" >> /io/console.log
fi

$BB sync
# Tell the host (qemu -no-reboot) to stop by issuing a power-off.
$BB poweroff -f 2>/dev/null
# Fallback if busybox poweroff is unavailable.
echo o > /proc/sysrq-trigger 2>/dev/null
# Last resort: do not return from PID 1.
while true; do $BB sleep 1; done
