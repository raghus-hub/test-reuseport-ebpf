#!/usr/bin/python
from bcc import BPF

# Add a BPF probe event that lets us know if reuseport_select_socket kernel
# function is getting called or not (i.e, to make sure eBPF code is being called

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>

int hello(struct pt_regs *ctx) {
  void *ret = PT_REGS_RC(ctx);
  bpf_trace_printk("Hello, World %p!\\n", ret);
  return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kretprobe(event="reuseport_select_sock", fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
  try:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
  except ValueError:
    continue
  print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
