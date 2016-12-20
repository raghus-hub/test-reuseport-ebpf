#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

/*
 * The eBPF Filter program
 * For now only return one index value (0) so only one process is selected
 */
int bpf_socket_filter(struct __sk_buff *skb) {
//  bpf_trace_printk("Hello, World!\\n");
  return 2;
}
