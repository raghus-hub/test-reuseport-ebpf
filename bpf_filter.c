#include <net/sock.h>
#include <uapi/linux/ip.h>

/* Return 0 for socket at index=1, i.e., first process,  if saddr is localhost
 *        1 for socket at index=2, i.e., second process, o/w
 */
int bpf_socket_filter(struct __sk_buff *skb) {
  u8 ip_proto;
  int nh_off = BPF_LL_OFF + ETH_HLEN;
  const u32 localhost_ip = 0x7f000001;

  /* Trust that we have TCP/IP packet */
  u32 saddr = load_word(skb, nh_off + offsetof(struct iphdr, saddr));
  if (saddr == localhost_ip) {
    return 0;
  } else {
    return 1;
  }
  /* We never get here */
  return 2;
}
