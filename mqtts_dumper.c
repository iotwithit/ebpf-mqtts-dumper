#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6
#define ETH_HLEN 14

/*eBPF program.
  Filter TCP packets, from or to port FILTER_PORT
  the program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int mqtts_dumper(struct __sk_buff *skb) {

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

    //check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) {
		goto DROP;
	}

    //shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	if (tcp->src_port != FILTER_PORT && tcp->dst_port != FILTER_PORT) {
		goto DROP;
	}

	//keep the packet and send it to userspace returning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;
}
