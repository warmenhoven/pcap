#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* this should be session stuff */
static unsigned char src_hw[6], dst_hw[6];
static uint32_t src_ip, dst_ip;
static uint16_t src_prt, dst_prt;
static uint32_t seqno;
/* should also have ackno */

/* this is global pcap stuff */
static char *dev;
static pcap_t *lph;

/* this will be useful when sessions are implemented */
enum tcp_states {
	CLOSED,
	LISTEN,
	SYN_RCVD,
	SYN_SENT,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK
};

/* i'm sure i didn't need to do this */
struct enet {
	unsigned char dst_hw[6];
	unsigned char src_hw[6];
	uint16_t type;
} __attribute__((packed));

struct arp {
	struct enet enet;
	uint16_t hrd;
	uint16_t pro;
	uint8_t hln;
	uint8_t pln;
	uint16_t op;
	unsigned char src_hw[6];
	uint32_t src_ip;
	unsigned char dst_hw[6];
	uint32_t dst_ip;
} __attribute__((packed));

struct ip_pkt {
	struct enet enet;
	unsigned int ver : 4;
	unsigned int ihl : 4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	unsigned int flags : 3;
	unsigned int frag : 13;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t hdr_csum;
	uint32_t src_ip;
	uint32_t dst_ip;
} __attribute__((packed));

struct tcp_pkt {
	struct ip_pkt ip;
	uint16_t src_prt;
	uint16_t dst_prt;
	uint32_t seqno;
	uint32_t ackno;
	unsigned int offset : 4;
	unsigned int res : 4;
	uint8_t control;
	uint16_t window;
	uint16_t csum;
	uint16_t urg;
} __attribute__((packed));

/* global */
int init_pcap()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (!(dev = pcap_lookupdev(errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}
	return 0;
}

/* global */
int init_filter()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char *filter_line = malloc(4 + 3 + 5 + 6);
	struct bpf_program filter;
	sprintf(filter_line, "arp or port %d", src_prt);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	lph = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
	if (!lph) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	pcap_compile(lph, &filter, filter_line, 0, net);

	if (pcap_setfilter(lph, &filter) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}
	return 0;
}

/* utility; should pass args */
int send_syn()
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	static libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	if (libnet_build_tcp(src_prt, dst_prt, seqno++, 0, TH_SYN, 32767,
			     0, 0, LIBNET_TCP_H, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}
	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 242, 0, 64, IPPROTO_TCP,
			      0, src_ip, dst_ip, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}

	libnet_destroy(lnh);
	return 0;
}

/* utility; should pass args */
int send_ack(uint32_t ackno)
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	static libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	if (libnet_build_tcp(src_prt, dst_prt, seqno++, ackno, TH_ACK, 32767,
			     0, 0, LIBNET_TCP_H, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}
	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 242, 0, 64, IPPROTO_TCP,
			      0, src_ip, dst_ip, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}

	libnet_destroy(lnh);
	return 0;
}

/* should deal with this more intelligently */
/* XXX convince the host we're running on that it can safely ignore us */
int arp_reply(unsigned char hw[6], uint32_t ip)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_LINK, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REPLY, src_hw,
			     (u_char *)&src_ip, hw, (u_char *)&ip, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}
	if (libnet_autobuild_ethernet(hw, ETHERTYPE_ARP, lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 1;
	}

	libnet_destroy(lnh);
	return 0;
}

/* main cb function. this needs to get rewritten. desperately. */
void packet_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct enet *enet = (struct enet *)pkt;
	if (ntohs(enet->type) == ETHERTYPE_IP) {
		struct ip_pkt *ip = (struct ip_pkt *)pkt;
		struct tcp_pkt *tcp = (struct tcp_pkt *)pkt;
		if (ip->src_ip == src_ip && ip->dst_ip == dst_ip && !src_hw[0]) {
			memcpy(src_hw, enet->src_hw, 6);
			memcpy(dst_hw, enet->dst_hw, 6);
		}

		if (ip->protocol != IPPROTO_TCP)
			return;
		if (ip->src_ip != dst_ip || ip->dst_ip != src_ip)
			return;
		if (ntohs(tcp->src_prt) != dst_prt || ntohs(tcp->dst_prt) != src_prt)
			return;

		if (tcp->control & TH_SYN && tcp->control & TH_ACK)
			send_ack(ntohl(tcp->seqno) + 1);
	} else if (ntohs(enet->type) == ETHERTYPE_ARP) {
		struct arp *arp = (struct arp *)pkt;
		if ((ntohs(arp->op) == ARPOP_REQUEST) &&
		    (arp->dst_ip == src_ip) && memcmp(src_hw, arp->src_hw, 6))
			arp_reply(arp->src_hw, arp->src_ip);
	}
}

int main(int argc, char **argv)
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	static libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	init_pcap();
	seqno = libnet_get_prand(LIBNET_PRu32);

	dst_hw[0] = 0;
	dst_ip = libnet_name2addr4(lnh, argc > 1 ? argv[1] : "172.20.102.1", LIBNET_RESOLVE);
	dst_prt = argc > 2 ? atoi(argv[2]) : 80;
	src_hw[0] = 0;
	src_ip = libnet_name2addr4(lnh, argc > 3 ? argv[3] : "172.20.102.9", LIBNET_RESOLVE);
	src_prt = argc > 4 ? atoi(argv[4]) : 12345;

	libnet_destroy(lnh);

	init_filter();
	send_syn();
	pcap_loop(lph, -1, packet_cb, NULL);

	return 0;
}
