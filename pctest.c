#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum tcp_state {
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

struct tcp_session {
	enum tcp_state state;

	libnet_t *lnh;
	libnet_ptag_t tcp_id;
	libnet_ptag_t ip_id;

	unsigned char src_hw[6];
	uint32_t src_ip;
	uint16_t src_prt;

	uint32_t dst_ip;
	uint16_t dst_prt;

	uint32_t seqno;
	uint32_t ackno;

	/* there's really a bunch of other stuff that I should be paying
	 * attention to */
};

/* I'm sure I didn't need to do this */
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
	struct ip_pkt ip;	/* XXX this is wrong. I'll fix it once I start
				   testing with servers other than Linux. */
	uint16_t src_prt;
	uint16_t dst_prt;
	uint32_t seqno;
	uint32_t ackno;
	unsigned int offset : 4;
	unsigned int res : 4;
	uint8_t control;	/* the control bits are only the last 6, but
				   that gave me problems for some reason.
				   besides, you don't need ECN anyway. */
	uint16_t window;
	uint16_t csum;
	uint16_t urg;
} __attribute__((packed));

static pcap_t *init_pcap(struct tcp_session *sess)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	pcap_t *lph;

	bpf_u_int32 net;
	bpf_u_int32 mask;
	char *filter_line;
	struct bpf_program filter;

	if (!(dev = pcap_lookupdev(errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	lph = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
	if (!lph) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	filter_line = malloc(4 + 3 + 5 + 6);
	/* we need arp because we're faking a client. we only filter on port
	 * because 1) I'm lazy and 2) it should be good enough */
	sprintf(filter_line, "arp or port %d", sess->src_prt);
	pcap_compile(lph, &filter, filter_line, 0, net);
	free(filter_line);

	if (pcap_setfilter(lph, &filter) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}
	return lph;
}

static int send_tcp(struct tcp_session *sess, int flags)
{
	if ((sess->tcp_id =
	     libnet_build_tcp(sess->src_prt, sess->dst_prt, sess->seqno,
			      sess->ackno, flags, 32767, 0, 0, LIBNET_TCP_H,
			      NULL, 0, sess->lnh, sess->tcp_id)) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
		return 1;
	}
	if ((sess->ip_id =
	     libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 242, 0, 64,
			       IPPROTO_TCP, 0, sess->src_ip, sess->dst_ip,
			       NULL, 0, sess->lnh, sess->ip_id)) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
		return 1;
	}

	if (libnet_write(sess->lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
		return 1;
	}

	return 0;
}

/* XXX convince the host we're running on that it can safely ignore us */
static int arp_reply(struct tcp_session *sess, unsigned char hw[6], uint32_t ip)
{
	/* we don't reuse the sess libnet_t handle because it's a raw socket
	 * and we want link-level access. we probably could make this handle
	 * static so that we don't have to rebuild it too many times, but
	 * hopefully we should only need to build it once. */
	char errbuf[PCAP_ERRBUF_SIZE];
	libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_LINK, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REPLY,
			     sess->src_hw, (u_char *)&sess->src_ip, hw,
			     (u_char *)&ip, NULL, 0, lnh, 0) == -1) {
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

static void state_machine(struct tcp_session *sess, struct tcp_pkt *pkt)
{
	/* here we can assume that the pkt is part of the session and for us */

	/* XXX none of these things check seqno/ackno. they should. */

	if (pkt->control & TH_RST) {
		/* TODO: since we're only single-session right now, we just
		 * exit when we receive a RST. if we ever handle multiple
		 * sessions, we should handle this differently */
		fprintf(stderr, "Remote host sent RST, exiting\n");
		exit(1);
	}

	/* XXX none of these things check to see that only the flags they're
	 * expecting are set. if we're in FIN_WAIT_1 and we get SYN/FIN/ACK
	 * then we'll just exit instead of sending RST. this probably isn't a
	 * big problem. */
	switch (sess->state) {
	case CLOSED:
		/* we should never get here because we exit if we're closed */
		break;
	case LISTEN:
		/* TODO: we don't deal with listening ports yet */
		break;
	case SYN_RCVD:
		/* TODO: we don't deal with listening ports yet */
		break;
	case SYN_SENT:
		if ((pkt->control & TH_SYN) && (pkt->control & TH_ACK)) {
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			sess->state = ESTABLISHED;
			printf("ESTABLISHED\n");
		} else {
			/* XXX actually if we get SYN but no ACK we're supposed
			 * to send an ACK, go to SYN_RCVD, and wait for the ACK
			 * to our SYN. but I don't care about that. */
			send_tcp(sess, TH_RST);
			fprintf(stderr, "RST'ing (State = SYN_SENT, "
				"Control = %02x)\n", pkt->control);
			exit(1);
		}
		break;
	case ESTABLISHED:
		if (pkt->control & TH_FIN) {
			/* the other side wants to shut down the connection */
			sess->ackno = ntohl(pkt->seqno) + 1;
			/* we send both the FIN and the ACK together, and move
			 * right through CLOSE_WAIT to LAST_ACK */
			send_tcp(sess, TH_FIN | TH_ACK);
			/* we should move to LAST_ACK, and either wait for the
			 * ACK back or retry this packet after a timeout. but
			 * since we don't do timers and we don't feel like
			 * waiting around until the user kills us, we just
			 * assume we will get our ACK back fine and exit. */
			/* sess->state = LAST_ACK; */
			printf("LAST_ACK\n");
			exit(0);
		}
		/* XXX there are more cases of things to do here */
		break;
	case FIN_WAIT_1:
		/* we sent the initial FIN */
		if ((pkt->control & TH_ACK) && (pkt->control & TH_FIN)) {
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			/* just like LAST_ACK, we should move to TIME_WAIT, but
			 * we just assume everything went well */
			/* sess->state = TIME_WAIT; */
			printf("TIME_WAIT\n");
			exit(0);
		}

		if (pkt->control & TH_FIN) {
			/* ACK the FIN, wait for our ACK */
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			/* just like LAST_ACK, we should move to CLOSING, but
			 * we just assume everything went well */
			/* sess->state = CLOSING; */
			printf("CLOSING\n");
			exit(0);
		}

		if (pkt->control & TH_ACK) {
			/* we've got the ACK, now we're waiting for the FIN */
			sess->state = FIN_WAIT_2;
			printf("FIN_WAIT_2\n");
			break;
		}

		/* we didn't get ACK or FIN, so we RST */
		send_tcp(sess, TH_RST);
		fprintf(stderr, "RST'ing (State = FIN_WAIT_1, "
			"Control = %02x)\n", pkt->control);
		exit(1);

		break;
	case FIN_WAIT_2:
		if (pkt->control & TH_FIN) {
			/* we've got the FIN, send the ACK and we're done */
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			/* just like LAST_ACK, we should move to TIME_WAIT, but
			 * we just assume everything went well */
			/* sess->state = TIME_WAIT */
			printf("TIME_WAIT \n");
			exit(0);
		}

		/* we're waiting for FIN but didn't get it, so RST */
		send_tcp(sess, TH_RST);
		fprintf(stderr, "RST'ing (State = FIN_WAIT_2, "
			"Control = %02x)\n", pkt->control);
		exit(1);

		break;
	case CLOSING:
		/* we never get here because we just assume everything went
		 * fine, and we exit before waiting for our ACK */
		break;
	case TIME_WAIT:
		/* we never get here because we just assume everything went
		 * fine, and we exit before waiting for our ACK */
		break;
	case CLOSE_WAIT:
		/* we never get here because we send the FIN with the ACK */
		break;
	case LAST_ACK:
		/* we never get here because we just assume everything went
		 * fine, and we exit before waiting for our ACK */
		break;
	}
}

/* main cb function. this needs to get rewritten. desperately. */
static void packet_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct tcp_session *sess = (struct tcp_session *)user;
	struct enet *enet = (struct enet *)pkt;
	if (ntohs(enet->type) == ETHERTYPE_IP) {
		struct ip_pkt *ip = (struct ip_pkt *)pkt;
		struct tcp_pkt *tcp = (struct tcp_pkt *)pkt;

		/* this is a hack. if we don't already know the MAC address
		 * we're faking, then we use our syn packet (which pcap should
		 * pick up since we install the filter before sending the syn)
		 * to get our MAC address. there are better ways but not many
		 * of them are as portable or as easy */
		if (!sess->src_hw[0] && !sess->src_hw[1] &&
		    ip->src_ip == sess->src_ip && ip->dst_ip == sess->dst_ip) {
			memcpy(sess->src_hw, enet->src_hw, 6);
		}

		/* we only deal with TCP */
		if (ip->protocol != IPPROTO_TCP)
			return;
		/* if the packet isn't from this session, and we aren't the
		 * receiver, ignore it */
		if (ip->src_ip != sess->dst_ip || ip->dst_ip != sess->src_ip)
			return;
		if (ntohs(tcp->src_prt) != sess->dst_prt ||
		    ntohs(tcp->dst_prt) != sess->src_prt)
			return;

		/* this is where the real work begins */
		state_machine(sess, tcp);
	} else if (ntohs(enet->type) == ETHERTYPE_ARP) {
		/* since we're "faking" a client, we need to reply to arp
		 * requests as that client. the problem is, we're using the MAC
		 * address of the host, so if we get an arp from the host about
		 * our client, we need to just ignore it. the host should deal
		 * with this gracefully. (there has to be a better way.) */
		struct arp *arp = (struct arp *)pkt;
		if ((ntohs(arp->hrd) == ARPHRD_ETHER) &&	/* ethernet*/
		    (ntohs(arp->pro) == ETHERTYPE_IP) &&	/* ipv4 */
		    (ntohs(arp->op) == ARPOP_REQUEST) &&	/* request */
		    (arp->dst_ip == sess->src_ip) &&		/* for us */
		    memcmp(sess->src_hw, arp->src_hw, 6))	/* not host */
			arp_reply(sess, arp->src_hw, arp->src_ip);
	}
}

/* yeah baby. this is evil. NEVER USE sig_sess OUTSITE THE SIG HANDLER! */
struct tcp_session *sig_sess = NULL;
static void sighandler(int num)
{
	send_tcp(sig_sess, TH_RST);
	exit(0);
}

int main(int argc, char **argv)
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	pcap_t *lph;

	struct tcp_session *sess = calloc(1, sizeof (struct tcp_session));

	if (!(sess->lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	/* initial setup of the tcp session */
	/* sess->state = CLOSED; */
	sess->dst_ip = libnet_name2addr4(sess->lnh,
					 argc > 1 ? argv[1] : "172.20.102.1",
					 LIBNET_RESOLVE);
	sess->dst_prt = argc > 2 ? atoi(argv[2]) : 12345;
	/* there's probably some great easy portable way of getting the MAC
	 * address of the host we're going to be using. but since I don't know
	 * what it is we're going to use our super-fun hacky way. */
	bzero(sess->src_hw, 6);
	sess->src_ip = libnet_name2addr4(sess->lnh,
					 argc > 3 ? argv[3] : "172.20.102.9",
					 LIBNET_RESOLVE);
	sess->src_prt = argc > 4 ? atoi(argv[4]) : 12345;

	/* I hear I shouldn't use this function for anything real. oh well. */
	sess->seqno = libnet_get_prand(LIBNET_PRu32);

	if (!(lph = init_pcap(sess)))
		return 1;

	/* send the SYN, and we're off! */
	if (send_tcp(sess, TH_SYN))
		return 1;
	sess->seqno++;
	sess->state = SYN_SENT;
	printf("SYN_SENT\n");

	/* if the user kills this program, try and cleanup. it's only nice. */
	sig_sess = sess;
	signal(SIGINT, sighandler);

	/* XXX instead of this we should have our own loop, and check for
	 * packets using pcap_fileno(3) and select(2), so that we could have
	 * timers and such of our own. */
	pcap_loop(lph, -1, packet_cb, (void *)sess);

	/* I don't think we'll ever get here, unless things go very wrong */
	return 1;
}
