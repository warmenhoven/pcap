/* valuable rfc's:
 *
 * 793, TCP
 * 1025, TCP bake off
 *
 * I'm sure there's more but those are all I knew off the top of my head
 *
 * right now in the TCP bake off I get 13 points:
 *
 * 0 from the Featherweight Division since I can't talk to myself yet (no
 *   listening sockets)
 *
 * 2 points for talking to someone else
 * 2 point for gracefully ending the conversaion
 * 4 points for repeating the above without reinitializing
 *
 * 5 points for being able to talk to more than one other TCP at the same time
 *   (since I can't actually "talk" to them yet, I'm only giving myself 5
 *   points, for being able to be connected to more than one at a time. once
 *   I'm able to exchange data then I'll get 2 more points in the Middleweight
 *   Division and the remainder of the 5 points here)
 *
 * but then, I haven't done any checksum tests, so unless the host itself
 * rejects faulty packets before they're given to pcap, I'm actually at 0
 * points so far....
 */

#include "list.h"

#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>

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
	uint32_t id;	/* heh. a more appropriate name might be 'fd'. */

	enum tcp_state state;

	/* quite honestly each session doesn't need its own socket but it does
	 * make some things simpler */
	libnet_t *lnh;
	libnet_ptag_t tcp_id;
	libnet_ptag_t ip_id;

	/* these describe the session. the src_ip is global. libnet_name2addr4
	 * puts ip addresses in network byte order, so those will always be
	 * that way. however, ports stored in the session will always be host
	 * byte order, so when comparing against what comes off the wire, make
	 * sure to do a proper translation */
	uint16_t src_prt;
	uint32_t dst_ip;
	uint16_t dst_prt;

	/* these are stored in host byte order mostly by default */
	uint32_t seqno;
	uint32_t ackno;

	/* there's really a bunch of other stuff that I should be paying
	 * attention to */
};

/* these are our global variables */
unsigned char src_hw[6];
uint32_t src_ip;
list *sessions;
uint32_t next_id = 0;
int sp[2];

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
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl : 4;
	unsigned int ver : 4;
#else
	unsigned int ver : 4;
	unsigned int ihl : 4;
#endif
	uint8_t tos;
	uint16_t len;
	uint16_t id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int frag : 13;
	unsigned int flags : 3;
#else
	unsigned int flags : 3;
	unsigned int frag : 13;
#endif
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
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int res : 4;
	unsigned int offset : 4;
	unsigned int control : 6;
	unsigned int ecn : 2;
#else
	unsigned int offset : 4;
	unsigned int res : 4;
	unsigned int ecn : 2;
	unsigned int control : 6;
#endif
	uint16_t window;
	uint16_t csum;
	uint16_t urg;
} __attribute__((packed));

static pcap_t *
init_pcap()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	pcap_t *lph;

	bpf_u_int32 net;
	bpf_u_int32 mask;
	char *filter_line;
	struct bpf_program filter;
	struct in_addr sa;

	if (!(dev = pcap_lookupdev(errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	if (!(lph = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	filter_line = malloc(5 + (4*4));
	/* libnet_name2addr4 puts src_ip in network byte order, so we don't
	 * need to do any of that here */
	sa.s_addr = src_ip;
	/* this filter line should give us everything we need (including arp
	 * requests) */
	sprintf(filter_line, "host %s", inet_ntoa(sa));
	pcap_compile(lph, &filter, filter_line, 0, net);
	free(filter_line);

	if (pcap_setfilter(lph, &filter) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}
	return lph;
}

static int
send_tcp(struct tcp_session *sess, int flags)
{
	if ((sess->tcp_id =
	     libnet_build_tcp(sess->src_prt, sess->dst_prt, sess->seqno,
			      sess->ackno, flags, 32767, 0, 0, LIBNET_TCP_H,
			      NULL, 0, sess->lnh, sess->tcp_id)) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
		return 0;
	}
	if ((sess->ip_id =
	     libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 242, 0, 64,
			       IPPROTO_TCP, 0, src_ip, sess->dst_ip,
			       NULL, 0, sess->lnh, sess->ip_id)) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
		return 0;
	}

	if (libnet_write(sess->lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
		return 0;
	}

	return 1;
}

/* yeah, I probably should figure out some way of reuing send_tcp instead of
 * just copying it. but eh. it probably isn't an issue. at least not often. */
static int
send_rst(uint32_t dst_ip, uint16_t dst_prt, uint32_t src_prt,
	 uint32_t seqno, uint32_t ackno)
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 0;
	}

	if (libnet_build_tcp(src_prt, dst_prt, seqno, ackno, TH_RST | TH_ACK,
			     0, 0, 0, LIBNET_TCP_H, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 0;
	}
	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0x10, 0, 0, 64,
			       IPPROTO_TCP, 0, src_ip, dst_ip, NULL, 0,
			       lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 0;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 0;
	}

	libnet_destroy(lnh);
	return 1;
}

static struct tcp_session *
find_session(uint32_t dst_ip, uint32_t dst_prt, uint32_t src_prt)
{
	list *l = sessions;

	while (l) {
		struct tcp_session *sess = l->data;
		if (sess->dst_ip == dst_ip &&
		    sess->dst_prt == dst_prt &&
		    sess->src_prt == src_prt)
			return sess;
		l = l->next;
	}

	return NULL;
}

/* there are probably several problems with this. */
static int
get_port(uint32_t dst_ip, uint16_t dst_prt)
{
	uint16_t src_prt;

	do {
		/* privileged ports, my ass */
		src_prt = libnet_get_prand(LIBNET_PRu16);
	} while (find_session(dst_ip, dst_prt, src_prt));

	return src_prt;
}

/* maybe eventually there will be a third argument, so you can specify the port
 * to connect from */
static struct tcp_session *
create_session(char *host, uint16_t port)
{
	struct tcp_session *sess = calloc(1, sizeof (struct tcp_session));
	char errbuf[LIBNET_ERRBUF_SIZE];

	/* sess->state = CLOSED; */

	if (!(sess->lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		free(sess);
		return NULL;
	}

	/* XXX we should have some check to see if sess->dst_ip == src_ip, so
	 * that we can detect when we're trying to send packets to ourselves,
	 * because we won't be able to put those packets out over the wire */
	sess->dst_ip = libnet_name2addr4(sess->lnh, host, LIBNET_RESOLVE);
	if (sess->dst_ip == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
		free(sess);
		return NULL;
	}
	sess->dst_prt = port;
	sess->src_prt = get_port(sess->dst_ip, sess->dst_prt);

	/* I hear I shouldn't use this function for anything real. oh well. */
	sess->seqno = libnet_get_prand(LIBNET_PRu32);

	/* send the SYN, and we're off! */
	send_tcp(sess, TH_SYN);
	sess->seqno++;
	sess->state = SYN_SENT;
	printf("SYN_SENT\n");

	sessions = list_append(sessions, sess);
	/* this is technically wrong but I doubt next_id will ever wrap (unless
	 * if you're doing mean things to this poor little program) */
	sess->id = next_id;
	printf("created session %d using port %d\n", next_id++, sess->src_prt);

	return sess;
}

/* after this function, sess is no longer valid (obviously) */
static void
remove_session(struct tcp_session *sess)
{
	sessions = list_remove(sessions, sess);
	libnet_destroy(sess->lnh);
	free(sess);
}

static int
state_machine(struct tcp_session *sess, struct tcp_pkt *pkt)
{
	/* here we can assume that the pkt is part of the session and for us */

	/* XXX none of these things check seqno/ackno. they should. */

	if (pkt->control & TH_RST) {
		fprintf(stderr, "Remote host sent RST\n");
		remove_session(sess);
		return 0;
	}

	/* XXX none of these things check to see that only the flags they're
	 * expecting are set. if we're in FIN_WAIT_1 and we get SYN/FIN/ACK
	 * then we'll just remove the session instead of sending RST. this
	 * probably isn't a big problem. */
	switch (sess->state) {
	case CLOSED:
		/* we should never get here because we just remove the session
		 * if it's closed */
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
			remove_session(sess);
			return 0;
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
			 * assume we will get our ACK back fine. */
			/* sess->state = LAST_ACK; */
			printf("LAST_ACK\n");
			remove_session(sess);
			return 0;
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
			remove_session(sess);
			return 0;
		}

		if (pkt->control & TH_FIN) {
			/* ACK the FIN, wait for our ACK */
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			/* just like LAST_ACK, we should move to CLOSING, but
			 * we just assume everything went well */
			/* sess->state = CLOSING; */
			printf("CLOSING\n");
			remove_session(sess);
			return 0;
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
		remove_session(sess);
		return 0;
	case FIN_WAIT_2:
		if (pkt->control & TH_FIN) {
			/* we've got the FIN, send the ACK and we're done */
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			/* just like LAST_ACK, we should move to TIME_WAIT, but
			 * we just assume everything went well */
			/* sess->state = TIME_WAIT */
			printf("TIME_WAIT \n");
			remove_session(sess);
			return 0;
		}

		/* we're waiting for FIN but didn't get it, so RST */
		send_tcp(sess, TH_RST);
		fprintf(stderr, "RST'ing (State = FIN_WAIT_2, "
			"Control = %02x)\n", pkt->control);
		remove_session(sess);
		return 0;
	case CLOSING:
		/* we never get here because we just assume everything went
		 * fine, and remove the sess before waiting for our ACK */
		break;
	case TIME_WAIT:
		/* we never get here because we just assume everything went
		 * fine, and remove the sess before waiting for our ACK */
		break;
	case CLOSE_WAIT:
		/* we never get here because we send the FIN with the ACK */
		break;
	case LAST_ACK:
		/* we never get here because we just assume everything went
		 * fine, and remove the sess before waiting for our ACK */
		break;
	}

	return 1;
}

static void
process_packet()
{
	struct pcap_pkthdr hdr;
	u_char *pkt;

	struct ip_pkt *ip;
	struct tcp_pkt *tcp;
	struct tcp_session *sess;

	/* XXX this section needs to be fixed, it assumes too much */
	if (read(sp[1], &hdr, sizeof (hdr)) != sizeof (hdr))
		return;
	pkt = malloc(hdr.len);
	if (read(sp[1], pkt, hdr.len) != hdr.len) {
		free(pkt);
		return;
	}

	ip = (struct ip_pkt *)pkt;

	/* XXX there are more IP options that we need to deal with. until then
	 * this program isn't a stack, it's a hack. */

	/* we only deal with TCP, because the host screws up ICMP for us */
	if (ip->protocol != IPPROTO_TCP) {
		free(pkt);
		return;
	}

	tcp = (struct tcp_pkt *)pkt;

	/* maybe we should move this check to state_machine. we'll see
	 * once we implement listening ports */
	if (!(sess = find_session(ip->src_ip, ntohs(tcp->src_prt),
				  ntohs(tcp->dst_prt)))) {
		send_rst(ip->src_ip, ntohs(tcp->src_prt),
			 ntohs(tcp->dst_prt), ntohl(tcp->ackno),
			 ntohl(tcp->seqno) + 1);
		free(pkt);
		return;
	}

	/* this is where the real work is */
	state_machine(sess, tcp);

	free(pkt);
}

static void
process_input()
{
	char buf[80];
	fgets(buf, sizeof(buf), stdin);
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;
	if (!strncasecmp(buf, "connect ", strlen("connect "))) {
		char *arg1, *arg2;
		arg1 = buf + strlen("connect ");
		arg2 = strchr(arg1, ' ');
		if (!arg2)
			return;
		*arg2++ = 0;

		create_session(arg1, atoi(arg2));
	} else if (!strncasecmp(buf, "listen ", strlen("listen "))) {
		printf("ha! not yet.\n");
	} else if (!strncasecmp(buf, "close ", strlen("close "))) {
		list *l = sessions;
		int id = atoi(buf + strlen("close "));

		while (l) {
			struct tcp_session *sess = l->data;

			if (sess->id == id) {
				/* XXX we should check the state of the session
				 * first. this might be the wrong thing to do
				 * at this point. */
				send_tcp(sess, TH_FIN | TH_ACK);
				sess->state = FIN_WAIT_1;
				printf("FIN_WAIT_1\n");
				break;
			}

			l = l->next;
		}
		if (!l)
			printf("couldn't find %d\n", id);
	} else if (!strcasecmp(buf, "quit")) {
		/* XXX should send RST to all the sessions */
		exit(0);
	}
}

/* this function needs to get rewritten. desperately. */
static void *
control_main(void *arg)
{
	fd_set set;

	while (1) {
		FD_ZERO(&set);
		FD_SET(0, &set);
		FD_SET(sp[1], &set);

		/* XXX for now we don't do timers */
		if (select(sp[1] + 1, &set, NULL, NULL, NULL) < 0)
			exit(1);

		if (FD_ISSET(0, &set))
			process_input();

		if (FD_ISSET(sp[1], &set))
			process_packet();
	}
}

/* TODO: convince the host we're running on that it can safely ignore us */
static int
arp_reply(unsigned char hw[6], uint32_t ip)
{
	/* we probably could make this handle static so that we don't have to
	 * rebuild it too many times, but hopefully we should only need to
	 * build it once. */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_LINK, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 0;
	}

	if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REPLY,
			     src_hw, (u_char *)&src_ip, hw, (u_char *)&ip,
			     NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 0;
	}
	if (libnet_autobuild_ethernet(hw, ETHERTYPE_ARP, lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 0;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s\n", libnet_geterror(lnh));
		return 0;
	}

	libnet_destroy(lnh);
	return 1;
}

/* 'main' is a misnomer since it's not really a "main" function, it's a
 * callback. pcap sucks. anyway, it can handle arp by itself but anything in ip
 * needs to be passed to the control thread. */
static void
packet_main(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	/* XXX at some point we should be checking packet size so that e.g. the
	 * IP header really is at least 5 bytes. some of these checks should be
	 * here and some of them should be in process_packet and some should be
	 * in state_machine. */
	struct enet *enet = (struct enet *)pkt;
	if (ntohs(enet->type) == ETHERTYPE_IP) {
		struct ip_pkt *ip = (struct ip_pkt *)pkt;

		/* if it's not for us, we ignore it */
		if (ip->dst_ip != src_ip)
			return;

		write(sp[0], hdr, sizeof (struct pcap_pkthdr));
		write(sp[0], pkt, hdr->len);
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
		    (arp->dst_ip == src_ip) &&			/* for us */
		    memcmp(src_hw, arp->src_hw, 6))		/* not host */
			arp_reply(arp->src_hw, arp->src_ip);
	}
}

int
main(int argc, char **argv)
{
	pthread_t thread;

	char errbuf[LIBNET_ERRBUF_SIZE];
	pcap_t *lph;

	libnet_t *lnh;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	libnet_seed_prand(lnh);

	/* setup of global variables */
	memcpy(src_hw, libnet_get_hwaddr(lnh), 6);
	/* you need to pick this IP address based on three characteristics:
	 *
	 * 1. it cannot be the same address as the host's address
	 * 2. the address cannot already be in use by another computer (i.e.
	 *    you can't pretend to be some other computer, only an imaginary
	 *    computer)
	 * 3. it needs to be on the same routing network (I don't know how else
	 *    to say that) as the host. in most cases if the address is part of
	 *    the same subnet as the host you should be fine.
	 *
	 * of course, if you remove the ip address from the host and just use
	 * that address, then you shouldn't have to worry about any of that.
	 * but then you'll have to modify this client to handle all the routing
	 * details itself, and that's not fun. */
	src_ip = libnet_name2addr4(lnh, argc > 1 ? argv[1] : "172.20.102.9",
				   LIBNET_RESOLVE);
	libnet_destroy(lnh);

	if (!(lph = init_pcap()))
		return 1;

	/* there are five (well, actually three) options if you want to have a
	 * main loop other than pcap_loop:
	 *
	 * 1. parse packets from pcap_fileno yourself
	 * 2. rewrite pcap
	 * 3. call pcap_dispatch occasionally
	 * 4. fork
	 * 5. use threads
	 *
	 * 1 and 2 are more or less the same thing, and if using pcap is this
	 * bad, I don't want to think about what hacking pcap is like. 3 isn't
	 * really an option because it increases the load and you may miss
	 * certain things. there's really no difference between 4 and 5 either,
	 * as long as the pcap thread (process) isn't processing the packets.
	 * and since I've never really used threads for anything real before,
	 * we'll use threads.
	 *
	 * I'm evil.
	 *
	 * even though this is a threaded program, I don't really consider it
	 * "using threads" since the threads don't share variables, so there's
	 * no need for locking. */
	socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	pthread_create(&thread, NULL, control_main, NULL);

	pcap_loop(lph, -1, packet_main, NULL);

	/* I don't think we'll ever get here, unless things go very wrong */
	return 1;
}
