/* valuable rfc's:
 *
 * 793, TCP
 * 1025, TCP bake off
 *
 * I'm sure there's more but those are all I knew off the top of my head
 *
 * right now in the TCP bake off I get 8 points:
 *
 * 2 points for talking to someone else
 * 2 point for gracefully ending the conversaion
 * 4 points for repeating the above without reinitializing
 *
 */

#include "list.h"

#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
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
	pthread_mutex_t lock;

	uint32_t id;

	enum tcp_state state;

	libnet_t *lnh;
	libnet_ptag_t tcp_id;
	libnet_ptag_t ip_id;

	uint16_t src_prt;

	uint32_t dst_ip;
	uint16_t dst_prt;

	uint32_t seqno;
	uint32_t ackno;

	/* there's really a bunch of other stuff that I should be paying
	 * attention to */
};

/* these are global */
/* we only emulate one ip address at a time */
unsigned char src_hw[6];
uint32_t src_ip;
/* snslck should be held for as short as possible because every incoming tcp
 * packet needs to be checked against the sessions list. this really should be
 * a read-write lock. */
pthread_mutex_t snslck;
list *sessions;
uint32_t next_id = 0;

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

	lph = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
	if (!lph) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}

	filter_line = malloc(4 + 3 + 5 + (4*4));
	sa.s_addr = src_ip;
	/* we need arp because we're faking a client. otherwise we only need
	 * the packets for the host we're faking. */
	sprintf(filter_line, "arp or host %s", inet_ntoa(sa));
	printf("filter line: %s\n", filter_line);
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

/* XXX convince the host we're running on that it can safely ignore us */
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

static struct tcp_session *
find_session(uint32_t dst_ip, uint32_t dst_prt, uint32_t src_prt, int lock)
{
	list *l;
	pthread_mutex_lock(&snslck);

	l = sessions;
	while (l) {
		struct tcp_session *sess = l->data;
		pthread_mutex_lock(&sess->lock);
		if (sess->dst_ip == dst_ip &&
		    sess->dst_prt == dst_prt &&
		    sess->src_prt == src_prt) {
			if (!lock)
				pthread_mutex_unlock(&sess->lock);
			pthread_mutex_unlock(&snslck);
			return sess;
		}
		pthread_mutex_unlock(&sess->lock);
		l = l->next;
	}

	pthread_mutex_unlock(&snslck);
	return NULL;
}

/* there are probably several problems with this. */
static int
get_port(uint32_t dst_ip, uint16_t dst_prt)
{
	uint16_t src_prt;

	do {
		src_prt = libnet_get_prand(LIBNET_PRu16);
	} while (find_session(dst_ip, dst_prt, src_prt, 0));

	return src_prt;
}

static struct tcp_session *
create_session(char *host, uint16_t port)
{
	struct tcp_session *sess = calloc(1, sizeof (struct tcp_session));
	char errbuf[LIBNET_ERRBUF_SIZE];

	/* initial setup of the tcp session */
	pthread_mutex_init(&sess->lock, NULL);

	pthread_mutex_lock(&sess->lock);

	/* sess->state = CLOSED; */

	if (!(sess->lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		pthread_mutex_unlock(&sess->lock);
		free(sess);
		return NULL;
	}

	sess->dst_ip = libnet_name2addr4(sess->lnh, host,
					 LIBNET_RESOLVE);
	sess->dst_prt = port;
	sess->src_prt = get_port(sess->dst_ip, sess->dst_prt);

	/* I hear I shouldn't use this function for anything real. oh well. */
	sess->seqno = libnet_get_prand(LIBNET_PRu32);

	/* send the SYN, and we're off! */
	send_tcp(sess, TH_SYN);
	sess->seqno++;
	sess->state = SYN_SENT;
	printf("SYN_SENT\n");

	pthread_mutex_lock(&snslck);
	sessions = list_append(sessions, sess);
	sess->id = next_id;
	printf("created session %d using port %d\n", next_id++, sess->src_prt);
	pthread_mutex_unlock(&snslck);

	pthread_mutex_unlock(&sess->lock);

	return sess;
}

/* after this function, sess is no longer valid */
static void
remove_session(struct tcp_session *sess)
{
	pthread_mutex_lock(&snslck);
	sessions = list_remove(sessions, sess);
	pthread_mutex_unlock(&snslck);

	pthread_mutex_destroy(&sess->lock);
	libnet_destroy(sess->lnh);
	free(sess);
}

/* this may well become 'main' for a "session" thread, that waits on a
 * condition triggered by either the pcap thread or the timer thread, instead
 * of trying to get the pcap and timer threads to play well together with the
 * session */
static int
state_machine(struct tcp_session *sess, struct tcp_pkt *pkt)
{
	/* here we can assume that the pkt is part of the session, we're the
	 * receiver, and the session is locked. */

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

/* main cb function. this needs to get rewritten. desperately. */
static void
packet_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct enet *enet = (struct enet *)pkt;
	if (ntohs(enet->type) == ETHERTYPE_IP) {
		struct ip_pkt *ip = (struct ip_pkt *)pkt;
		struct tcp_pkt *tcp = (struct tcp_pkt *)pkt;
		struct tcp_session *sess;

		/* XXX we only deal with TCP; we should handle ICMP too */
		if (ip->protocol != IPPROTO_TCP)
			return;

		/* if it's not for us, we ignore it */
		if (ip->dst_ip != src_ip)
			return;

		if (!(sess = find_session(ip->src_ip, ntohs(tcp->src_prt),
					  ntohs(tcp->dst_prt), 1))) {
			send_rst(ip->src_ip, ntohs(tcp->src_prt),
				 ntohs(tcp->dst_prt),
				 ntohl(tcp->ackno), ntohl(tcp->seqno) + 1);
			return;
		}

		/* find_session locks sess for us, to avoid race conditions */

		/* this is where the real work is. we don't have to unlock it
		 * if there's a problem, it'll do that for us. */
		if (state_machine(sess, tcp))
			pthread_mutex_unlock(&sess->lock);
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

static void *
control_main(void *arg)
{
	while (1) {
		char buf[80];
		fgets(buf, sizeof(buf), stdin);
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		if (!strncasecmp(buf, "connect ", strlen("connect "))) {
			struct tcp_session *sess;
			char *arg1, *arg2;
			arg1 = buf + strlen("connect ");
			arg2 = strchr(arg1, ' ');
			if (!arg2)
				continue;
			*arg2++ = 0;

			sess = create_session(arg1, atoi(arg2));
		} else if (!strncasecmp(buf, "listen ", strlen("listen "))) {
			printf("ha! not yet.\n");
		} else if (!strncasecmp(buf, "close ", strlen("close "))) {
			list *l;
			int id = atoi(buf + strlen("close "));

			pthread_mutex_lock(&snslck);
			l = sessions;
			while (l) {
				struct tcp_session *sess = l->data;

				pthread_mutex_lock(&sess->lock);
				if (sess->id == id) {
					/* XXX we should check the state of the
					 * session first. this might be the
					 * wrong thing to do at this point. */
					printf("CLOSING %d\n", id);
					send_tcp(sess, TH_FIN | TH_ACK);
					sess->state = FIN_WAIT_1;
					pthread_mutex_unlock(&sess->lock);
					break;
				}
				pthread_mutex_unlock(&sess->lock);

				l = l->next;
			}
			if (!l)
				printf("couldn't find %d\n", id);
			pthread_mutex_unlock(&snslck);
		}
	}
}

static void *
timer_main(void *arg)
{
	/* XXX if this is going to be the timer thread, but the pcap thread is
	 * also sending packets on behalf of the session, then we need to put
	 * in a lot of information about the session into the struct so that
	 * the two threads can always understand exactly what the state of the
	 * session is. a better idea might be to also have a session thread,
	 * waiting on a condition, that either the pcap or the timer thread can
	 * then wake up. ("now there are two of them! this is getting out of
	 * hand.") */
	while (1) {
		/* XXX for now we don't do timers */
		sleep(0xffffffff);
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

	pthread_mutex_init(&snslck, NULL);

	if (!(lph = init_pcap()))
		return 1;

	/* there are three (well, four) options if you want to have a main loop
	 * other than pcap_loop:
	 *
	 * 1. call pcap_dispatch occasionally
	 * 2. parse packets from pcap_fileno yourself
	 * 3. use threads
	 * 4. rewrite pcap
	 *
	 * 2 and 4 are more or less the same thing, and if using pcap is this
	 * bad, I don't want to think about what hacking pcap is like. 1 isn't
	 * really an option because it increases the load and you'll miss
	 * certain things. so the only option left is 3.
	 *
	 * I'm evil. */
	pthread_create(&thread, NULL, timer_main, NULL);
	pthread_create(&thread, NULL, control_main, NULL);

	pcap_loop(lph, -1, packet_cb, NULL);

	/* I don't think we'll ever get here, unless things go very wrong */
	return 1;
}
