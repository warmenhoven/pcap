/*
 * right now in the TCP bake off I get 17 points:
 *
 * Featherweight Division:
 *   1 points for talking to myself
 *   1 points for gracefully ending the conversation
 *   2 points for repeating the above without reinitializing
 *
 * Middleweight Division:
 *   2 points for talking to someone else
 *   2 point for gracefully ending the conversaion
 *   4 points for repeating the above without reinitializing
 *
 * Heavyweight Division:
 *   5 points for being able to talk to more than one other TCP at the same time
 *     (since I can't actually "talk" to them yet, I'm only giving myself 5
 *     points, for being able to be connected to more than one at a time. once
 *     I'm able to exchange data then I'll get 1 more point in the Lightweight
 *     Division, 2 more points in the Middleweight Division, and the remainder
 *     of the 5 points here)
 */

#include <ansidecl.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

const char *state_names[] = {
	"UNKNOWN",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"TCP_CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
};

typedef struct _list {
	struct _list *next;
	void *data;
} list;
typedef int (*cmpfnc)(const void *, const void *);

/* define all the list functions */
static list *
list_new(void *data)
{
	list *l = malloc(sizeof(list));
	l->next = NULL;
	l->data = data;
	return l;
}

static list *
list_prepend(list *l, void *data)
{
	list *s = list_new(data);
	s->next = l;
	return s;
}

static list *
list_remove(list *l, void *data)
{
	list *s = l, *p = NULL;

	if (!s) return NULL;
	if (s->data == data) {
		p = s->next;
		free(s);
		return p;
	}
	while (s->next) {
		p = s;
		s = s->next;
		if (s->data == data) {
			p->next = s->next;
			free(s);
			return l;
		}
	}
	return l;
}

static list *
list_insert_sorted(list *l, void *data, cmpfnc f)
{
	list *s = l;

	if (!s)
		return list_prepend(l, data);
	if (f(s->data, data) >= 0)
		return list_prepend(l, data);

	while (s->next) {
		if (f(s->next->data, data) < 0) {
			s = s->next;
			continue;
		}
		s->next = list_prepend(s->next, data);
		return l;
	}

	s->next = list_new(data);
	return l;
}

typedef struct tcp_session {
	uint32_t id;	/* heh. a more appropriate name might be 'fd'. */

	uint32_t state;

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
	uint16_t dst_prt;
	uint32_t dst_ip;

	/* these are stored in host byte order mostly by default */
	uint32_t seqno;
	uint32_t ackno;

	/* there's really a bunch of other stuff that I should be paying
	 * attention to */
} TCB;

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
	/* everything from here down is IPv4 but that's all we need */
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

/* these are our global variables */
static unsigned char src_hw[6];
static uint32_t src_ip;
static list *sessions = NULL;
static list *open_connections = NULL;
static list *listeners = NULL;
static int sp[2];

static pcap_t *
init_pcap(void)
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

	filter_line = malloc(4 + 5 + (4*4));
	/* libnet_name2addr4 puts src_ip in network byte order, so we don't
	 * need to do any of that here */
	sa.s_addr = src_ip;
	/* this filter line should give us everything we need (including arp
	 * requests) */
	sprintf(filter_line, "dst host %s", inet_ntoa(sa));
	pcap_compile(lph, &filter, filter_line, 0, net);
	free(filter_line);

	if (pcap_setfilter(lph, &filter) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}
	return lph;
}

static int
send_tcp(TCB *sess, int flags)
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

/* yeah, I probably should figure out some way of reusing send_tcp instead of
 * just copying it. but eh. it probably isn't an issue. at least not often. */
static int
send_rst(uint32_t dst_ip, uint16_t dst_prt, uint32_t src_prt,
		 uint32_t seqno, uint32_t ackno, int state, int control)
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

	fprintf(stderr, "RST'ing (State = %s, Control = %02x)\n",
			state_names[state], control);
	libnet_destroy(lnh);
	return 1;
}

static TCB *
find_session(uint32_t dst_ip, uint32_t dst_prt, uint32_t src_prt)
{
	list *l = open_connections;

	while (l && dst_ip && dst_prt) {
		TCB *sess = l->data;
		l = l->next;

		if (sess->src_prt != src_prt)
			continue;

		if (sess->dst_ip == dst_ip && sess->dst_prt == dst_prt)
			return sess;
	}

	l = listeners;

	/* TODO: we should be able to support listening for specific
	 * hosts (or specific ports) */
	while (l) {
		TCB *sess = l->data;
		l = l->next;

		if (sess->src_prt == src_prt)
			return sess;
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

static int
get_next_sess_id(void)
{
	list *l = sessions;
	unsigned int i = 0;
	while (l) {
		TCB *s = l->data;
		l = l->next;
		if (s->id != i)
			return i;
		i++;
	}
	return i;
}

static int
sess_cmp(const void *x, const void *y)
{
	const TCB *a = x, *b = y;
	return a->id - b->id;
}

static TCB *
session_setup(void)
{
	TCB *sess = calloc(1, sizeof (TCB));
	char errbuf[LIBNET_ERRBUF_SIZE];

	/* sess->state = TCP_CLOSE; */

	if (!(sess->lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		free(sess);
		return NULL;
	}

	/* XXX this isn't actually supposed to be random; it's supposed to be
	 * somewhat internal-clock-based so that if we happen to be using the same
	 * src_prt/dst_ip/dst_prt tuple that was used in a previous session, the
	 * remote stack knows that it's for a new session. but I don't care. */
	/* I hear I shouldn't use this function for anything real. oh well. */
	sess->seqno = libnet_get_prand(LIBNET_PRu32);

	sess->id = get_next_sess_id();
	sessions = list_insert_sorted(sessions, sess, sess_cmp);
	printf("creating socket %d\n", sess->id);

	return sess;
}

/* maybe eventually there will be a third argument, so you can specify the port
 * to connect from */
static TCB *
create_session(char *host, uint16_t port)
{
	TCB *sess;

	if (host) {
		if ((sess = session_setup()) == NULL)
			return NULL;

		/* XXX we should have some check to see if sess->dst_ip ==
		 * src_ip, so that we can detect when we're trying to send
		 * packets to ourselves, because we won't be able to put those
		 * packets out over the wire */
		sess->dst_ip = libnet_name2addr4(sess->lnh, host,
						 LIBNET_RESOLVE);
		if (sess->dst_ip == 0xffffffff) {
			fprintf(stderr, "%s\n", libnet_geterror(sess->lnh));
			free(sess);
			return NULL;
		}
		sess->dst_prt = port;
		sess->src_prt = get_port(sess->dst_ip, sess->dst_prt);

		/* send the SYN, and we're off! */
		send_tcp(sess, TH_SYN);
		sess->seqno++;
		sess->state = TCP_SYN_SENT;
		printf("%u: %s (port %u)\n", sess->id, state_names[sess->state],
			   sess->src_prt);
		open_connections = list_prepend(open_connections, sess);
	} else {
		/* listening socket */
		if ((sess = find_session(0, 0, port)) != NULL) {
			fprintf(stderr, "id %d already listening on port %d\n",
					sess->id, port);
			return sess;
		}
		if ((sess = session_setup()) == NULL)
			return NULL;

		sess->dst_ip = 0;
		sess->dst_prt = 0;
		sess->src_prt = port;

		sess->state = TCP_LISTEN;
		printf("%u: %s\n", sess->id, state_names[sess->state]);
		listeners = list_prepend(listeners, sess);
	}

	return sess;
}

static TCB *
accept_session(TCB *listener, struct tcp_pkt *pkt)
{
	TCB *sess = session_setup();

	if (!sess)
		return NULL;

	sess->dst_ip = pkt->ip.src_ip;
	sess->dst_prt = ntohs(pkt->src_prt);
	sess->src_prt = listener->src_prt;

	sess->ackno = ntohl(pkt->seqno) + 1;

	send_tcp(sess, TH_SYN | TH_ACK);
	sess->seqno++;
	sess->state = TCP_SYN_RECV;
	printf("%u: %s\n", sess->id, state_names[sess->state]);

	open_connections = list_prepend(open_connections, sess);

	return sess;
}

/* after this function, sess is no longer valid (obviously) */
static void
remove_session(TCB *sess)
{
	if (sess->state == TCP_LISTEN) {
		listeners = list_remove(listeners, sess);
	} else {
		open_connections = list_remove(open_connections, sess);
	}
	sessions = list_remove(sessions, sess);
	libnet_destroy(sess->lnh);
	free(sess);
}

static void
state_machine(TCB *sess, struct tcp_pkt *pkt)
{
	/* here we can assume that the pkt is part of the session and for us */

	/* XXX none of these things check seqno/ackno. they should. */

	if ((sess->state != TCP_LISTEN) && (pkt->control & TH_RST)) {
		fprintf(stderr, "Remote host sent RST\n");
		remove_session(sess);
		return;
	}

	/* XXX none of these things check to see that only the flags they're
	 * expecting are set. if we're in FIN_WAIT1 and we get SYN/FIN/ACK
	 * then we'll just remove the session instead of sending RST. this
	 * probably isn't a big problem. */
	switch (sess->state) {
	case TCP_LISTEN:
		if (pkt->control & TH_SYN) {
			accept_session(sess, pkt);
		} else {
			send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
					 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
					 ntohl(pkt->seqno) + 1,
					 sess->state, pkt->control);
			/* don't remove_sess because we're still listening */
		}
		break;
	case TCP_SYN_RECV:
		if (pkt->control & TH_ACK) {
			if (ntohl(pkt->ackno) != sess->seqno) {
				fprintf(stderr, "Invalid ackno\n");
				send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
						 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
						 ntohl(pkt->seqno) + 1,
						 sess->state, pkt->control);
				remove_session(sess);
				return;
			}
			sess->ackno = ntohl(pkt->seqno) + 1;
			sess->state = TCP_ESTABLISHED;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
		} else {
			send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
					 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
					 ntohl(pkt->seqno) + 1,
					 sess->state, pkt->control);
			remove_session(sess);
		}
		break;
	case TCP_SYN_SENT:
		if ((pkt->control & TH_SYN) && (pkt->control & TH_ACK)) {
			if (ntohl(pkt->ackno) != sess->seqno) {
				fprintf(stderr, "Invalid ackno\n");
				send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
						 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
						 ntohl(pkt->seqno) + 1,
						 sess->state, pkt->control);
				remove_session(sess);
				return;
			}
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			sess->state = TCP_ESTABLISHED;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
		} else if (pkt->control & TH_SYN) {
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			sess->state = TCP_SYN_RECV;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
		} else {
			send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
					 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
					 ntohl(pkt->seqno) + 1,
					 sess->state, pkt->control);
			remove_session(sess);
		}
		break;
	case TCP_ESTABLISHED:
		if (pkt->control & TH_FIN) {
			/* the other side wants to shut down the connection */
			sess->ackno = ntohl(pkt->seqno) + 1;
			/* we send both the FIN and the ACK together, and move
			 * right through CLOSE_WAIT to LAST_ACK */
			send_tcp(sess, TH_FIN | TH_ACK);
			sess->seqno++;
			sess->state = TCP_LAST_ACK;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
		}
		/* XXX there are more cases of things to do here */
		{
			unsigned int len = ntohs(pkt->ip.len) -
				(pkt->ip.ihl << 2) -
				(pkt->offset << 2);
			unsigned char *ptr = ((unsigned char *)&pkt->src_prt) +
				(pkt->offset << 2);
			unsigned int i;

			printf("read %u: %u bytes\n", sess->id, len);

			for (i = 0; i < len; i++) {
				printf("%02x ", ptr[i]);
				if (i && (i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");
			for (i = 0; i < len; i++) {
				printf("%c ", ptr[i]);
				if (i && (i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");
			sess->ackno += len;
			send_tcp(sess, TH_ACK);
		}
		break;
	case TCP_FIN_WAIT1:
		/* we sent the initial FIN */
		if ((pkt->control & TH_ACK) && (pkt->control & TH_FIN)) {
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			sess->state = TCP_TIME_WAIT;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
			/* we should move to TIME_WAIT in case if the other
			 * side doesn't receive our ACK, but we just assume
			 * everything went well */
			remove_session(sess);
			break;
		}

		if (pkt->control & TH_FIN) {
			/* ACK the FIN, wait for our ACK */
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			sess->state = TCP_CLOSING;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
			/* just like TIME_WAIT, we should move to CLOSING, but
			 * we just assume everything went well */
			remove_session(sess);
			break;
		}

		if (pkt->control & TH_ACK) {
			/* we've got the ACK, now we're waiting for the FIN */
			sess->state = TCP_FIN_WAIT2;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
			break;
		}

		/* we didn't get ACK or FIN, so we RST */
		send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
				 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
				 ntohl(pkt->seqno) + 1, sess->state, pkt->control);
		remove_session(sess);
		break;
	case TCP_FIN_WAIT2:
		if (pkt->control & TH_FIN) {
			/* we've got the FIN, send the ACK and we're done */
			sess->ackno = ntohl(pkt->seqno) + 1;
			send_tcp(sess, TH_ACK);
			sess->state = TCP_TIME_WAIT;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
			/* just like above, we should move to TIME_WAIT, but
			 * we just assume everything went well */
			remove_session(sess);
			break;
		}

		/* we're waiting for FIN but didn't get it, so RST */
		send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
				 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
				 ntohl(pkt->seqno) + 1, sess->state, pkt->control);
		remove_session(sess);
		break;
	case TCP_CLOSING:
		/* we never get here because we just assume everything went
		 * fine, and remove the sess before waiting for our ACK */
		break;
	case TCP_TIME_WAIT:
		/* we never get here because we just assume everything went
		 * fine, and remove the sess before waiting for our ACK */
		break;
	case TCP_CLOSE_WAIT:
		/* we never get here because we send the FIN with the ACK */
		break;
	case TCP_LAST_ACK:
		if (pkt->control & TH_ACK) {
			/* now we can remove the session */
			sess->state = TCP_CLOSE;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
			remove_session(sess);
		} else {
			send_rst(pkt->ip.src_ip, ntohs(pkt->src_prt),
					 ntohs(pkt->dst_prt), ntohl(pkt->ackno),
					 ntohl(pkt->seqno) + 1,
					 sess->state, pkt->control);
			remove_session(sess);
		}
		break;
	}
}

static void
process_packet(void)
{
	struct pcap_pkthdr hdr;
	u_char *pkt;

	struct ip_pkt *ip;
	struct tcp_pkt *tcp;
	TCB *sess;

	uint16_t csum;
	int sum, len;

	/* XXX this section needs to be fixed, it assumes too much */
	if (read(sp[1], &hdr, sizeof (hdr)) != sizeof (hdr))
		return;
	pkt = malloc(hdr.len + (hdr.len % 1));
	if ((len = read(sp[1], pkt, hdr.len)) < 0) {
		free(pkt);
		return;
	}
	if ((unsigned int)len != hdr.len) {
		free(pkt);
		return;
	}
	if (hdr.len % 1)
		pkt[hdr.len] = 0;

#if 0
	printf("\nPACKET:\n");
	for (i = 0; i < hdr.len; i++) {
		printf("%02x ", pkt[i]);
		if (i && (i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n\n");
#endif

	ip = (struct ip_pkt *)pkt;

	/* XXX there are more IP options that we need to deal with. until then
	 * this program isn't a stack, it's a hack. */
	csum = ip->hdr_csum;
	ip->hdr_csum = 0;
	sum = libnet_in_cksum((u_int16_t *)ip + sizeof (struct enet) / 2,
						  ip->ihl << 2);
	ip->hdr_csum = LIBNET_CKSUM_CARRY(sum);
	if (csum != ip->hdr_csum) {
		fprintf(stderr, "checksum mismatch in IP header!\n");
		free(pkt);
		return;
	}

	/* we only deal with TCP, because the host screws up ICMP for us */
	if (ip->protocol != IPPROTO_TCP) {
		free(pkt);
		return;
	}

	tcp = (struct tcp_pkt *)pkt;
	csum = tcp->csum;
	tcp->csum = 0;
	sum = libnet_in_cksum((u_int16_t *)&ip->src_ip, 8);
	len = ntohs(ip->len) - (ip->ihl << 2);
	sum += ntohs(IPPROTO_TCP + len);
	sum += libnet_in_cksum((u_int16_t *)&tcp->src_prt, len);
	tcp->csum = LIBNET_CKSUM_CARRY(sum);
	if (csum != tcp->csum) {
		fprintf(stderr, "checksum mismatch in TCP header!\n");
		free(pkt);
		return;
	}

	/* maybe we should move this check to state_machine. */
	if (!(sess = find_session(ip->src_ip, ntohs(tcp->src_prt),
							  ntohs(tcp->dst_prt)))) {
		send_rst(ip->src_ip, ntohs(tcp->src_prt),
				 ntohs(tcp->dst_prt), ntohl(tcp->ackno),
				 ntohl(tcp->seqno) + 1, TCP_CLOSE, tcp->control);
		free(pkt);
		return;
	}

	/* this is where the real work is */
	state_machine(sess, tcp);

	free(pkt);
}

static void
process_input(void)
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
		create_session(NULL, atoi(buf + strlen("listen ")));
	} else if (!strncasecmp(buf, "close ", strlen("close "))) {
		list *l = sessions;
		unsigned int id = atoi(buf + strlen("close "));

		while (l) {
			TCB *sess = l->data;

			if (sess->id > id) {
				l = NULL;
				break;
			}

			if (sess->id < id) {
				l = l->next;
				continue;
			}

			if (sess->state == TCP_LISTEN ||
				sess->state == TCP_SYN_SENT) {
				remove_session(sess);
			} else if (sess->state == TCP_ESTABLISHED ||
					   sess->state == TCP_SYN_RECV) {
				send_tcp(sess, TH_FIN | TH_ACK);
				sess->seqno++;
				sess->state = TCP_FIN_WAIT1;
				printf("%u: %s\n",
					   sess->id,
					   state_names[sess->state]);
			}
			break;
		}
		if (!l)
			printf("couldn't find %u\n", id);
	} else if (!strcasecmp(buf, "netstat")) {
		list *l = sessions;

		while (l) {
			TCB *sess = l->data;
			l = l->next;

			printf("id %d: port %d with %s:%d\n",
				   sess->id, sess->src_prt,
				   libnet_addr2name4(sess->dst_ip, LIBNET_DONT_RESOLVE),
				   sess->dst_prt);
		}
	} else if (!strcasecmp(buf, "quit")) {
		/* XXX should send RST to all the sessions */
		exit(0);
	}
}

/* this function needs to get rewritten. desperately. */
static void * ATTRIBUTE_NORETURN
control_main(void *arg ATTRIBUTE_UNUSED)
{
	fd_set set;

	while (1) {
		FD_ZERO(&set);
		FD_SET(0, &set);
		FD_SET(sp[1], &set);

		/* XXX for now we don't do timers; therefore no retransmission, etc. */
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
 * callback. pcap sucks. anyway, it can handle some things by itself but
 * anything that needs an understanding of state needs to be passed to the
 * control thread. */
static void
packet_main(u_char *user ATTRIBUTE_UNUSED,
			const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	/* XXX at some point we should be checking packet size so that e.g. the
	 * IP header really is at least 5 bytes. some of these checks should be
	 * here and some of them should be in process_packet and some should be
	 * in state_machine. (and some of them should be in the host and in
	 * pcap, so this might not be necessary.)*/
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

	if (argc < 2) {
		printf("Usage: %s <ip>\n", argv[0]);
		return 1;
	}

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
	src_ip = libnet_name2addr4(lnh, argv[1], LIBNET_RESOLVE);
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

/* vim:set ts=4 sw=4 noet ai tw=80: */
