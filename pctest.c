/*
 * right now in the TCP bake off I get 30 points:
 *
 * Featherweight Division:
 *   1 point for talking to myself
 *   1 point for saying something to myself
 *   1 point for gracefully ending the conversation
 *   2 points for repeating the above without reinitializing
 *
 * Middleweight Division:
 *   2 points for talking to someone else
 *   2 points for saying something to someone else
 *   2 points for gracefully ending the conversaion
 *   4 points for repeating the above without reinitializing
 *
 * Heavyweight Division:
 *   10 points for being able to talk to more than one other TCP at the same time
 *
 * TODO:
 *   IP:
 *     - Parse IP options
 *     - Support IP fragments
 *     - Support precedence
 *     - Support loopback (talking to self without gateway)
 *
 *   TCP:
 *     - Parse TCP options
 *     - Handle data in inital SYN
 *     - Support URG data
 *     - Better initial seqno generation
 *     - Handle seqno wrap-around
 *     - Grow/shrink windows
 *     - Use timers and retransmission
 *     - Deal with lost received data
 */

#include <libnet.h>
#include <pcap.h>
#include <pthread.h>

/* LIST { */
typedef struct _list {
	struct _list *next;
	void *data;
} list;
typedef int (*cmpfnc)(const void *, const void *);

static list *
list_new(void *data)
{
	list *l = malloc(sizeof (list));
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
/* } */

/* TIMER { */
struct timer {
	struct timeval end;
	void (*func)(void *);
	void *arg;
};

static list *timers = NULL;

static int
timer_cmp(const void *x, const void *y)
{
	const struct timer *a = x, *b = y;
	return timercmp(&a->end, &b->end, -);
}

static struct timer *
timer_start(int ms, void (*func)(void *), void *arg)
{
	struct timer *timer;
	struct timeval tv;

	timer = malloc(sizeof (struct timer));
	if (!timer)
		return NULL;

	gettimeofday(&tv, NULL);

	timer->func = func;
	timer->arg = arg;
	timer->end.tv_sec = tv.tv_sec + (ms / 1000);
	timer->end.tv_usec = tv.tv_usec + ((ms % 1000) * 1000);

	timers = list_insert_sorted(timers, timer, timer_cmp);

	return timer;
}

static void
timer_cancel(struct timer *timer)
{
	timers = list_remove(timers, timer);
	free(timer);
}

static struct timeval *
timer_sleep_time(struct timeval *rtv)
{
	if (timers) {
		/* we keep the timers in order sorted by when they're going to
		 * expire (first to last), so taking the first on the list should
		 * always be the first to expire and so we can use it to figure out
		 * how long to tell select to sleep */
		struct timer *timer = timers->data;
		struct timeval tv;

		gettimeofday(&tv, NULL);

		timersub(&timer->end, &tv, rtv);
		if (rtv->tv_sec < 0)
			timerclear(rtv);

		return rtv;
	} else {
		return NULL;
	}
}

static void
timer_process_pending(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	/* timers are sorted by when they expire. the first on the list will always
	 * be the first that needs to get processed. after processing it, we remove
	 * it from the list. if we come across one that doesn't need processing, all
	 * subsequent ones won't need processing, so we can return. */
	while (timers) {
		struct timer *timer = timers->data;
		/* we get away with this because the timeval is the first element
		 * of the timer */
		if (timer_cmp(timer, &tv) <= 0) {
			if (timer->func)
				timer->func(timer->arg);
			timer_cancel(timer);
		} else {
			return;
		}
	}
}
/* } */

static const char *state_names[] = {
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
	uint32_t seqno; /* aka SND.NXT */
	uint32_t ackno; /* aka RCV.NXT */

	uint32_t unacked; /* aka SND.UNA */

	/* I didn't actually start using Linux to get away from windows; I started
	 * using it because I wanted to know about computing in general */
	uint16_t snd_win; /* aka SND.WND */
	uint16_t rcv_win; /* aka RCV.WND */

	/* there's really a bunch of other stuff that I should be paying
	 * attention to */
} TCB;

struct arp {
	struct libnet_ethernet_hdr enet;
	struct libnet_arp_hdr hdr __attribute__((__packed__));
	/* everything from here down is IPv4 but that's all we need */
	unsigned char src_hw[6] __attribute__((__packed__));
	uint32_t src_ip __attribute__((__packed__));
	unsigned char dst_hw[6] __attribute__((__packed__));
	uint32_t dst_ip __attribute__((__packed__));
};

struct ip_pkt {
	struct libnet_ipv4_hdr *hdr;
	u_char *options;
	u_char *data;
};

struct icmp_pkt {
	struct libnet_ipv4_hdr *ip;
	struct libnet_icmpv4_hdr *hdr;
	u_char *data;
};

struct tcp_pkt {
	struct libnet_ipv4_hdr *ip;
	u_char *ip_options;
	struct libnet_tcp_hdr *hdr;
	u_char *tcp_options;
	u_char *data;
	uint32_t data_len;
};

/* these are our global variables */
static unsigned char src_hw[6];
static uint32_t src_ip;
static list *sessions = NULL;
static list *open_connections = NULL;
static list *listeners = NULL;
static int sp[2];

static int
send_tcp(TCB *sess, int flags, u_char *data, uint32_t len)
{
	if ((sess->tcp_id =
		 libnet_build_tcp(sess->src_prt, sess->dst_prt, sess->seqno,
						  sess->ackno, flags, sess->rcv_win, 0, 0, LIBNET_TCP_H,
						  data, len, sess->lnh, sess->tcp_id)) == -1) {
		fprintf(stderr, "%s", libnet_geterror(sess->lnh));
		return 1;
	}
	if ((sess->ip_id =
		 libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 242, 0, 64,
						   IPPROTO_TCP, 0, src_ip, sess->dst_ip,
						   NULL, 0, sess->lnh, sess->ip_id)) == -1) {
		fprintf(stderr, "%s", libnet_geterror(sess->lnh));
		return 1;
	}

	if (libnet_write(sess->lnh) == -1) {
		fprintf(stderr, "%s", libnet_geterror(sess->lnh));
		return 1;
	}

	if (flags & TH_SYN)
		sess->seqno++;
	if (flags & TH_FIN)
		sess->seqno++;
	sess->seqno += len;

	return 0;
}

/* yeah, I probably should figure out some way of reusing send_tcp instead of
 * just copying it. but eh. it probably isn't an issue. at least not often. */
static int
send_rst(uint32_t dst_ip, uint16_t dst_prt, uint32_t src_prt,
		 uint32_t seqno, uint32_t ackno, int state, int control)
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lnh;
	u_int8_t cntrl = TH_RST;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 0;
	}

	if (!(control & TH_ACK))
		cntrl |= TH_ACK;

	if (libnet_build_tcp(src_prt, dst_prt, seqno, ackno, cntrl,
						 0, 0, 0, LIBNET_TCP_H, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return 0;
	}

	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0x10, 0, 0, 64,
						  IPPROTO_TCP, 0, src_ip, dst_ip, NULL, 0,
						  lnh, 0) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return 0;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return 0;
	}

	fprintf(stderr, "RST'ing (Port = %d, State = %s, Control = %02x)\n",
			src_prt, state_names[state], control);
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

	/* XXX at some point I'm going to have to consider what might happen if I
	 * want to do something like queuing the data until someone tells me they
	 * want to read it. at that point I may need to decrease this window */
	sess->rcv_win = 0xffff;

	sess->id = get_next_sess_id();
	sessions = list_insert_sorted(sessions, sess, sess_cmp);
	printf("creating socket %d\n", sess->id);

	return sess;
}

static TCB *
accept_session(TCB *listener, struct tcp_pkt *pkt)
{
	TCB *sess = session_setup();

	if (!sess)
		return NULL;

	sess->dst_ip = pkt->ip->ip_src.s_addr;
	sess->dst_prt = ntohs(pkt->hdr->th_sport);
	sess->src_prt = listener->src_prt;

	sess->ackno = ntohl(pkt->hdr->th_seq) + 1;

	/* XXX "any other control or text should be queued for processing later" */

	send_tcp(sess, TH_SYN | TH_ACK, NULL, 0);
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
tcp_process_listen(TCB *sess, struct tcp_pkt *pkt)
{
	if (pkt->hdr->th_flags & TH_RST) {
		/* we're in a listening state, just drop it */
	} else if (pkt->hdr->th_flags & TH_ACK) {
		send_rst(pkt->ip->ip_src.s_addr, ntohs(pkt->hdr->th_sport),
				 ntohs(pkt->hdr->th_dport), ntohl(pkt->hdr->th_ack),
				 ntohl(pkt->hdr->th_seq) + 1,
				 sess->state, pkt->hdr->th_flags);
	} else if (pkt->hdr->th_flags & TH_SYN) {
		accept_session(sess, pkt);
		/* XXX it is "perfectly legitimate" to have "connection synchronization
		 * using data-carrying segments" but we don't handle that here. */
	} else {
		/* And I quote:
		 *
		 * Any other control or text-bearing segment (not containing SYN)
		 * must have an ACK and thus would be discarded by the ACK
		 * processing.  An incoming RST segment could not be valid, since it
		 * could not have been sent in response to anything sent by this
		 * incarnation of the connection.  So you are unlikely to get here,
		 * but if you do, drop the segment, and return. */
	}
}

static void
tcp_process_syn_sent(TCB *sess, struct tcp_pkt *pkt)
{
	if (pkt->hdr->th_flags & TH_ACK) {
		if (ntohl(pkt->hdr->th_ack) != sess->seqno) {
			fprintf(stderr, "Invalid ackno on %d\n", sess->id);
			if (!(pkt->hdr->th_flags & TH_RST)) {
				send_rst(pkt->ip->ip_src.s_addr, ntohs(pkt->hdr->th_sport),
						 ntohs(pkt->hdr->th_dport), ntohl(pkt->hdr->th_ack),
						 ntohl(pkt->hdr->th_seq) + 1,
						 sess->state, pkt->hdr->th_flags);
			} else {
				remove_session(sess);
			}
			return;
		} else {
			sess->unacked = ntohl(pkt->hdr->th_ack);
		}
	}

	if (pkt->hdr->th_flags & TH_RST) {
		fprintf(stderr, "Remote host sent RST, closing %d\n", sess->id);
		remove_session(sess);
		return;
	}

	/* any other packet without SYN set we should just drop */
	if (!(pkt->hdr->th_flags & TH_SYN))
		return;

	sess->ackno = ntohl(pkt->hdr->th_seq) + 1;
	if (sess->unacked == sess->seqno) {
		sess->state = TCP_ESTABLISHED;
		send_tcp(sess, TH_ACK, NULL, 0);
	} else {
		sess->state = TCP_SYN_RECV;
		/* we're resending our initial syn, so we have to decrement the
		 * seqno to get at our initial seqno for the syn */
		sess->seqno--;
		send_tcp(sess, TH_SYN | TH_ACK, NULL, 0);
	}
	printf("%u: %s\n", sess->id, state_names[sess->state]);
}

static int
tcp_check_seqno(TCB *sess, struct tcp_pkt *pkt)
{
	unsigned int len = ntohs(pkt->ip->ip_len) -
		(pkt->ip->ip_hl << 2) - (pkt->hdr->th_off << 2);
	uint32_t rcvnxt = sess->ackno, segseq = ntohl(pkt->hdr->th_seq);

	/* XXX we don't deal correctly with seqno wrap-around */

	if (len == 0) {
		if ((rcvnxt <= segseq) &&
			/* if sess->rcv_win is 0 then the check is if
			 * pkt->hdr->th_seq <= sess->ackno, which is acceptable,
			 * since the above check makes it the same check
			 * as checking if sess->ackno == pkt->hdr->th_seq */
			(segseq <= rcvnxt + sess->rcv_win)) {
			return 0;
		}
	} else if (sess->rcv_win != 0) {
		/* if there's data and our window is 0 then it's unacceptable */
		if (((rcvnxt <= segseq) && (segseq < rcvnxt + sess->rcv_win)) ||
			((rcvnxt <= segseq + len - 1) &&
			 (segseq + len - 1 < rcvnxt + sess->rcv_win))) {
			return 0;
		}
	}
	return 1;
}

static int
tcp_process_syn_recv(TCB *sess, struct tcp_pkt *pkt)
{
	if (sess->unacked > ntohl(pkt->hdr->th_ack) ||
		ntohl(pkt->hdr->th_ack) > sess->seqno) {
		fprintf(stderr, "Invalid ackno on %d\n", sess->id);
		send_rst(pkt->ip->ip_src.s_addr, ntohs(pkt->hdr->th_sport),
				 ntohs(pkt->hdr->th_dport), ntohl(pkt->hdr->th_ack),
				 ntohl(pkt->hdr->th_seq) + 1, sess->state, pkt->hdr->th_flags);
		remove_session(sess);
		return 1;
	}

	sess->state = TCP_ESTABLISHED;
	printf("%u: %s\n", sess->id, state_names[sess->state]);
	/* and continue procesing */
	return 0;
}

static void
tcp_process_last_ack(TCB *sess, struct tcp_pkt *pkt)
{
	if (ntohl(pkt->hdr->th_ack) == sess->seqno) {
		/* now we can remove the session */
		sess->state = TCP_CLOSE;
		printf("%u: %s\n", sess->id, state_names[sess->state]);
		remove_session(sess);
	} else if (ntohl(pkt->hdr->th_ack) > sess->seqno) {
		/* they're acking more than we've sent? anyway, resend FIN (which means
		 * decrement seqno before sending since it's sort of a retransmit) */
		sess->seqno--;
		send_tcp(sess, TH_FIN | TH_ACK, NULL, 0);
	}
}

static int
tcp_check_ackno(TCB *sess, struct tcp_pkt *pkt)
{
	uint32_t snduna = sess->unacked,
			 segack = ntohl(pkt->hdr->th_ack),
			 sndnxt = sess->seqno;

	if ((snduna <= segack) && (segack <= sndnxt)) {
		sess->unacked = segack;
		/* XXX "the send window should be updated" */
	} else if (segack < snduna) {
		/* the ACK is a duplicate and can be ignored */
		fprintf(stderr, "duplicate ack on %d\n", sess->id);
		return 1;
	} else {
		/* the ACK acks something not yet sent */
		fprintf(stderr, "ack for something not sent on %d\n", sess->id);
		send_tcp(sess, TH_ACK, NULL, 0);
		return 1;
	}

	if (snduna == sndnxt) {
		if (sess->state == TCP_FIN_WAIT1) {
			/* the FIN has been acked, we can move to FIN-WAIT-2 */
			sess->state = TCP_FIN_WAIT2;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
		} else if (sess->state == TCP_CLOSING) {
			/* the FIN has been acked, we can move to TIME-WAIT. but we don't
			 * move to TIME-WAIT, we simply delete the TCB and go straight to
			 * CLOSED without the 2 MSL delay */
			sess->state = TCP_TIME_WAIT;
			printf("%u: %s\n", sess->id, state_names[sess->state]);
			remove_session(sess);
			return 1;
		}
	}

	return 0;
}

static void
tcp_handle_data(TCB *sess, struct tcp_pkt *pkt)
{
	unsigned int i;

	if (pkt->data_len == 0)
		return;

	printf("read %u: %u bytes\n", sess->id, pkt->data_len);

	for (i = 0; i < pkt->data_len; i++) {
		printf("%02x ", pkt->data[i]);
		if (i && (i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
	for (i = 0; i < pkt->data_len; i++) {
		if (isprint(pkt->data[i]))
			printf(" %c ", pkt->data[i]);
		else
			printf("   ");
		if (i && (i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");

	/* XXX this is wrong */
	sess->ackno += pkt->data_len;
	send_tcp(sess, TH_ACK, NULL, 0);
}

static void
tcp_handle_fin(TCB *sess, struct tcp_pkt *pkt)
{
	sess->ackno++;

	if ((sess->state == TCP_SYN_RECV) || (sess->state == TCP_ESTABLISHED)) {
		send_tcp(sess, TH_FIN | TH_ACK, NULL, 0);
		/* we send both the FIN and the ACK together, and move
		 * right through CLOSE_WAIT to LAST_ACK */
		sess->state = TCP_LAST_ACK;
		printf("%u: %s\n", sess->id, state_names[sess->state]);
	} else if (sess->state == TCP_FIN_WAIT1) {
		/* ACK the FIN, wait for our ACK */
		send_tcp(sess, TH_ACK, NULL, 0);
		sess->state = TCP_CLOSING;
		printf("%u: %s\n", sess->id, state_names[sess->state]);
	} else if (sess->state == TCP_FIN_WAIT2) {
		/* we've got the FIN, send the ACK and we're done */
		/* XXX if there's still data missing then we don't want to set ackno to
		 * pkt->hdr->th_seq + 1; we want to receive that data still */
		sess->ackno = ntohl(pkt->hdr->th_seq) + 1;
		send_tcp(sess, TH_ACK, NULL, 0);
		sess->state = TCP_TIME_WAIT;
		printf("%u: %s\n", sess->id, state_names[sess->state]);
		/* just like above, we should move to TIME_WAIT, but
		 * we just assume everything went well */
		remove_session(sess);
	} else {
		/* anyone else just stays in their state. TIME-WAIT, if it were
		 * possible for us, would restart the 2 MSL time-wait timeout. */
	}
}

static void
tcp_state_machine(TCB *sess, struct tcp_pkt *pkt)
{
	/* here we can assume that the pkt is part of the session and for us */

	/* XXX none of these things check security, precedence, or URG */

	if (sess->state == TCP_LISTEN) {
		tcp_process_listen(sess, pkt);
		return;
	}

	if (sess->state == TCP_SYN_SENT) {
		tcp_process_syn_sent(sess, pkt);
		/* it is "perfectly legitimate" to have "connection synchronization
		 * using data-carrying segments" but we don't handle that here. */
		return;
	}

	/* at this point the state is not CLOSED, LISTEN, or SYN_SENT. also we can't
	 * be in the CLOSE_WAIT state because we send the FIN with the ACK. also we
	 * won't be in the TIME_WAIT state because we assume the other side received
	 * our last ACK. even if it didn't, we'll be in LISTEN or CLOSED, and it
	 * will get a RST, which is probably not what's expected, but should work
	 * just as well. */

	if (pkt->hdr->th_flags & TH_RST) {
		fprintf(stderr, "Remote host sent RST, closing %d\n", sess->id);
		remove_session(sess);
		return;
	}

	if (tcp_check_seqno(sess, pkt)) {
		/* XXX should we be updating sess->unacked from hdr->th_ack here? */
		fprintf(stderr, "unacceptable segment size on %d\n", sess->id);
		send_tcp(sess, TH_ACK, NULL, 0);
		return;
	}

	if (pkt->hdr->th_flags & TH_SYN) {
		fprintf(stderr, "SYN on %d\n", sess->id);
		send_rst(pkt->ip->ip_src.s_addr, ntohs(pkt->hdr->th_sport),
				 ntohs(pkt->hdr->th_dport), ntohl(pkt->hdr->th_ack),
				 ntohl(pkt->hdr->th_seq) + 1, sess->state, pkt->hdr->th_flags);
		remove_session(sess);
		return;
	}

	if (!(pkt->hdr->th_flags & TH_ACK)) {
		/* "if the ACK bit is off drop the segment and return" */
		return;
	}

	if (sess->state == TCP_SYN_RECV) {
		if (tcp_process_syn_recv(sess, pkt))
			return;
	}

	if (sess->state == TCP_LAST_ACK) {
		tcp_process_last_ack(sess, pkt);
		return;
	}

	/* at this point we're either ESTABLISHED, FIN_WAIT (1 or 2), or CLOSING.
	 * all of these "Do the same processing as for the ESTABLISHED state" before
	 * doing their own thing */
	if (tcp_check_ackno(sess, pkt))
		return;

	tcp_handle_data(sess, pkt);

	if (pkt->hdr->th_flags & TH_FIN)
		tcp_handle_fin(sess, pkt);
}

static void
process_tcp_packet(struct ip_pkt *ip)
{
	struct tcp_pkt tcp;
	TCB *sess;

	uint16_t csum;
	int sum, len;

	tcp.ip = ip->hdr;
	tcp.ip_options = ip->options;
	tcp.hdr = (struct libnet_tcp_hdr *)ip->data;

	csum = tcp.hdr->th_sum;
	tcp.hdr->th_sum = 0;
	sum = libnet_in_cksum((u_int16_t *)&ip->hdr->ip_src, 8);
	len = ntohs(ip->hdr->ip_len) - (ip->hdr->ip_hl << 2);
	sum += ntohs(IPPROTO_TCP + len);
	sum += libnet_in_cksum((u_int16_t *)&tcp.hdr->th_sport, len);
	tcp.hdr->th_sum = LIBNET_CKSUM_CARRY(sum);
	if (csum != tcp.hdr->th_sum) {
		fprintf(stderr, "checksum mismatch in TCP header (src %s)!\n",
				libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
		return;
	}

	if ((unsigned int)(tcp.hdr->th_off << 2) < sizeof (struct libnet_tcp_hdr)) {
		fprintf(stderr, "invalid TCP header (src %s)!\n",
				libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
		return;
	}

	if (!(sess = find_session(ip->hdr->ip_src.s_addr, ntohs(tcp.hdr->th_sport),
							  ntohs(tcp.hdr->th_dport)))) {
		if (!(tcp.hdr->th_flags & TH_RST)) {
			/* if they're sending us a RST then we don't need to send RST back,
			 * we can safely drop it. */
			send_rst(ip->hdr->ip_src.s_addr, ntohs(tcp.hdr->th_sport),
					 ntohs(tcp.hdr->th_dport), ntohl(tcp.hdr->th_ack),
					 ntohl(tcp.hdr->th_seq) + 1, TCP_CLOSE, tcp.hdr->th_flags);
		}
		return;
	}

	tcp.tcp_options = (u_char *)tcp.hdr + sizeof (struct libnet_tcp_hdr);
	/* XXX we don't actually do anything with the options, but eh */

	tcp.data = (u_char *)&tcp.hdr->th_sport + (tcp.hdr->th_off << 2);
	tcp.data_len = ntohs(ip->hdr->ip_len) - (ip->hdr->ip_hl << 2) -
		(tcp.hdr->th_off << 2);

	/* this is where the real work is */
	tcp_state_machine(sess, &tcp);
}

static void
icmp_echo_reply(struct icmp_pkt *icmp)
{
	/* we probably could make this handle static so that we don't have to
	 * rebuild it too many times */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lnh;
	u_char *payload;
	unsigned int len;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return;
	}

	len = ntohs(icmp->ip->ip_len) - LIBNET_IPV4_H - LIBNET_ICMPV4_ECHO_H;
	payload = icmp->data;

	if (libnet_build_icmpv4_echo(ICMP_ECHOREPLY, 0, 0, ntohs(icmp->hdr->icmp_id),
								 ntohs(icmp->hdr->icmp_seq), payload, len,
								 lnh, 0) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return;
	}

	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + len, 0, 0x42,
						  0, 64, IPPROTO_ICMP, 0, src_ip,
						  icmp->ip->ip_src.s_addr, NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
	}

	libnet_destroy(lnh);
	return;
}

static void
process_icmp_packet(struct ip_pkt *ip)
{
	struct icmp_pkt icmp;

	icmp.ip = ip->hdr;
	icmp.hdr = (struct libnet_icmpv4_hdr *)ip->data;
	icmp.data = (u_char *)(icmp.hdr + 1);

	switch (icmp.hdr->icmp_type) {
	case ICMP_ECHO:
		printf("being pinged (src %s)\n",
			   libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
		icmp_echo_reply(&icmp);
		break;
	case ICMP_ECHOREPLY:
		printf("received ping response from %s\n",
			   libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_RESOLVE));
		break;
	default:
		fprintf(stderr, "received unhandled icmp type %d (src %s)\n",
				icmp.hdr->icmp_type,
				libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_RESOLVE));
		break;
	}
}

static void
process_ip_packet(struct libnet_ethernet_hdr *enet)
{
	struct ip_pkt ip;
	uint16_t csum;
	int sum;

	ip.hdr = (struct libnet_ipv4_hdr *)(enet + 1);

	if (ip.hdr->ip_hl < 5 || ip.hdr->ip_v != 4) {
		fprintf(stderr, "bad IP packet, len = %d, ver = %d\n", ip.hdr->ip_hl,
				ip.hdr->ip_v);
		return;
	}

	csum = ip.hdr->ip_sum;
	ip.hdr->ip_sum = 0;
	sum = libnet_in_cksum((u_int16_t *)ip.hdr, ip.hdr->ip_hl << 2);
	ip.hdr->ip_sum = LIBNET_CKSUM_CARRY(sum);
	if (csum != ip.hdr->ip_sum) {
		fprintf(stderr, "checksum mismatch in IP header!\n");
		return;
	}

	/* if it's not for us, we ignore it. that's probably a bad thing since
	 * it means we ignore broadcast as well. but who the hell cares. if we
	 * ever want to support broadcast then we'll also have to change
	 * init_pcap so that it gives us broadcast packets. if we ever want to
	 * be really evil and do horrible things to other people's connections
	 * then we'll have to modify this and init_pcap. */
	if (ip.hdr->ip_dst.s_addr != src_ip) {
		return;
	}

	if (ip.hdr->ip_off & IP_MF) {
		/* XXX we don't deal with fragmentation at all (and again, we don't tell
		 * whoever we're talking to that we don't) */
		fprintf(stderr, "fragmentation being used (src %s)\n",
				libnet_addr2name4(ip.hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
		return;
	}

	ip.options = (u_char *)ip.hdr + sizeof (struct libnet_ipv4_hdr);
	/* XXX we don't actually do anything with the options, but eh */

	ip.data = (u_char *)ip.hdr + (ip.hdr->ip_hl << 2);

	switch (ip.hdr->ip_p) {
	case IPPROTO_TCP:
		process_tcp_packet(&ip);
		break;
	case IPPROTO_ICMP:
		process_icmp_packet(&ip);
		break;
	default:
		/* that's right, we don't handle udp! when's the last time you used udp.
		 * honestly. and don't tell me you actually use dns or ntp! or nfs. or
		 * smb. *shudder* */
		fprintf(stderr, "received unhandled protocol %d (src %s)\n",
				ip.hdr->ip_p, libnet_addr2name4(ip.hdr->ip_src.s_addr,
												LIBNET_DONT_RESOLVE));
		break;
	}
}

static void
process_packet(void)
{
	struct pcap_pkthdr hdr;
	u_char *pkt;

	struct libnet_ethernet_hdr *enet;

	int len;

	/* XXX this section needs to be fixed, it assumes too much */
	if (read(sp[1], &hdr, sizeof (hdr)) != sizeof (hdr))
		return;
	pkt = malloc(hdr.len);
	if ((len = read(sp[1], pkt, hdr.len)) < 0) {
		free(pkt);
		return;
	}
	if ((unsigned int)len != hdr.len) {
		free(pkt);
		return;
	}

#if 0
	printf("\nPACKET:\n");
	for (i = 0; i < hdr.len; i++) {
		printf("%02x ", pkt[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n\n");
#endif

	enet = (struct libnet_ethernet_hdr *)pkt;

	switch (ntohs(enet->ether_type)) {
	case ETHERTYPE_IP:
		process_ip_packet(enet);
		break;
	default:
		fprintf(stderr, "received unhandled ethernet type %d\n",
				ntohs(enet->ether_type));
		break;
	}

	free(pkt);
}

/* INPUT { */
static void
ping(char *host)
{
	/* we probably could make this handle static so that we don't have to
	 * rebuild it too many times */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lnh;
	libnet_ptag_t tag;
	uint32_t dst_ip;
	u_char payload[64 - LIBNET_ICMPV4_ECHO_H];
	unsigned int i;

	if (!(lnh = libnet_init(LIBNET_RAW4, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return;
	}

	dst_ip = libnet_name2addr4(lnh, host, LIBNET_RESOLVE);
	if (dst_ip == 0xffffffff) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return;
	}

	for (i = 0; i < sizeof (payload); i++)
		payload[i] = i;

	if ((tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, 0x42, 0, payload,
										sizeof (payload), lnh, 0)) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return;
	}

	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + 64, 0, 0, 0,
						  64, IPPROTO_ICMP, 0, src_ip, dst_ip,
						  NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
	}

	libnet_destroy(lnh);
	return;
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
			fprintf(stderr, "%s", libnet_geterror(sess->lnh));
			free(sess);
			return NULL;
		}
		sess->dst_prt = port;
		sess->src_prt = get_port(sess->dst_ip, sess->dst_prt);

		/* send the SYN, and we're off! */
		send_tcp(sess, TH_SYN, NULL, 0);
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

static void
fake_timeout(void *arg __attribute__((__unused__)))
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("processing timer at %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
}

static void
process_input(void)
{
	char buf[80];
	fgets(buf, sizeof (buf), stdin);
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;
	if (!strncasecmp(buf, "ping ", strlen("ping "))) {
		char *arg1;
		arg1 = buf + strlen("ping ");
		ping(arg1);
	} else if (!strncasecmp(buf, "connect ", strlen("connect "))) {
		char *arg1, *arg2;
		arg1 = buf + strlen("connect ");
		arg2 = strchr(arg1, ' ');
		if (!arg2)
			return;
		*arg2++ = 0;

		create_session(arg1, atoi(arg2));
	} else if (!strncasecmp(buf, "listen ", strlen("listen "))) {
		create_session(NULL, atoi(buf + strlen("listen ")));
	} else if (!strncasecmp(buf, "write ", strlen("write "))) {
		list *l = sessions;
		unsigned int id;
		char *arg1, *arg2;
		arg1 = buf + strlen("write ");
		arg2 = strchr(arg1, ' ');
		if (!arg2)
			return;
		*arg2++ = 0;
		id = atoi(arg1);

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

			if ((sess->state == TCP_ESTABLISHED) ||
				/* it's not possible for us to be in CLOSE_WAIT but we check it
				 * anyway, just to be pedantic */
				(sess->state == TCP_CLOSE_WAIT)) {
				send_tcp(sess, TH_PUSH | TH_ACK, (u_char *)arg2, strlen(arg2));
				/* XXX should add it to the send queue in case we need to
				 * retransmit. in that case we should also set a timer. */
			}
			break;
		}
		if (!l)
			printf("couldn't find %u\n", id);
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
				send_tcp(sess, TH_FIN | TH_ACK, NULL, 0);
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

			printf("id %d: port %d with %s:%d state %s\n",
				   sess->id, sess->src_prt,
				   libnet_addr2name4(sess->dst_ip, LIBNET_DONT_RESOLVE),
				   sess->dst_prt, state_names[sess->state]);
		}
	} else if (!strncasecmp(buf, "timer ", strlen("timer "))) {
		struct timeval tv;
		char *arg1;
		arg1 = buf + strlen("timer ");
		gettimeofday(&tv, NULL);
		printf("starting timer at %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
		timer_start(atoi(arg1), fake_timeout, NULL);
	} else if (!strcasecmp(buf, "timerlist")) {
		list *l = timers;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		printf("Current time: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
		while (l) {
			struct timer *t = l->data;
			l = l->next;
			printf("timer to expire at %ld.%06ld\n", t->end.tv_sec,
				   t->end.tv_usec);
		}
	} else if (!strcasecmp(buf, "quit")) {
		/* XXX should send RST to all the sessions */
		exit(0);
	}
}
/* } */

/* this function needs to get rewritten. desperately. */
static void * __attribute__((__noreturn__))
control_main(void *arg __attribute__((__unused__)))
{
	fd_set set;
	struct timeval tv, *ptv;

	while (1) {
		FD_ZERO(&set);
		FD_SET(0, &set);
		FD_SET(sp[1], &set);

		ptv = timer_sleep_time(&tv);

		if (select(sp[1] + 1, &set, NULL, NULL, ptv) < 0)
			exit(1);

		if (FD_ISSET(0, &set))
			process_input();

		if (FD_ISSET(sp[1], &set))
			/* we assume everything pcap gives is is IP, because we assume that
			 * the pcap thread handles everything else itself */
			process_packet();

		timer_process_pending();
	}
}

/* PCAP { */
/* TODO: convince the host we're running on that it can safely ignore us */
static int
arp_reply(const unsigned char hw[6], uint32_t ip)
{
	/* we probably could make this handle static so that we don't have to
	 * rebuild it too many times, but hopefully we should only need to
	 * build it once. */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lnh;
	unsigned char hwa[6];

	if (!(lnh = libnet_init(LIBNET_LINK, NULL, errbuf))) {
		fprintf(stderr, "%s\n", errbuf);
		return 0;
	}

	memcpy(hwa, hw, 6);

	if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REPLY,
						 src_hw, (u_char *)&src_ip, hwa, (u_char *)&ip,
						 NULL, 0, lnh, 0) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return 0;
	}

	if (libnet_autobuild_ethernet(hwa, ETHERTYPE_ARP, lnh) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
		return 0;
	}

	if (libnet_write(lnh) == -1) {
		fprintf(stderr, "%s", libnet_geterror(lnh));
		libnet_destroy(lnh);
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
packet_main(u_char *user __attribute__((__unused__)),
			const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	const struct libnet_ethernet_hdr *enet =
		(const struct libnet_ethernet_hdr *)pkt;
	if (ntohs(enet->ether_type) == ETHERTYPE_ARP) {
		/* since we're "faking" a client, we need to reply to arp
		 * requests as that client. the problem is, we're using the MAC
		 * address of the host, so if we get an arp from the host about
		 * our client, we need to just ignore it. the host should deal
		 * with this gracefully. (there has to be a better way.) */
		const struct arp *arp = (const struct arp *)pkt;
		if (hdr->len < sizeof (struct arp))
			return;
		if ((ntohs(arp->hdr.ar_hrd) == ARPHRD_ETHER) &&	/* ethernet*/
			(ntohs(arp->hdr.ar_pro) == ETHERTYPE_IP) &&	/* ipv4 */
			(ntohs(arp->hdr.ar_op) == ARPOP_REQUEST) &&	/* request */
			(arp->dst_ip == src_ip) &&			/* for us */
			memcmp(src_hw, arp->src_hw, 6))		/* not host */
			arp_reply(arp->src_hw, arp->src_ip);
	} else {
		/* XXX should probably do some sort of sanity check before sending it
		 * off. do you trust pcap? */
		write(sp[0], hdr, sizeof (struct pcap_pkthdr));
		write(sp[0], pkt, hdr->len);
	}
}

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
	/* this filter line should give us everything we need (including arp
	 * requests) */
	sprintf(filter_line, "dst host %s",
			libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE));
	pcap_compile(lph, &filter, filter_line, 0, net);
	free(filter_line);

	if (pcap_setfilter(lph, &filter) == -1) {
		fprintf(stderr, "%s\n", errbuf);
		return NULL;
	}
	return lph;
}
/* } */

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
