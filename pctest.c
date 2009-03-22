/*
 * TODO:
 *   IP:
 *     - IP options (security, source route, record route, timestamp)
 *     - traceroute
 *
 *   UDP:
 *     - maybe, if we do dhcp
 *
 *   DHCP:
 *     - would require changing the pcap filter line
 *
 *   TCP:
 *     - TCP options (mss, sack, wscale, timestamp)
 *     - "connection synchronization using data-carrying segments"
 *     - URG
 *     - Better initial seqno generation
 *     - slow start
 *     - congestion avoidance
 *     - tx queue (that obeys remote window size)
 *     - Grow/shrink windows
 *     - retransmission/timers (Karn, Jacobson, exp. backoff, etc.)
 *     - delayed/selective ACKs
 *     - header prediction
 *
 *   General:
 *     - argv parsing (specify device, user to run as, etc.)
 *     - better CLI (history would be nice, at least)
 *     - some way of guessing which IP address to use (dhcp?)
 *     - make sure not using loopback device
 *     - we can't talk to the host at all since moving to a link layer socket
 *
 *   And finally, all of the evil things I'd like to do:
 *    - Increased control over remote window size
 */

#include <libnet.h>
#include <pcap.h>
#include <pwd.h>

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
    if (!l) return NULL;
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
        /* timers are sorted by when they're going to expire (first to last), so
         * taking the first on the list should always be the first to expire and
         * so we can use it to figure out how long to tell select to sleep */
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
    /* we don't support periodic timers, and since timers are sorted by
     * expiration date, if we come across one that doesn't need processing, all
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

/* these are our global variables */
static libnet_t *lnh_link = NULL;
static pcap_t *lph;
static unsigned char src_hw[6];
static uint32_t src_ip = 0;
static u_int16_t ip_id;
static const u_int8_t ip_ttl = 64;
static list *sessions = NULL;
static list *open_connections = NULL;
static list *listeners = NULL;

/* ARP { */
struct arp_ent {
    uint32_t ip; /* network byte order */
    unsigned char hw[6];
} __attribute__ ((__packed__));

static list *arp_cache = NULL;

/* this probably wasn't entirely necessary but it's convenient */
struct arp_pkt {
    struct libnet_ethernet_hdr enet;
    struct libnet_arp_hdr hdr;
    /* everything from here down is IPv4 but that's all we need */
    unsigned char src_hw[6];
    uint32_t src_ip;
    unsigned char dst_hw[6];
    uint32_t dst_ip;
} __attribute__ ((__packed__));

static void
cache_arp(uint32_t ip, unsigned char *hw)
{
    list *l = arp_cache;
    struct arp_ent *ent;

    while (l) {
        ent = l->data;
        if (ent->ip == ip) {
            if (memcmp(ent->hw, hw, 6)) {
                printf("HW addr for %s changed\n",
                       libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));
                memcpy(ent->hw, hw, 6);
            }
            return;
        }
        l = l->next;
    }

    printf("caching arp for %s\n", libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));

    ent = malloc(sizeof (struct arp_ent));
    ent->ip = ip;
    memcpy(ent->hw, hw, 6);
    arp_cache = list_prepend(arp_cache, ent);
}

static unsigned char *
arp_lookup(uint32_t ip)
{
    list *l = arp_cache;
    while (l) {
        struct arp_ent *ent = l->data;
        l = l->next;
        if (ent->ip == ip) {
            return ent->hw;
        }
    }
    return NULL;
}

/* since we're "faking" a client, we need to reply to arp requests as that
 * client. we need to make sure that we don't send arp replies to the host,
 * because that will just confuse it. sending arp requests to it also confuses
 * it, but at least it doesn't do anything. */
static void
arp_reply(struct arp_pkt *arp)
{
    printf("replying to arp from %s\n",
           libnet_addr2name4(arp->src_ip, LIBNET_DONT_RESOLVE));

    libnet_clear_packet(lnh_link);

    if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REPLY, src_hw,
                         (u_char *)&src_ip, arp->src_hw, (u_char *)&arp->src_ip,
                         NULL, 0, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    if (libnet_autobuild_ethernet(arp->src_hw, ETHERTYPE_ARP, lnh_link) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    if (libnet_write(lnh_link) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }
}

static void
process_arp_packet(struct libnet_ethernet_hdr *enet, uint32_t len)
{
    struct arp_pkt *arp = (struct arp_pkt *)enet;

    if (len < LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H)
        return;

    if ((ntohs(arp->hdr.ar_hrd) != ARPHRD_ETHER) ||    /* ethernet*/
        (ntohs(arp->hdr.ar_pro) != ETHERTYPE_IP) ||    /* ipv4 */
        (arp->dst_ip != src_ip) ||                     /* for us */
        memcmp(src_hw, arp->src_hw, 6) == 0)           /* not host */
        return;

    cache_arp(arp->src_ip, arp->src_hw);

    if (ntohs(arp->hdr.ar_op) == ARPOP_REQUEST) {
        arp_reply(arp);
    }
}

static void
arp_request(uint32_t dst_ip)
{
    u_int8_t hw[6];

    printf("sending arp request for %s\n",
           libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE));

    libnet_clear_packet(lnh_link);

    memset(hw, 0, 6);
    if (libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST, src_hw,
                         (u_char *)&src_ip, hw, (u_char *)&dst_ip,
                         NULL, 0, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    memset(hw, 0xFF, 6);
    if (libnet_autobuild_ethernet(hw, ETHERTYPE_ARP, lnh_link) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    if (libnet_write(lnh_link) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }
}
/* } */

/* ROUTING { */
/* everything here is network byte order */
struct route_row {
    uint32_t dest;
    uint32_t mask;
    uint32_t gw;
};
static list *routing_table = NULL;

static int
route_cmp(const void *x, const void *y)
{
    const struct route_row *a = x, *b = y;
    /* the bigger (i.e. more specific) mask should come first */
    if (a->mask > b->mask) {
        return -1;
    } else if (a->mask < b->mask) {
        return 1;
    } else {
        /* otherwise, just sort by destination */
        return a->dest - b->dest;
    }
}

static int
route_add(uint32_t dest, uint32_t mask, uint32_t gw)
{
    struct route_row *rt;

    /* should we validate our input? well, probably. */
    uint32_t bit = 1 << 31, hmask = ntohl(mask), i = 1;
    while (bit) {
        if ((hmask & bit) == 0) {
            i = 0;
        } else if (i != 1) {
            fprintf(stderr, "invalid mask %08x\n", hmask);
            return 1;
        }
        bit >>= 1;
    }
    if ((dest & ~mask) != 0) {
        fprintf(stderr, "invalid dest/mask pair\n");
        return 1;
    }

    rt = malloc(sizeof (struct route_row));
    rt->dest = dest;
    rt->mask = mask;
    rt->gw = gw;
    routing_table = list_insert_sorted(routing_table, rt, route_cmp);

    if (dest == 0 && mask == 0) {
        /* if it's the default gateway, get its mac now. we're likely going to
         * have to eventually anyway. also, it's a handy way of seeing
         * immediately whether the setup is at least somewhat correct. */
        arp_request(gw);
    }

    return 0;
}

static libnet_ptag_t
send_ethernet(uint32_t dst_ip, libnet_ptag_t ptag)
{
    list *l = routing_table;

    while (l) {
        struct route_row *rt = l->data;
        unsigned char *dst_hw, broadcast[6];

        l = l->next;

        if ((dst_ip != 0) && ((dst_ip & rt->mask) != rt->dest)) {
            continue;
        }

        if ((dst_ip == 0) || ((dst_ip & ~rt->mask) == ~rt->mask)) {
            memset(broadcast, 0xff, 6);
            dst_hw = broadcast;
        } else {
            if (rt->gw != 0) {
                dst_ip = rt->gw;
            }

            dst_hw = arp_lookup(dst_ip);
            if (dst_hw == NULL) {
                arp_request(dst_ip);
                return -1;
            }
        }

        ptag = libnet_build_ethernet(dst_hw, src_hw, ETHERTYPE_IP,
                                     NULL, 0, lnh_link, ptag);
        if (ptag == -1) {
            fprintf(stderr, "%s", libnet_geterror(lnh_link));
            return -1;
        }

        if (libnet_write(lnh_link) == -1) {
            fprintf(stderr, "%s", libnet_geterror(lnh_link));
            return -1;
        }

        return ptag;
    }

    fprintf(stderr, "no route to host %s\n",
            libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE));
    return -1;
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

struct pkt_q {
    uint32_t seqno;
    int len; /* -1 means this is the fin */
    u_char *data;
};

typedef struct tcp_session {
    uint32_t id;    /* heh. a more appropriate name might be 'fd'. */

    uint32_t state;

    /* these identify a unique session. the src_ip is global. libnet_name2addr4
     * puts ip addresses in network byte order, so those will always be that
     * way. however, ports stored in the session will always be host byte order,
     * so when comparing against what comes off the wire, make sure to do a
     * proper translation */
    uint16_t src_prt;
    uint16_t dst_prt;
    uint32_t dst_ip;

    /* these are stored in host byte order mostly by default */
    uint32_t unacked; /* aka SND.UNA */
    uint32_t seqno;   /* aka SND.NXT */
    uint32_t snd_win; /* aka SND.WND */
    uint32_t iss;

    uint32_t ackno;   /* aka RCV.NXT */
    uint32_t rcv_win; /* aka RCV.WND */
    uint32_t irs;

    list *rx;

    /* there's really a bunch of other stuff that I should be paying
     * attention to */

    /* this is where we start getting evil: reimplementing sting */
    int sting;
    int count;
    int sting_acks;
    int data_lost;
    struct timer *tmr;
#define STING_STRING "GET / HTTP/1.0\n" \
        "Accept: text/plain\nAccept: */*\n" \
        "User-Agent: Mozilla/4.0 " \
        "(compatible; MSIE 5.0; Windows NT; DigExt; Sting)\n\n"
#define STING_COUNT 100
#define STING_DELAY 100
} TCB;

struct ip_pkt {
    struct libnet_ipv4_hdr *hdr;
    u_char *options;
    u_char *data;
};

struct icmp_pkt {
    struct libnet_ipv4_hdr *ip;
    struct libnet_icmpv4_hdr *hdr;
};

struct tcp_pkt {
    struct libnet_ipv4_hdr *ip;
    u_char *ip_options;
    struct libnet_tcp_hdr *hdr;
    u_char *tcp_options;
    u_char *data;
    uint32_t data_len;
};

/* TCP UTIL { */
static int
send_tcp(TCB *sess, int flags, u_char *data, uint32_t len)
{
    libnet_clear_packet(lnh_link);

    if (libnet_build_tcp(sess->src_prt, sess->dst_prt, sess->seqno, sess->ackno,
                         flags, sess->rcv_win, 0, 0, LIBNET_TCP_H + len, data,
                         len, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return 1;
    }
    if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H + len, IPTOS_RELIABILITY,
                          ip_id++, 0, ip_ttl, IPPROTO_TCP, 0, src_ip,
                          sess->dst_ip, NULL, 0, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return 1;
    }

    if (send_ethernet(sess->dst_ip, 0) == -1) {
        return 1;
    }

    if (flags & TH_SYN)
        sess->seqno++;
    if (flags & TH_FIN)
        sess->seqno++;
    sess->seqno += len;

    return 0;
}

/* eventually send_tcp is going to do nice things like queuing the data to be
 * sent and setting timers so it can retry if it hasn't been ack'd, so it makes
 * sense to have a separate function just for sending a RST. or at least, that's
 * what I keep telling myself. */
static int
send_rst(uint32_t state, struct tcp_pkt *tcp)
{
    uint32_t ackno = ntohl(tcp->hdr->th_seq) + 1;
    u_int8_t cntrl = TH_RST;

    if (!(tcp->hdr->th_flags & TH_ACK))
        cntrl |= TH_ACK;
    else
        ackno = 0;

    libnet_clear_packet(lnh_link);

    if (libnet_build_tcp(ntohs(tcp->hdr->th_dport), ntohs(tcp->hdr->th_sport),
                         ntohl(tcp->hdr->th_ack), ackno, cntrl, 0, 0, 0,
                         LIBNET_TCP_H, NULL, 0, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return 1;
    }

    if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPTOS_LOWDELAY, ip_id++,
                          0, ip_ttl, IPPROTO_TCP, 0, src_ip,
                          tcp->ip->ip_src.s_addr, NULL, 0, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return 1;
    }

    if (send_ethernet(tcp->ip->ip_src.s_addr, 0) == -1) {
        return 1;
    }

    fprintf(stderr, "RST'ing (SRC = %s:%d, DPort = %d (%s), Cntrl = %02x)\n",
            libnet_addr2name4(tcp->ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
            ntohs(tcp->hdr->th_sport), ntohs(tcp->hdr->th_dport),
            state_names[state], tcp->hdr->th_flags);
    return 0;
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

    /* TODO: we should support listening for specific hosts and/or ports */
    while (l) {
        TCB *sess = l->data;
        l = l->next;

        if (sess->src_prt == src_prt)
            return sess;
    }

    return NULL;
}

/* XXX there are probably several problems with this. */
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

    /* sess->state = TCP_CLOSE; */

    /* XXX this isn't actually supposed to be random; it's supposed to be
     * somewhat internal-clock-based so that if we happen to be using the same
     * src_prt/dst_ip/dst_prt tuple that was used in a previous session, the
     * remote stack knows that it's for a new session. but I don't care. */
    /* I hear I shouldn't use this function for anything real. oh well. */
    sess->seqno = libnet_get_prand(LIBNET_PRu32);

    /* XXX What you see is what you get. This is the only place the receive
     * window is modified. Setting it to 0 makes most hosts annoyed. And who can
     * blame them? The person they're talking to isn't listening to them. */
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

    sess->irs = ntohl(pkt->hdr->th_seq);
    sess->ackno = sess->irs + 1;

    send_tcp(sess, TH_SYN | TH_ACK, NULL, 0);
    sess->state = TCP_SYN_RECV;
    printf("%u: %s\n", sess->id, state_names[sess->state]);

    open_connections = list_prepend(open_connections, sess);

    return sess;
}

static void
free_txrx_queues(TCB *sess)
{
    while (sess->rx) {
        struct pkt_q *pq = sess->rx->data;
        sess->rx = list_remove(sess->rx, pq);
        if (pq->data)
            free(pq->data);
        free(pq);
    }
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
    free_txrx_queues(sess);
    timer_cancel(sess->tmr);
    free(sess);
}

/* TODO: maybe eventually you can specify the port to connect from */
static TCB *
create_session(char *host, uint16_t port)
{
    TCB *sess;

    if (host) {
        if ((sess = session_setup()) == NULL)
            return NULL;

        sess->dst_ip = libnet_name2addr4(lnh_link, host, LIBNET_RESOLVE);
        if (sess->dst_ip == 0xffffffff) {
            fprintf(stderr, "%s", libnet_geterror(lnh_link));
            remove_session(sess);
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
/* } */

/* STING { */
static void
sting(void *data)
{
    TCB *sess = data;

    u_char str[] = STING_STRING;

    sess->count++;
    send_tcp(sess, TH_PUSH | TH_ACK, &str[sess->count], 1);

    if (sess->count != STING_COUNT) {
        sess->tmr = timer_start(STING_DELAY, sting, data);
    } else {
        /* so now we send the last byte */
        sess->tmr = NULL;
        sess->seqno = sess->iss;
        send_tcp(sess, TH_PUSH | TH_ACK, &str[0], 1);
        sess->seqno = sess->iss + STING_COUNT + 1;
    }
}

static void
sting_process(TCB *sess, struct tcp_pkt *pkt)
{
    u_char str[] = STING_STRING;

    if (sess->state != TCP_ESTABLISHED) {
        fprintf(stderr, "sting session stopping?\n");
        timer_cancel(sess->tmr);
        return;
    }

    if (ntohl(pkt->hdr->th_ack) == sess->iss) {
        /* they're still waiting for our first byte */
        sess->sting_acks++;
    } else if (ntohl(pkt->hdr->th_ack) == sess->seqno) {
        printf("sting to %s:\n",
               libnet_addr2name4(pkt->ip->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        printf("remote received %d/%d packets\n", STING_COUNT - sess->data_lost,
               STING_COUNT);
        printf("we received %d/%d acks\n", sess->sting_acks,
               STING_COUNT - sess->data_lost);

        send_tcp(sess, TH_RST | TH_ACK, NULL, 0);
        remove_session(sess);
    } else {
        /* this indicates that they dropped something and need it resent */
        sess->data_lost++;

        sess->seqno = ntohl(pkt->hdr->th_ack);
        send_tcp(sess, TH_PUSH | TH_ACK, &str[sess->seqno - sess->iss], 1);
        sess->seqno = sess->iss + STING_COUNT + 1;
    }
}
/* } */

/* TCP SM { */
static TCB *
tcp_process_listen(TCB *sess, struct tcp_pkt *pkt)
{
    if (pkt->hdr->th_flags & TH_RST) {
        /* we're in a listening state, just drop it */
    } else if (pkt->hdr->th_flags & TH_ACK) {
        send_rst(sess->state, pkt);
    } else if (pkt->hdr->th_flags & TH_SYN) {
        return accept_session(sess, pkt);
    } else {
        /* And I quote:
         *
         * Any other control or text-bearing segment (not containing SYN)
         * must have an ACK and thus would be discarded by the ACK
         * processing. An incoming RST segment could not be valid, since it
         * could not have been sent in response to anything sent by this
         * incarnation of the connection. So you are unlikely to get here,
         * but if you do, drop the segment, and return. */
    }
    return NULL;
}

static void
tcp_process_syn_sent(TCB *sess, struct tcp_pkt *pkt)
{
    if (pkt->hdr->th_flags & TH_ACK) {
        if (ntohl(pkt->hdr->th_ack) != sess->seqno) {
            fprintf(stderr, "Invalid ackno on %d\n", sess->id);
            send_rst(sess->state, pkt);
            remove_session(sess);
            return;
        } else {
            sess->unacked = ntohl(pkt->hdr->th_ack);
        }
    }

    /* by now we've already handled RST and ACK. any other packet without SYN
     * should just be dropped */
    if (!(pkt->hdr->th_flags & TH_SYN))
        return;

    sess->irs = ntohl(pkt->hdr->th_seq);
    sess->ackno = sess->irs + 1;
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

    /* we assume that sting will always go this route */
    if ((sess->state == TCP_ESTABLISHED) && sess->sting) {
        /* bump seqno deliberately despite not having sent anything yet */
        sess->seqno++;
        sting(sess);
    }
}

static int
tcp_check_seqno(TCB *sess, struct tcp_pkt *pkt)
{
    unsigned int len = ntohs(pkt->ip->ip_len) -
        (pkt->ip->ip_hl << 2) - (pkt->hdr->th_off << 2);
    uint32_t rcvnxt = sess->ackno, segseq = ntohl(pkt->hdr->th_seq);

    if (len == 0) {
        if ((0 <= (int32_t)(segseq - rcvnxt)) &&
            /* if sess->rcv_win is 0 then the check is if
             * pkt->hdr->th_seq <= sess->ackno, which is acceptable,
             * since the above check makes it the same check
             * as checking if sess->ackno == pkt->hdr->th_seq */
            (0 <= (int32_t)(rcvnxt + sess->rcv_win - segseq))) {
            return 0;
        }
    } else if (sess->rcv_win != 0) {
        if (((0 <= (int32_t)(segseq - rcvnxt)) &&
             (0 < (int32_t)(rcvnxt + sess->rcv_win - segseq))) ||
            ((0 <= (int32_t)(segseq + len - 1 - rcvnxt)) &&
             (0 < (int32_t)(rcvnxt + sess->rcv_win - (segseq + len - 1))))) {
            return 0;
        }
    }
    /* if there's data and our window is 0 then it's unacceptable */
    return 1;
}

static int
tcp_process_syn_recv(TCB *sess, struct tcp_pkt *pkt)
{
    if (sess->unacked > ntohl(pkt->hdr->th_ack) ||
        ntohl(pkt->hdr->th_ack) > sess->seqno) {
        fprintf(stderr, "Invalid ackno on %d\n", sess->id);
        send_rst(sess->state, pkt);
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

    if ((0 <= (int32_t)(segack - snduna)) &&
        (0 <= (int32_t)(sndnxt - segack))) {
        snduna = sess->unacked = segack;
        /* XXX "the send window should be updated" */
    } else if (0 < (int32_t)(snduna - segack)) {
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

static int
pkt_q_cmp(const void *x, const void *y)
{
    /* this works because seqno is the first item */
    return (*(const uint32_t *)x - *(const uint32_t *)y);
}

static void
tcp_queue_packet(TCB *sess, struct tcp_pkt *pkt)
{
    uint32_t seqno = ntohl(pkt->hdr->th_seq);

    /* if we're in closing then we got the FIN, don't queue anything */
    if (sess->state == TCP_CLOSING) {
        return;
    }

    if ((seqno + pkt->data_len > sess->ackno) &&
        (pkt->data_len != 0)) {
        /* add the data to the rx queue */
        struct pkt_q *pq = calloc(1, sizeof (struct pkt_q));
        pq->seqno = seqno;
        pq->len = pkt->data_len;
        pq->data = malloc(pkt->data_len);
        memcpy(pq->data, pkt->data, pkt->data_len);
        sess->rx = list_insert_sorted(sess->rx, pq, pkt_q_cmp);
    }

    if ((pkt->hdr->th_flags & TH_FIN) &&
        (seqno + pkt->data_len + 1 > sess->ackno)) {
        /* add the fin to the rx queue */
        struct pkt_q *pq = calloc(1, sizeof (struct pkt_q));
        pq->seqno = seqno + pkt->data_len;
        pq->len = -1; /* FIN */
        sess->rx = list_insert_sorted(sess->rx, pq, pkt_q_cmp);
    }
}

static void
tcp_handle_data(TCB *sess, u_char *data, unsigned int len)
{
    unsigned int i;

    if (len == 0)
        return;

    printf("read %u: %u bytes\n", sess->id, len);

    for (i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if (i && (i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
    for (i = 0; i < len; i++) {
        if (isprint(data[i]))
            printf(" %c ", data[i]);
        else
            printf("   ");
        if (i && (i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");

    sess->ackno += len;
}

static int
tcp_handle_fin(TCB *sess)
{
    sess->ackno++;

    if ((sess->state == TCP_SYN_RECV) || (sess->state == TCP_ESTABLISHED)) {
        /* some stacks send both the FIN and the ACK together, and move right
         * through CLOSE_WAIT to LAST_ACK. not us! we'll sit in CLOSE_WAIT
         * until the user tells us to close. */
        send_tcp(sess, TH_ACK, NULL, 0);
        sess->state = TCP_CLOSE_WAIT;
        printf("%u: %s\n", sess->id, state_names[sess->state]);
    } else if (sess->state == TCP_FIN_WAIT1) {
        /* ACK the FIN, wait for our ACK */
        send_tcp(sess, TH_ACK, NULL, 0);
        sess->state = TCP_CLOSING;
        printf("%u: %s\n", sess->id, state_names[sess->state]);
    } else if (sess->state == TCP_FIN_WAIT2) {
        /* we've got the FIN, send the ACK and we're done */
        send_tcp(sess, TH_ACK, NULL, 0);
        sess->state = TCP_TIME_WAIT;
        printf("%u: %s\n", sess->id, state_names[sess->state]);
        /* we should stay in TIME_WAIT for 2 MSL, but if the ack is received
         * it's not necessary. if it's lost and they resend FIN we'll send RST,
         * which isn't what's expected but will do about the right thing */
        remove_session(sess);
    } else {
        /* anyone else just stays in their state. TIME-WAIT, if it were
         * possible for us, would restart the 2 MSL time-wait timeout. */
        return 1;
    }

    return 0;
}

static void
tcp_drain_queue(TCB *sess)
{
    int send_ack = 0;

    while (sess->rx) {
        struct pkt_q *pq = sess->rx->data;
        int offset, len;

        /* we got here because we got a packet containing *something*, so send
         * an ack no matter what. but sometimes we send an ack as part of
         * handling fin, so don't necessarily do it here. just do it. */
        send_ack = 1;

        /* if it's not time to handle this yet, just break */
        if (pq->seqno > sess->ackno) {
            fprintf(stderr, "detected missed packet on %d\n", sess->id);
            break;
        }

        /* if it's a FIN, handle it, free the list, and we're done */
        if (pq->len == -1) {
            /* what if pq->seqno < sess->ackno? in that case, we got a misplaced
             * FIN? that seems like someone is trying to do something evil */
            if (pq->seqno < sess->ackno) {
                fprintf(stderr, "FIN again on %d!\n", sess->id);
            }
            /* free before handle because sess might not be valid after */
            free_txrx_queues(sess);
            send_ack = tcp_handle_fin(sess);
            break;
        }

        /* now comes the fun part, reassembling the data */
        offset = sess->ackno - pq->seqno;
        len = pq->len - offset;
        if (len > 0) {
            tcp_handle_data(sess, pq->data + offset, len);
        }
        sess->rx = list_remove(sess->rx, pq);
        if (pq->data)
            free(pq->data);
        free(pq);
    }

    if (send_ack) {
        send_tcp(sess, TH_ACK, NULL, 0);
    }
}

static void
tcp_state_machine(TCB *sess, struct tcp_pkt *pkt)
{
    /* here we can assume that the pkt is part of the session and for us */

    if (sess->state == TCP_LISTEN) {
        sess = tcp_process_listen(sess, pkt);
        return;
    }

    if (pkt->hdr->th_flags & TH_RST) {
        fprintf(stderr, "Remote host sent RST, closing %d\n", sess->id);
        remove_session(sess);
        return;
    }

    if (sess->state == TCP_SYN_SENT) {
        tcp_process_syn_sent(sess, pkt);
        return;
    }

    /* at this point the state is not CLOSED, LISTEN, or SYN_SENT. also we won't
     * be in the TIME_WAIT state because we assume the other side received our
     * last ACK. */

    if (tcp_check_seqno(sess, pkt)) {
        /* XXX should we be updating sess->unacked from hdr->th_ack here? */
        fprintf(stderr, "unacceptable segment size on %d\n", sess->id);
        send_tcp(sess, TH_ACK, NULL, 0);
        return;
    }

    if (pkt->hdr->th_flags & TH_SYN) {
        fprintf(stderr, "SYN on %d\n", sess->id);
        send_rst(sess->state, pkt);
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

    /* at this point we're either ESTABLISHED, FIN_WAIT (1 or 2), CLOSE_WAIT, or
     * CLOSING. all of these "Do the same processing as for the ESTABLISHED
     * state" before doing their own thing */
    if (tcp_check_ackno(sess, pkt))
        return;

    if (sess->state == TCP_CLOSE_WAIT) {
        /* receiving data or FIN is either invalid or ignored, so we can stop
         * processing now. XXX should we send an ACK? */
        return;
    }

    tcp_queue_packet(sess, pkt);

    tcp_drain_queue(sess);

    if (sess->sting)
        sting_process(sess, pkt);
}

static void
process_tcp_packet(struct ip_pkt *ip)
{
    struct tcp_pkt tcp;
    TCB *sess;

    uint16_t csum;
    int sum, len;

    if (ntohs(ip->hdr->ip_len) < (ip->hdr->ip_hl << 2) + LIBNET_TCP_H) {
        fprintf(stderr, "invalid tcp packet (src %s)\n",
                libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        return;
    }

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
        fprintf(stderr, "checksum mismatch in TCP header (src %s), was %x, should be %x!\n",
                libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE),
                csum, tcp.hdr->th_sum);
        return;
    }

    if ((tcp.hdr->th_off << 2) < LIBNET_TCP_H) {
        fprintf(stderr, "invalid TCP header (src %s)!\n",
                libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        return;
    }

    if (!(sess = find_session(ip->hdr->ip_src.s_addr, ntohs(tcp.hdr->th_sport),
                              ntohs(tcp.hdr->th_dport)))) {
        if (!(tcp.hdr->th_flags & TH_RST)) {
            /* if they're sending us a RST then we don't need to send RST back,
             * we can safely drop it. */
            send_rst(TCP_CLOSE, &tcp);
        }
        return;
    }

    if (ntohs(ip->hdr->ip_len) <
        (ip->hdr->ip_hl << 2) + (tcp.hdr->th_off << 2)) {
        fprintf(stderr, "invalid th_off (src %s)\n",
                libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        return;
    }

    tcp.tcp_options = (u_char *)tcp.hdr + LIBNET_TCP_H;
    /* TODO: we don't actually do anything with the options, but eh */

    tcp.data = (u_char *)&tcp.hdr->th_sport + (tcp.hdr->th_off << 2);
    tcp.data_len = ntohs(ip->hdr->ip_len) - (ip->hdr->ip_hl << 2) -
        (tcp.hdr->th_off << 2);

    /* this is where the real work is */
    tcp_state_machine(sess, &tcp);
}
/* } */

/* UDP { */
static void
process_udp_packet(struct ip_pkt *ip)
{
    /* that's right, we don't handle udp! when's the last time you used udp.
     * honestly. and don't tell me you actually use dns! or ntp. or nfs. or
     * smb. *shudder* */
    unsigned int len;

    printf("rejecting udp (src %s)\n",
           libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));

    len = (ip->hdr->ip_hl << 2) + 64;
    if (len > ntohs(ip->hdr->ip_len))
        len = ntohs(ip->hdr->ip_len);

    libnet_clear_packet(lnh_link);

    if (libnet_build_icmpv4_unreach(ICMP_UNREACH, ICMP_UNREACH_PORT, 0,
                                    (u_int8_t *)ip->hdr, len,
                                    lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_UNREACH_H + len,
                          0, ip_id++, 0, ip_ttl, IPPROTO_ICMP, 0,
                          src_ip, ip->hdr->ip_src.s_addr,
                          NULL, 0, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    send_ethernet(ip->hdr->ip_src.s_addr, 0);
}
/* } */

/* ICMP { */
static void
icmp_echo_reply(struct icmp_pkt *icmp)
{
    unsigned int len;

    if (ntohs(icmp->ip->ip_len) <
        (icmp->ip->ip_hl << 2) + LIBNET_ICMPV4_ECHO_H) {
        fprintf(stderr, "invalid icmp echo packet (src %s)\n",
                libnet_addr2name4(icmp->ip->ip_src.s_addr,
                                  LIBNET_DONT_RESOLVE));
        return;
    }

    printf("being pinged (src %s)\n",
           libnet_addr2name4(icmp->ip->ip_src.s_addr, LIBNET_DONT_RESOLVE));

    len = ntohs(icmp->ip->ip_len) - (icmp->ip->ip_hl << 2) -
        LIBNET_ICMPV4_ECHO_H;

    libnet_clear_packet(lnh_link);

    if (libnet_build_icmpv4_echo(ICMP_ECHOREPLY, 0, 0,
                                 ntohs(icmp->hdr->icmp_id),
                                 ntohs(icmp->hdr->icmp_seq),
                                 (u_int8_t *)icmp->hdr->icmp_data, len,
                                 lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + len,
                        icmp->ip->ip_tos, ip_id++, 0, ip_ttl, IPPROTO_ICMP, 0,
                        src_ip, icmp->ip->ip_src.s_addr,
                        NULL, 0, lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    send_ethernet(icmp->ip->ip_src.s_addr, 0);
}

static void
process_icmp_echo_reply(struct icmp_pkt *icmp)
{
    struct timeval tv, diff;
    int i;

    gettimeofday(&tv, NULL);

    if (ntohs(icmp->ip->ip_len) != (icmp->ip->ip_hl << 2) + 64) {
        fprintf(stderr, "improper echo reply (src %s)\n",
                libnet_addr2name4(icmp->ip->ip_src.s_addr,
                                  LIBNET_DONT_RESOLVE));
        return;
    }

    for (i = sizeof (struct timeval); i < 64 - LIBNET_ICMPV4_ECHO_H; i++) {
        if (icmp->hdr->icmp_data[i] != i) {
            fprintf(stderr, "byte %d is %02x, should be %02x\n",
                    i, icmp->hdr->icmp_data[i], i);
        }
    }

    timersub(&tv, (struct timeval *)(icmp->hdr->icmp_data), &diff);
    printf("received ping response from %s (%ld.%.03ld ms)\n",
           libnet_addr2name4(icmp->ip->ip_src.s_addr, LIBNET_RESOLVE),
           (diff.tv_sec * 1000) + (diff.tv_usec / 1000),
           diff.tv_usec % 1000);
}

static void
process_icmp_packet(struct ip_pkt *ip)
{
    struct icmp_pkt icmp;
    uint16_t csum;
    int sum;

    icmp.ip = ip->hdr;
    icmp.hdr = (struct libnet_icmpv4_hdr *)ip->data;

    csum = icmp.hdr->icmp_sum;
    icmp.hdr->icmp_sum = 0;
    sum = libnet_in_cksum((u_int16_t *)icmp.hdr,
                          ntohs(ip->hdr->ip_len) - (ip->hdr->ip_hl << 2));
    icmp.hdr->icmp_sum = LIBNET_CKSUM_CARRY(sum);
    if (csum != icmp.hdr->icmp_sum) {
        fprintf(stderr, "invalid icmp checksum (src %s)\n",
                libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        return;
    }

    switch (icmp.hdr->icmp_type) {
    case ICMP_ECHO:
        icmp_echo_reply(&icmp);
        break;
    case ICMP_ECHOREPLY:
        process_icmp_echo_reply(&icmp);
        break;
    default:
        fprintf(stderr, "received unhandled icmp type %d (src %s)\n",
                icmp.hdr->icmp_type,
                libnet_addr2name4(ip->hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        break;
    }
}
/* } */

/* IP { */

/*        FRAGMENTS { */
struct ip_frag_bit {
    uint16_t offset;
    uint16_t len;
    int end;
    uint8_t *data;
};

struct ip_frag {
    uint32_t ip_src;
    u_int16_t ip_id;
    u_int8_t ip_p;
    u_int8_t pad;
    list *bits;
    uint8_t *data;
    struct timer *timer;
};

static list *fragments = NULL;

static struct ip_frag *
find_ip_frag(struct ip_pkt *pkt)
{
    list *l = fragments;
    while (l) {
        struct ip_frag *frag = l->data;
        l = l->next;
        if ((frag->ip_src == pkt->hdr->ip_src.s_addr) &&
            (frag->ip_id == pkt->hdr->ip_id) &&
            (frag->ip_p == pkt->hdr->ip_p))
            return frag;
    }
    return NULL;
}

static void
free_ip_frag(struct ip_frag *frag)
{
    if (!frag)
        return;

    fragments = list_remove(fragments, frag);

    while (frag->bits) {
        struct ip_frag_bit *bit = frag->bits->data;
        frag->bits = list_remove(frag->bits, bit);
        free(bit->data);
        free(bit);
    }

    if (frag->data)
        free(frag->data);

    free(frag);
}

static void
timeout_ip_frag(void *arg)
{
    struct ip_frag *frag = arg;
    fprintf(stderr, "fragment %s %d %d timed out\n",
            libnet_addr2name4(frag->ip_src, LIBNET_DONT_RESOLVE),
            frag->ip_id, frag->ip_p);
    /* we should be sending an ICMP message here but I don't care. odds are that
     * either the host that was sending us the fragmented packet was trying to
     * do something evil to us, or the network between us is a little wonky.
     * either way the ICMP message saying that the reassembly timed out will
     * probably not have any effect. */
    free_ip_frag(frag);
}

static int
frag_bit_cmp(const void *x, const void *y)
{
    const struct ip_frag_bit *a = x, *b = y;
    return (a->offset - b->offset);
}

static struct ip_frag *
reassemble_ip_frag(struct ip_frag *frag, struct ip_pkt *pkt)
{
    int cur = 0;
    list *l = frag->bits;

    while (l) {
        struct ip_frag_bit *bit = l->data;
        l = l->next;
        /* if the offset is greater than our current pointer then return */
        if (bit->offset > cur)
            return NULL;
        /* update our offset */
        cur = bit->offset + bit->len;
        /* if this isn't the end but there are no more bits return */
        if (!bit->end && !l)
            return NULL;
        /* if this is the end then stop processing bits */
        if (bit->end)
            break;
    }

    /* at this point we have all the data we're told we're going to get and cur
     * is equal to the length of that data */
    timer_cancel(frag->timer);
    frag->timer = NULL;

    frag->data = malloc(LIBNET_IPV4_H + cur);
    if (!frag->data) {
        free_ip_frag(frag);
        return NULL;
    }

    l = frag->bits;
    while (l) {
        struct ip_frag_bit *bit = l->data;
        l = l->next;
        memcpy(&frag->data[bit->offset + LIBNET_IPV4_H], bit->data, bit->len);
        if (bit->end)
            break;
    }

    memcpy(frag->data, pkt->hdr, LIBNET_IPV4_H);
    pkt->hdr = (struct libnet_ipv4_hdr *)frag->data;
    pkt->hdr->ip_len = ntohs(LIBNET_IPV4_H + cur);
    /* TODO: we're supposed to support options, but eh */
    pkt->hdr->ip_hl = (LIBNET_IPV4_H >> 2);
    pkt->options = NULL;
    pkt->data = (u_char *)pkt->hdr + LIBNET_IPV4_H;

    return frag;
}

static struct ip_frag *
add_ip_frag(struct ip_pkt *pkt)
{
    struct ip_frag *frag = find_ip_frag(pkt);
    struct ip_frag_bit *bit;
    uint16_t offset;
    uint16_t len;
    int more;

    if (!frag) {
        frag = malloc(sizeof (struct ip_frag));
        if (!frag) return NULL;
        frag->ip_src = pkt->hdr->ip_src.s_addr;
        frag->ip_id = pkt->hdr->ip_id;
        frag->ip_p = pkt->hdr->ip_p;

        frag->bits = NULL;
        frag->data = NULL;
        frag->timer = timer_start(pkt->hdr->ip_ttl * 1000,
                                timeout_ip_frag, frag);

        fragments = list_prepend(fragments, frag);
    }

    offset = (ntohs(pkt->hdr->ip_off) & IP_OFFMASK) << 3;
    len = ntohs(pkt->hdr->ip_len) - (pkt->hdr->ip_hl << 2);
    more = ntohs(pkt->hdr->ip_off) & IP_MF ? 1 : 0;

    bit = malloc(sizeof (struct ip_frag_bit));
    if (!bit) return NULL;
    bit->offset = offset;
    bit->len = len;
    bit->end = !more;
    bit->data = malloc(len);
    if (!bit->data) {
        free(bit);
        return NULL;
    }
    memcpy(bit->data, pkt->data, len);
    /* XXX we should also be copying and verifying options, but eh */

    frag->bits = list_insert_sorted(frag->bits, bit, frag_bit_cmp);

    return reassemble_ip_frag(frag, pkt);
}
/*        } */

static void
process_ip_packet(struct libnet_ethernet_hdr *enet, uint32_t len)
{
    struct ip_frag *frag = NULL;
    struct ip_pkt ip;
    uint16_t csum;
    int sum;

    if (len < LIBNET_ETH_H + LIBNET_IPV4_H) {
        fprintf(stderr, "packet does not include full header\n");
        return;
    }

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
     * then we'll have to modify this and init_pcap() below. */
    if (ip.hdr->ip_dst.s_addr != src_ip) {
        return;
    }

    if (len < (uint32_t)(LIBNET_ETH_H + (uint16_t)ntohs(ip.hdr->ip_len))) {
        fprintf(stderr, "invalid ip_len (src %s)\n",
                libnet_addr2name4(ip.hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        return;
    }
    if ((ip.hdr->ip_hl << 2) > ntohs(ip.hdr->ip_len)) {
        fprintf(stderr, "invalid ip_hl (src %s)\n",
                libnet_addr2name4(ip.hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
        return;
    }
    /* now we know that there's at least as much data as ip_len says and that
     * ip_hl isn't invalid, so we can use those for validation from now on */

    ip.options = (u_char *)ip.hdr + LIBNET_IPV4_H;
    /* TODO: we don't actually do anything with the options, but eh */

    ip.data = (u_char *)ip.hdr + (ip.hdr->ip_hl << 2);

    if (ntohs(ip.hdr->ip_off) & (IP_MF|IP_OFFMASK)) {
        frag = add_ip_frag(&ip);
        if (frag == NULL)
            return;
    }

    switch (ip.hdr->ip_p) {
    case IPPROTO_TCP:
        process_tcp_packet(&ip);
        break;
    case IPPROTO_UDP:
        process_udp_packet(&ip);
        break;
    case IPPROTO_ICMP:
        process_icmp_packet(&ip);
        break;
    default:
        fprintf(stderr, "received unhandled protocol %d (src %s)\n",
                ip.hdr->ip_p, libnet_addr2name4(ip.hdr->ip_src.s_addr,
                                                LIBNET_DONT_RESOLVE));
        break;
    }

    free_ip_frag(frag);
}
/* } */

/* INPUT { */
static void
ping(char *host)
{
    uint32_t dst_ip;
    u_char payload[64 - LIBNET_ICMPV4_ECHO_H];
    unsigned int i;

    dst_ip = libnet_name2addr4(lnh_link, host, LIBNET_RESOLVE);
    if (dst_ip == 0xffffffff) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    for (i = 0; i < sizeof (payload); i++)
        payload[i] = i;

    gettimeofday((struct timeval *)&payload[0], NULL);

    libnet_clear_packet(lnh_link);

    if (libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, 0x42, 0, payload,
                                 sizeof (payload), lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    if (libnet_build_ipv4(LIBNET_IPV4_H + 64, IPTOS_LOWDELAY, ip_id++, 0,
                          ip_ttl, IPPROTO_ICMP, 0, src_ip, dst_ip, NULL, 0,
                          lnh_link, 0) == -1) {
        fprintf(stderr, "%s", libnet_geterror(lnh_link));
        return;
    }

    send_ethernet(dst_ip, 0);
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
    } else if (!strncasecmp(buf, "sting ", strlen("sting "))) {
        TCB *sess;
        char *arg1, *arg2;
        uint16_t port = 80;
        arg1 = buf + strlen("sting ");
        arg2 = strchr(arg1, ' ');
        if (arg2) {
            *arg2++ = 0;
            port = atoi(arg2);
        }

        sess = create_session(arg1, port);
        sess->sting = 1;
        /* by this time seqno is iss+1 but that's fine for our purposes */
        sess->iss = sess->seqno;
    } else if (!strncasecmp(buf, "connect ", strlen("connect "))) {
        char *arg1, *arg2;
        arg1 = buf + strlen("connect ");
        arg2 = strchr(arg1, ' ');
        if (!arg2) {
            fprintf(stderr, "need to specify port to connect to\n");
            return;
        }
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
        if (!arg2) {
            fprintf(stderr, "need to specify socket to write to\n");
            return;
        }
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

            if (sess->sting) {
                fprintf(stderr, "can't write to sting session!\n");
                break;
            }

            if ((sess->state == TCP_ESTABLISHED) || (sess->state == TCP_CLOSE_WAIT)) {
                send_tcp(sess, TH_PUSH | TH_ACK, (u_char *)arg2, strlen(arg2));
                /* XXX should add it to the send queue in case we need to
                 * retransmit. in that case we should also set a timer. */
            }
            break;
        }
        if (!l)
            printf("couldn't find %u\n", id);
    } else if (!strncasecmp(buf, "fragw ", strlen("fragw "))) {
        list *l = sessions;
        unsigned int id;
        char *arg1, *arg2;
        arg1 = buf + strlen("fragw ");
        arg2 = strchr(arg1, ' ');
        if (!arg2) {
            fprintf(stderr, "need to specify socket to write to\n");
            return;
        }
        *arg2++ = 0;
        if (strlen(arg2) < 8) {
            fprintf(stderr, "Need more data to send bizarre write\n");
            return;
        }
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

            if (sess->sting) {
                fprintf(stderr, "can't write to sting session!\n");
                break;
            }

            if ((sess->state == TCP_ESTABLISHED) || (sess->state == TCP_CLOSE_WAIT)) {
                uint32_t orig_seqno = sess->seqno, post_seqno;
                sess->seqno += 4;
                send_tcp(sess, TH_PUSH | TH_ACK, (u_char *)arg2 + 4, strlen(arg2) - 4);
                post_seqno = sess->seqno;
                usleep(600);
                sess->seqno = orig_seqno;
                send_tcp(sess, TH_PUSH | TH_ACK, (u_char *)arg2, 8);
                sess->seqno = post_seqno;
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
                printf("%u: %s\n", sess->id, state_names[sess->state]);
            } else if (sess->state == TCP_CLOSE_WAIT) {
                send_tcp(sess, TH_FIN | TH_ACK, NULL, 0);
                sess->state = TCP_LAST_ACK;
                printf("%u: %s\n", sess->id, state_names[sess->state]);
            }
            break;
        }
        if (!l)
            printf("couldn't find %u\n", id);
    } else if (!strcasecmp(buf, "netstat")) {
        list *l = sessions;
        printf("%-5s%-22s%-22s%s\n",
               "ID", "Local Address", "Foreign Address", "State");
        while (l) {
            char sting_string[100];
            char local[23], foreign[23];
            TCB *sess = l->data;
            l = l->next;

            sprintf(local, "%s:%d",
                    libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE),
                    sess->src_prt);

            sprintf(foreign, "%s:%d",
                    libnet_addr2name4(sess->dst_ip, LIBNET_DONT_RESOLVE),
                    sess->dst_prt);

            if (sess->sting) {
                sprintf(sting_string, " (stinging, %d/%d sent)",
                        sess->count, STING_COUNT);
            } else {
                sting_string[0] = '\0';
            }

            printf("%-5d%-22s%-22s%-12s%s\n",
                   sess->id, local, foreign, state_names[sess->state],
                   sting_string);
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
    } else if (!strcasecmp(buf, "arp")) {
        list *l = arp_cache;
        printf("%-20s%s\n", "Address", "HWaddress");
        while (l) {
            struct arp_ent *ent = l->data;
            l = l->next;
            printf("%-20s%02x:%02x:%02x:%02x:%02x:%02x\n",
                   libnet_addr2name4(ent->ip, LIBNET_DONT_RESOLVE),
                   ent->hw[0], ent->hw[1],
                   ent->hw[2], ent->hw[3],
                   ent->hw[4], ent->hw[5]);
        }
    } else if (!strcasecmp(buf, "route")) {
        list *l = routing_table;
        printf("%-16s%-16s%s\n", "Destination", "Gateway", "Genmask");
        while (l) {
            struct route_row *rt = l->data;
            l = l->next;
            printf("%-16s%-16s%s\n",
                   libnet_addr2name4(rt->dest, LIBNET_DONT_RESOLVE),
                   libnet_addr2name4(rt->gw, LIBNET_DONT_RESOLVE),
                   libnet_addr2name4(rt->mask, LIBNET_DONT_RESOLVE));
        }
    } else if (!strcasecmp(buf, "quit")) {
        /* XXX should send RST to all the sessions, and remove the bogus arp
         * entry from the host, though that required root, which we dropped */
        exit(0);
    }
}
/* } */

/* PCAP { */
static void
process_packet(void)
{
    struct libnet_ethernet_hdr *enet;
    struct pcap_pkthdr *hdr;
    u_char *pkt;
    int rc;

    /* we pretend pkt is a const here! that's probably pretty evil. in fact we
     * never actually modify the contents of the packet (or shouldn't!), but
     * not everything (ahem, libnet) uses const. rather than copy the data to
     * avoid const, or sprinkling const all over the place, we'll just avoid
     * the warning.
     */
    if ((rc = pcap_next_ex(lph, &hdr, (const u_char **)&pkt)) != 1) {
        fprintf(stderr, "pcap_next fails, rc=%d, %s!\n", rc, pcap_geterr(lph));
        return;
    }

    if (hdr == NULL || pkt == NULL) {
        fprintf(stderr, "pcap_next returns bad data!\n");
        return;
    }

    if (hdr->len < LIBNET_ETH_H) {
        fprintf(stderr, "pcap packet too short!\n");
        return;
    }

    /* we assume everything pcap gives us is ethernet */
    enet = (struct libnet_ethernet_hdr *)pkt;

    switch (ntohs(enet->ether_type)) {
    case ETHERTYPE_ARP:
        process_arp_packet(enet, hdr->len);
        break;
    case ETHERTYPE_IP:
        process_ip_packet(enet, hdr->len);
        break;
    default:
        fprintf(stderr, "received unhandled ethernet type %d\n",
                ntohs(enet->ether_type));
        break;
    }
}

static int
init_pcap(uint32_t ip, uint32_t net)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_line;
    struct bpf_program filter;

    filter_line = malloc(4 + 5 + (4*4));
    /* this filter should give us everything we need (including arp requests) */
    sprintf(filter_line, "dst host %s",
            libnet_addr2name4(ip, LIBNET_DONT_RESOLVE));
    pcap_compile(lph, &filter, filter_line, 0, net);
    free(filter_line);

    if (pcap_setfilter(lph, &filter) == -1) {
        fprintf(stderr, "%s\n", errbuf);
        return 1;
    }

    pcap_freecode(&filter);

    return 0;
}
/* } */

static int
setup_dhcp(void)
{
    fprintf(stderr, "not currently supported\n");
    return 1;
}

static int
setup_static(char **argv)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    uint32_t mask, gw;

    dev = (char *)libnet_getdevice(lnh_link);

    /* you need to pick this IP address based on two characteristics:
     *
     * 1. it cannot be in use by another computer (including the host)
     * 2. it needs to be in the same subnet as the host
     */
    src_ip = libnet_name2addr4(lnh_link, argv[1], LIBNET_RESOLVE);
    if (src_ip == (uint32_t)-1) {
        fprintf(stderr, "invalid host name %s\n", argv[1]);
        return 1;
    }
    mask = libnet_name2addr4(lnh_link, argv[2], LIBNET_DONT_RESOLVE);
    if (mask == (uint32_t)-1) {
        fprintf(stderr, "invalid mask %s\n", argv[2]);
        return 1;
    }
    gw = libnet_name2addr4(lnh_link, argv[3], LIBNET_RESOLVE);
    if (gw == (uint32_t)-1 || ((gw & mask) != (src_ip & mask))) {
        fprintf(stderr, "invalid gateway %s\n", argv[3]);
        return 1;
    }

    if (!(lph = pcap_open_live(dev, BUFSIZ, 0, 0, pcap_errbuf))) {
        fprintf(stderr, "%s\n", pcap_errbuf);
        return 1;
    }
    if (init_pcap(src_ip, src_ip & mask))
        return 1;

    if (route_add(src_ip & mask, mask, 0)) {
        return 1;
    }
    if (route_add(0, 0, gw)) {
        return 1;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    char net_errbuf[LIBNET_ERRBUF_SIZE];

    const char *user = "nobody";
    struct passwd *pswd;

    if (!(argc == 2 && !strcasecmp(argv[1], "dhcp")) && argc != 4) {
        printf("Usage: %s <ip mask gw | dhcp>\n", argv[0]);
        return 1;
    }

    if (!(lnh_link = libnet_init(LIBNET_LINK, NULL, net_errbuf))) {
        fprintf(stderr, "%s\n", net_errbuf);
        return 1;
    }

    memcpy(src_hw, libnet_get_hwaddr(lnh_link), 6);
    libnet_seed_prand(lnh_link);
    ip_id = libnet_get_prand(LIBNET_PRu16);

    if (argc == 2 && !strcasecmp(argv[1], "dhcp")) {
        if (setup_dhcp())
            return 1;
    } else {
        if (setup_static(argv))
            return 1;
    }

    /* now that we've created all of our sockets and opened up pcap, drop root
     * privileges and run as specified user (which defaults to 'nobody'). */
    pswd = getpwnam(user);
    if (!pswd || setuid(pswd->pw_uid)) {
        fprintf(stderr, "I ain't %s! (can't drop root privs)\n", user);
        return 1;
    }

    while (1) {
        fd_set set;
        struct timeval tv, *ptv;

        FD_ZERO(&set);
        FD_SET(0, &set);
        FD_SET(pcap_fileno(lph), &set);

        ptv = timer_sleep_time(&tv);

        if (select(pcap_fileno(lph) + 1, &set, NULL, NULL, ptv) < 0)
            exit(1);

        if (FD_ISSET(0, &set))
            process_input();

        if (FD_ISSET(pcap_fileno(lph), &set))
            process_packet();

        timer_process_pending();
    }

    /* I don't think we'll ever get here, unless things go very wrong */
    return 1;
}
