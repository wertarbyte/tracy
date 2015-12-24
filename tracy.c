#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <libnet/libnet-functions.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define IPv6_ETHERTYPE 0x86DD

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip6 {
	uint32_t ip_vtcfl;
	uint16_t ip_len;
	uint8_t	ip_nxt;
	uint8_t	ip_hl;
	struct in6_addr ip_src;
	struct in6_addr ip_dst;
};

#define IP_V(ip) (ntohl((ip)->ip_vtcfl) >> 28)

struct in6_addr sink_addr;
uint8_t sink_addr_len = 0;

libnet_t *net_h;

void drop_root(void) {
	/* use nobody */
	int userid = 65534;
	int groupid = 65534;
	if (getuid() == 0) {
		/* process is running as root, drop privileges */
		if (setgid(groupid) != 0) {
			fprintf(stderr, "setgid: Unable to drop group privileges: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (setuid(userid) != 0) {
			fprintf(stderr, "setuid: Unable to drop user privileges: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

void genResponse(const struct in6_addr *target_addr, const struct in6_addr *client_addr, uint8_t hl, uint8_t *data, size_t len) {
	struct in6_addr router_addr;
	char router[INET6_ADDRSTRLEN];
	char target[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	memcpy(&router_addr, target_addr, sizeof(router_addr));

	libnet_ptag_t icmp, ip;
	if (hl >= ((uint8_t*)&router_addr)[15]) {
		/* target reached */
		icmp = libnet_build_icmpv6_unreach(
			0x1,
			0x1,
			0,
			data,
			len,
			net_h,
			0
		       );
	} else {
		/* synthesize router address */
		((uint8_t*)&router_addr)[15] = hl;
		icmp = libnet_build_icmpv6_unreach(
			0x3,
			0x0,
			0,
			data,
			len,
			net_h,
			0
		       );
	}

	size_t ip_payload_len = LIBNET_ICMPV6_H + len;
	ip = libnet_build_ipv6(
		0, 0,
		ip_payload_len,
		IPPROTO_ICMP6, 64,
		*(struct libnet_in6_addr*)&router_addr,
		*(struct libnet_in6_addr*) client_addr,
		NULL,
		0,
		net_h,
		0
	       );
	inet_ntop(AF_INET6, &router_addr, router, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, target_addr, target, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, client_addr, dst, INET6_ADDRSTRLEN);
	printf("Sending response to '%s' from '%s' (target: '%s')\n", dst, router, target);
	libnet_write(net_h);
	libnet_clear_packet(net_h);
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip6 *ip;

	int size_ip;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	if (ntohs(ethernet->ether_type) != IPv6_ETHERTYPE) {
		return;
	}
	
	ip = (struct sniff_ip6*)(packet + SIZE_ETHERNET);
	if (IP_V(ip) != 6) {
		return;
	}

	genResponse(&ip->ip_dst, &ip->ip_src, ip->ip_hl, (uint8_t *)ip, header->caplen - SIZE_ETHERNET);
}

uint8_t parse_net(char *str, struct in6_addr *addr, uint8_t *len) {
	char *l = strrchr(str, '/');
	if (!l) return 0;
	if (sscanf(l, "/%hu", len) != 1 || *len > 128) {
		return 0;
	}
	*l = '\0';
	if (inet_pton(AF_INET6, str, addr) != 1) {
		return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{

	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	struct bpf_program fp;

	char errmsg[LIBNET_ERRBUF_SIZE];
	if (argc == 3) {
		dev = argv[1];
	} else {
		fprintf(stderr, "Please specify device and network address, e.g.\n");
		fprintf(stderr, "  tracy eth0 cafe:beef:babe::/64\n");
		exit(EXIT_FAILURE);
	}

	if (parse_net(argv[2], &sink_addr, &sink_addr_len) != 1) {
		fprintf(stderr, "Couldn't parse network: %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	net_h = libnet_init(LIBNET_RAW6, NULL, &errmsg[0]);

	if (!net_h) {
		fprintf(stderr, "Unable to initialize libnet: %s\n\n", errmsg);
		exit(EXIT_FAILURE);
	}

	/* build filter expression */
	/* ip6 and dst net NETWORK/LENGTH and not src net NETWORK/LENGTH */
	size_t filter_str_len = 0;
	filter_str_len += 4; // "ip6 "
	filter_str_len += 4; // "and "
	filter_str_len += 4; // "dst "
	filter_str_len += 4; // "net "
	filter_str_len += INET6_ADDRSTRLEN+1+3+1; // "NETWORK/LENGTH "
	filter_str_len += 4; // "and "
	filter_str_len += 4; // "not "
	filter_str_len += 4; // "src "
	filter_str_len += 4; // "net "
	filter_str_len += INET6_ADDRSTRLEN+1+3; // "NETWORK/LENGTH"

	char net_str[INET6_ADDRSTRLEN];
	char pref_str[5];
	inet_ntop(AF_INET6, &sink_addr, &net_str[0], INET6_ADDRSTRLEN);
	sprintf(&pref_str[0], "/%hu", sink_addr_len);

	char filter_exp[filter_str_len+1];
	filter_exp[0] = '\0';
	strcat(&filter_exp[0], "ip6 and dst net ");
	strcat(&filter_exp[0], &net_str[0]);
	strcat(&filter_exp[0], &pref_str[0]);
	strcat(&filter_exp[0], " and not src net ");
	strcat(&filter_exp[0], &net_str[0]);
	strcat(&filter_exp[0], &pref_str[0]);
	
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 10, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	drop_root();

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}

