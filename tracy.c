/*
 *  Tracy - generate simulated routing paths
 *
 *  by Stefan Tomanek <stefan@datenbruch.de>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>

#include <pcap.h>
#include <pcap/sll.h>

#include <libnet.h>
#include <libnet/libnet-headers.h>
#include <libnet/libnet-functions.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define IPv6_ETHERTYPE 0x86DD

/* match IPv6 directed at (but not originating from) our network
 * of every protocol except icmp6 (but allow ICMP6 echo requests)
 */
#define FILTER_TMPL "(" \
                     "ip6 " \
                     "and dst net %s/%hu " \
                     "and not src net %s/%hu " \
                     "and (not icmp6 or (icmp6 and ip6[40]=128))" \
                    ")" \
                    " and (%s)"

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
short unsigned int sink_addr_len = 0;

libnet_t *net_h;

int link_type;

void drop_root(char *user) {
	struct passwd *pw = getpwnam(user);
	if (!pw) {
		fprintf(stderr, "Unable to lookup user '%s'\n", user);
		exit(EXIT_FAILURE);
	}
	if (setgid(pw->pw_gid) != 0) {
		fprintf(stderr, "setgid: Unable to drop group privileges: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (setuid(pw->pw_uid) != 0) {
		fprintf(stderr, "setuid: Unable to drop user privileges: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void gen_response(const struct in6_addr *target_addr,
                  const struct in6_addr *client_addr,
                 uint8_t hl,
                 uint8_t *data,
                 size_t len) {
	struct in6_addr router_addr;
	char router[INET6_ADDRSTRLEN];
	char target[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	memcpy(&router_addr, target_addr, sizeof(router_addr));

	if (hl >= ((uint8_t*)&router_addr)[15]) {
		/* target reached */
		libnet_build_icmpv6_unreach(
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
		libnet_build_icmpv6_unreach(
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
	libnet_build_ipv6(
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

	time_t now;
	time(&now);
	struct tm* tm_info = localtime(&now);
#define TS_MAX 32
	char ts[TS_MAX+1];
	strftime(ts, TS_MAX, "%Y-%m-%d %H:%M:%S", tm_info);

	printf("%s Sending response to '%s' from '%s' (target: '%s')\n", ts, dst, router, target);
	libnet_write(net_h);
	libnet_clear_packet(net_h);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ip6 *ip;
	int ip_size = 0;

	/* define ethernet header */
	if (link_type == DLT_EN10MB) {
		struct sniff_ethernet *ll = (struct sniff_ethernet*)(packet);
		if (ntohs(ll->ether_type) != IPv6_ETHERTYPE) {
			return;
		}
		ip = (struct sniff_ip6*)(packet + sizeof(struct sniff_ethernet));
		ip_size = header->caplen - sizeof(struct sniff_ethernet);
	} else if (link_type == DLT_LINUX_SLL) {
		struct sll_header *ll = (struct sll_header*)(packet);
		if (ntohs(ll->sll_protocol) != IPv6_ETHERTYPE) {
			return;
		}
		ip = (struct sniff_ip6*)(packet + SLL_HDR_LEN);
		ip_size = header->caplen - SLL_HDR_LEN;
	}
	
	if (ip_size < 40 || IP_V(ip) != 6) {
		return;
	}

	gen_response(&ip->ip_dst, &ip->ip_src,
	             ip->ip_hl, (uint8_t *)ip,
	             ip_size);
}

uint8_t parse_net(char *str, struct in6_addr *addr, short unsigned int *len) {
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

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	char errmsg[LIBNET_ERRBUF_SIZE];

	char *dev = "any";
	char *subnet = NULL;
	char *user = NULL;
	// this is a placeholder that is always true
	char *filter_extra = "1=1";
	// we usually do not need promiscious mode
	int use_promisc = 0;

	int c;
	while ((c = getopt (argc, argv, "i:ps:u:g:f:")) != -1) {
		switch (c) {
			case 'i':
				dev = optarg;
				break;
			case 'p':
				use_promisc = 1;
				break;
			case 's':
				subnet = optarg;
				break;
			case 'u':
				user = optarg;
				break;
			case 'f':
				filter_extra = optarg;
				break;
		}
	}

	if (!dev || !subnet) {
		fprintf(stderr, "Please specify subnet address, e.g.\n");
		fprintf(stderr, "  tracy -s cafe:beef:babe::/64\n");
		exit(EXIT_FAILURE);
	}

	if (parse_net(subnet, &sink_addr, &sink_addr_len) != 1) {
		fprintf(stderr, "Couldn't parse network: %s\n", subnet);
		exit(EXIT_FAILURE);
	}

	net_h = libnet_init(LIBNET_RAW6, NULL, &errmsg[0]);

	if (!net_h) {
		fprintf(stderr, "Unable to initialize libnet: %s\n\n", errmsg);
		exit(EXIT_FAILURE);
	}

	/* build filter expression */
	// we ignore the space occupied by the placeholders
	size_t filter_str_len = strlen(FILTER_TMPL)
	                        + 2 * (INET6_ADDRSTRLEN + 3)
	                        + strlen(filter_extra);

	char net_str[INET6_ADDRSTRLEN + 1];
	inet_ntop(AF_INET6, &sink_addr, net_str, INET6_ADDRSTRLEN);
	char *filter_exp = malloc(filter_str_len);
	if (!filter_exp) {
		fprintf(stderr, "Allocating memory for filter expression: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	int n = sprintf(filter_exp, FILTER_TMPL,
	                net_str, sink_addr_len,
	                net_str, sink_addr_len,
	                filter_extra);

	if (n < 0 || n > filter_str_len) {
		fprintf(stderr, "Error constructing pcap filter string.\n");
		exit(EXIT_FAILURE);
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, use_promisc, 10, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if (user) {
		drop_root(user);
	}

	/* make sure we're capturing on an usable device */
	link_type = pcap_datalink(handle);
	if (link_type != DLT_EN10MB && link_type != DLT_LINUX_SLL) {
		fprintf(stderr, "%s is not using a usable capture format\n", dev);
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

