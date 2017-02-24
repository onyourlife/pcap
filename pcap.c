#include <stdio.h>
#include <pcap.h>
#include <Winsock2.h>
#include <WS2tcpip.h>

#define ETH_A_LEN 6

/* Structure of Ethernet Header */
typedef struct ether_hdr
{
	unsigned char   h_dest[ETH_A_LEN];
	unsigned char   h_source[ETH_A_LEN];
	unsigned short  h_proto;
} ether_header;

/* Structure of IP Address */
typedef struct ip_addr {
	u_char a_class;
	u_char b_class;
	u_char c_class;
	u_char d_class;
} ip_address;

/* Structure of IP Header */
typedef struct ip_hdr {
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flag_offset;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address saddr;
	ip_address daddr;
	u_int op_pad;
} ip_header;

/* Structure of TCP Header */
typedef struct tcp_hdr {
	u_short sport;
	u_short dport;
	u_int seqnum;
	u_int acknum;
	u_char hlen;
	u_char flags;
	u_short winsize;
	u_short crc;
	u_short urgptr;
} tcp_header;

void parse_eth_packet(const u_char* buffer);
void parse_ip_packet(const u_char* buffer);
void parse_tcp_packet(const u_char* buffer);
void packet_handler(u_char, const struct pcap_pkthdr, const u_char);

int main(int argc, char** argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;

	pcap_t *adhandle;

	pcap_dumper_t *dumpfile;

	int inum;
	int i = 0, res = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	if (argc != 2) {
		printf("Usage: %s filename", argv[0]);
		return -1;
	}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	/* Select the network interface */
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,	// name of the device
		65536,							// portion of the packet to capture. 
										// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,		// promiscuous mode
		1000,							// read timeout
		NULL,							// authentication on the remote machine
		errbuf							// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Open the dump file */
	dumpfile = pcap_dump_open(adhandle, argv[1]);
	
	if (dumpfile == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}

	printf("\nListening on %s... Press Ctrl+C to stop...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);

	/* Handle error */
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	return 0;
}

/* Parsing Ethernet packet */
void parse_eth_packet(const u_char* buffer) {
	ether_header *eth = (ether_header *)buffer;
	printf("[MAC] %.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
		eth->h_source[0],
		eth->h_source[1],
		eth->h_source[2],
		eth->h_source[3],
		eth->h_source[4],
		eth->h_source[5],

		eth->h_dest[0],
		eth->h_dest[1],
		eth->h_dest[2],
		eth->h_dest[3],
		eth->h_dest[4],
		eth->h_dest[5]
	);
}

/* Parsing IP packet */
void parse_ip_packet(const u_char* buffer) {
	ip_header *ip = (ip_header *)(buffer + sizeof(ether_header));
	printf("[IP] %3d.%3d.%3d.%3d -> %3d.%3d.%3d.%3d\n",
		ip->saddr.a_class,
		ip->saddr.b_class,
		ip->saddr.c_class,
		ip->saddr.d_class,

		ip->daddr.a_class,
		ip->daddr.b_class,
		ip->daddr.c_class,
		ip->daddr.d_class);
}

/* Parsing TCP packet */
void parse_tcp_packet(const u_char* buffer) {
	tcp_header *tcp = (tcp_header *)(buffer + sizeof(ether_header) + sizeof(tcp_header));
	printf("[Port] %d -> %d\n", ntohs(tcp->sport), ntohs(tcp->dport));
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	time_t local_tv_sec;
	
	char timestr[16];

	/* Convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* Call parse functions */
	printf("----------------------------------------------------------\n");
	printf("%s [%.6d] len:%d\n", timestr, header->ts.tv_usec, header->len);

	parse_eth_packet(pkt_data);	// Parsing Ethernet packet
	parse_ip_packet(pkt_data);	// Parsing IP packet
	parse_tcp_packet(pkt_data);	// Parsing TCP packet

	/* Dump network packet */
	pcap_dump(dumpfile, header, pkt_data);
}
