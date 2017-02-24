#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define MAXBYTES2CAPTURE 2048

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	int i = 0, *counter = (int *)arg;

	printf("Packet Count: %d\n", ++(*counter));
	printf("Received Packet Size: %d\n", pkthdr->len);
	printf("Payload:\n");
	for (i = 0; i < pkthdr->len; i++) {
		if (isprint(packet[i]))
			printf("%c ", packet[i]);
		else
			printf(". ");
		if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
			printf("\n");
	}
	return;
}

int main(int argc, char** argv) {

	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *desrc = NULL;
	pcap_t *adhandle;

	int i = 0, inum = 0, count = 0;
	char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);


	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum<1 || inum>i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}



	
	desrc = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);

	pcap_loop(desrc, -1, processPacket, (u_char *)&count);

	return 0;
}