#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

void usage() {
	printf("syntax : pcap_test <interface>\n");
	printf("sample : pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if(argc != 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2) break;
		uint8_t version = *(uint8_t*) (packet + 14);
		version >>= 4;
		if(version != 4) continue;
		printf("Ethernet Header's source / destination mac address : ");
		for(int i = 0; i < 2; i++) {
			for(int j = 0; j < 6; j++) {
				if(j == 0) printf("(");
				printf("%x", *(uint8_t*) (packet + 6 * i + j));
				printf(j < 5 ? ":" : ")");
			}
			printf(i == 0 ? " / " : "\n");
		}
		printf("IP Header's source / destination ip address : ");
		for(int i = 0; i < 2; i++) {
			for(int j = 0; j < 4; j++) {
				if(j == 0) printf("(");
				printf("%u", *(uint8_t*) (packet + 4 * i + 26 + j));
				printf(j < 3 ? "." : ")");
			}
			printf(i == 0 ? " / " : "\n");
		}
		printf("TCP Header's source / destination port number : ");
		for(int i = 0; i < 2; i ++) {
			printf("%u", ntohs( *(uint16_t*) (packet + 2 * i + 34)));
			printf(i == 0 ? " / " : "\n");
		}
		int datalen = ntohs( *(uint16_t*) (packet + 16));
		int ihl = *(uint8_t*) (packet + 14);
		ihl = (ihl & 0x0F) << 2;
		int thl = *(uint8_t*) (packet + 46);
		thl = (thl & 0xF0) >> 2;
		if(datalen - ihl - thl > 0) printf("Payload : 0x%x\n", ntohl( *(uint32_t*) (packet + 54)));
		else printf("There's no Payload\n");
	}

	pcap_close(handle);
	return 0;
}
