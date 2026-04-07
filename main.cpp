#include <cstdio>
#include <pcap.h>
#include <netinet.h>
#include "hdr.h"
#include "getmac.h"

typedef struct{
	eth_hdr eth;
	arp_hdr arp;
}eth_arp_hdr;

void usage(){
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool send_packet(pcap_t* pcap, eth_arp_hdr* packet){
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), sizeof(eth_arp_hdr));
	if(res != 0){
		printf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return false;
	}
	return true;
}

int main(int argc, char* argv[]){
	if(argc&1 || argc<4){
		usage();
		return EXIT_FAILURE;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if(pcap == nullptr){
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	eth_arp_hdr packet;
	
	if(!get_mac(dev, &packet.eth.smac)){
		printf("Wrong interface\n");
		return EXIT_FAILURE;
	}
	memset(packet.eth.dmac, 0xFF, MAC_LEN); // broadcast
	packet.eth.type = htons(0x0806); // ARP
	
	packet.arp.htype = htons(1);
	packet.arp.ptype = htons(0x0800);
	packet.arp.hlen = MAC_LEN;
	packet.arp.plen = 4;
	packet.arp.op = 1;

	if(!send_packet(pcap, &packet)) return -1;

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet_ans;
		int res = pcap_next_ex(pcap, &header, &packet_ans);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res = PCAP_ERROR_BREAK){
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		eth_hdr* eth_ans = (eth_hdr*)packet_ans;
		if(ntohs(eth_ans->type) != 0x0806) continue;
		
		arp_hdr* arp_ans = (arp_ans*)(packet_ans + sizeof(eth_hdr));
		if(ntohs(arp_ans->op != 2)) continue;

		if(arp_ans->spa == my_ip){
			memcpy(packet.arp.tmac, arp_ans->smac, MAC_LEN);
			break;
		}
	}

	

