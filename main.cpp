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
	
	packet.eth.smac = Mac::get_mac(dev);
	packet.eth.dmac = Mac("FF:FF:FF:FF:FF:FF"); // broadcast
	packet.eth.type = htons(eth_hdr::ARP);
	
	packet.arp.htype = htons(arp_hdr::ETHER);
	packet.arp.ptype = htons(eth_hdr::IP4);
	packet.arp.hlen = Mac::Size;
	packet.arp.plen = Ip::Size;
	packet.arp.op = arp_hdr::Request;
	packet.arp.smac = packet.eth.smac;
	packet.arp.sip = Ip::get_ip(dev);
	packet.arp.tmac = Mac("00:00:00:00:00:00");
	packet.arp.tip = Ip(argv[i]); // Sender ip

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
		if(ntohs(eth_ans->type) != eth_hdr::ARP) continue;
		
		arp_hdr* arp_ans = (arp_ans*)(packet_ans + sizeof(eth_hdr));
		if(ntohs(arp_ans->op != arp_hdr::Reply)) continue;

		if(arp_ans->spa == my_ip){
			packet.eth.dmac = arp_ans->smac;
			packet.arp.tmac = arp_ans->smac;
			break;
		}
	}
	packet.arp.sip = Ip(argv[i*2+1]); // Target ip
	
	pcap_close(pcap);

	return 0;
}	
	
