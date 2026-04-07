#pragma once

#include <cstring>
#include <stdint.h>
#include <arpa/inet.h>
#include <string>

struct Mac{
	static constexpr int Size = 6;
	uint8_t mac[Size];
	
	// constructor
	Mac(){}
	Mac(const uint8_t* r) {memcpy(this->mac, r, Size);}
	Mac(const std::string& r);
	
	// assign operator
	Mac& operator = (const Mac& r){memcpy(this->mac, r.mac, Size);return *this;}
	
	// bool operator
	bool operator == (const Mac& r) const{return memcmp(mac, r.mac, Size) == 0;}
	bool operator != (const Mac& r) const{return memcmp(mac, r.mac, Size) != 0;}

	static Mac get_mac(const std::string& iface);
};

struct Ip{
	static const int Size = 4;
	uint32_t ip;
	
	// constructor
	Ip(){}
	Ip(const uint32_t r) : ip(r){}
	Ip(const std::string r){ip = inet_addr(r.c_str());};
	
	// bool operator
	bool operator == (const Ip& r) const{return ip == r.ip;}

	static Ip get_ip(const std::string& iface);
};

#pragma pack(push, 1)
typedef struct{
	Mac dmac;
	Mac smac;
	uint16_t type;

	// type
        enum: uint16_t {
                IP4 = 0x0800,
                ARP = 0x0806,
                IP6 = 0x86DD
        };
}eth_hdr;

typedef struct{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t op;
	Mac smac;
	Ip sip;
	Mac tmac;
	Ip tip;

	// htype
        enum: uint16_t {
                NETROM = 0, // from KA9Q: NET/ROM pseudo
                ETHER = 1, // Ethernet 10Mbps
                EETHER = 2, // Experimental Ethernet
                AX25 = 3, // AX.25 Level 2
                PRONET = 4, // PROnet token ring
                CHAOS = 5, // Chaosnet
                IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
                ARCNET = 7, // ARCnet
                APPLETLK = 8, // APPLEtalk
                LANSTAR = 9, // Lanstar
                DLCI = 15, // Frame Relay DLCI
                ATM = 19, // ATM
                METRICOM = 23, // Metricom STRIP (new IANA id)
                IPSEC = 31 // IPsec tunnel
        };

        // op
        enum: uint16_t {
                Request = 1, // req to resolve address
                Reply = 2, // resp to previous request
                RevRequest = 3, // req protocol address given hardware
                RevReply = 4, // resp giving protocol address
                InvRequest = 8, // req to identify peer
                InvReply = 9 // resp identifying peer
        };
}arp_hdr;
#pragma pack(pop)
