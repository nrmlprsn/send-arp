#pragma once

#include <stdint.h>

typedef struct{
	uint8_t dmac[6];
	uint8_t smac[6];
	uint16_5 type;
}eth_hdr;

typedef struct{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t op;
	uint8_t smac[6];
	uint32_t sip;
	uint8_t tmac[6];
	uint32_t tip;
}arp_hdr;
