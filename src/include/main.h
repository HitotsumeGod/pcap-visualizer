#ifndef __MAIN_H__
#define __MAIN_H__

#include "ptools.h"
#include <stdio.h>

struct pcap_hdr {
        dword magic;
        word majorv;
        word minorv;
        dword res1;
        dword res2;
        dword snaplen;
        byte fcs:3;
        byte f:1;
        word zero:12;
        word linktype;
};

struct pcap_rec {
        dword timestamp_big;
        dword timestamp_small;
        dword capd_plen;
        dword og_plen;
        byte *daten;
        struct pcap_rec *next;
};

struct pcap {
        struct pcap_hdr *header;
        struct pcap_rec *records;
};

#define         REC_CONST_SIZ sizeof(dword) * 4

extern struct errep *parse_pcap_file(byte *pcap, size_t length, struct pcap_hdr **header, struct pcap_rec **records);

extern struct errep *print_pcap_info(struct pcap *cap);

#endif //__MAIN_H__