#ifndef __MAIN_H__
#define __MAIN_H__

#include "ptools.h"
#include <stdio.h>

struct pcap {
        struct pcap_hdr {
                dword                 magic;
                word                  majorv;
                word                  minorv;
                dword                 thiszone;
                dword                 sigfigs;
                dword                 snaplen;
                dword                 network;
        } *hdr;
        struct pcap_rec {
                dword                 tstamp_big;
                dword                 tstamp_small;
                dword                 capd_plen;
                dword                 og_plen;
                byte                  *daten;
                struct pcap_rec       *next;
        } *recs;
};

#define         REC_CONST_SIZ sizeof(dword) * 4

extern struct errep *parse_pcap_file(byte *pcap, size_t length, struct pcap **res);

extern struct errep *print_pcap_info(struct pcap *cap);

#endif //__MAIN_H__
