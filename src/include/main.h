#ifndef __MAIN_H__
#define __MAIN_H__

#include "ptools.h"
#include <stdio.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

struct network_dgram {
        union {
                struct iphdr            *iph;
                struct ip6hdr           *ip6h;
        } *hdr;
        struct {
                union {
                        struct icpmhdr          *icmph;
                        struct icmp6hdr         *icmp6h;
                        struct tcphdr           *tcph;
                        struct udphdr           *udph;
                } *hdr;
                byte        *body;
        } transport_packet;
};

union linklayer_frame {
        struct {
                struct {
                        byte            proto_vers:2;
                        byte            type:2;
                        byte            subtype:4;
                        byte            to_ds:1;
                        byte            from_ds:1;
                        byte            more_frag:1;
                        byte            retry:1;
                        byte            power_mng:1;
                        byte            more_data:1;
                        byte            prot_frame:1;
                        byte            order:1;
                } *frame_control;
                word                    duration;
                byte                    addr1[6];
                byte                    addr2[6];
                byte                    addr3[6];
                word                    seq_ctrl;
                byte                    addr4[6];
                struct network_dgram    *body;
                dword                   fcs;
        } _80211_frame;
        struct {
                struct ethhdr           *hdr;
                struct network_dgram    *body;
                dword                   crc;
        } etherii_frame;
};

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
