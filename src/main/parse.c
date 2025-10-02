#include "main.h"
#include <stdlib.h>
#include <string.h>

struct errep *parse_pcap_file(byte *daten, size_t caplen, struct pcap_hdr **res, struct pcap_rec **list)
{
        struct errep *err;
        char *fnname = "parse_pcap_file()";
        struct pcap_hdr *hdr;
        struct pcap_rec *recs, *og;
        byte *limit = daten + caplen;

        if (!daten || !res || !list) {
                ERREP(err, fnname, "function was passed at least one bad argument");
                return err;
        }
        hdr = (struct pcap_hdr *) daten;
        daten += sizeof(struct pcap_hdr);
        og = recs = (struct pcap_rec *) daten;
        daten += REC_CONST_SIZ;
        if ((recs -> daten = malloc(sizeof(byte) * recs -> capd_plen)) == NULL) {
                ERREP(err, fnname, "pcap record data could not be allocated memory");
                return err;
        }
        memcpy(recs -> daten, daten, recs -> capd_plen);
        daten += recs -> capd_plen;
        while (daten < limit) {
                recs = recs -> next;
                recs = (struct pcap_rec *) daten;
                daten += REC_CONST_SIZ;
                if ((recs -> daten = malloc(sizeof(byte) * recs -> capd_plen)) == NULL) {
                        ERREP(err, fnname, "pcap record data could not be allocated memory");
                        return err;
                }
                memcpy(recs -> daten, daten, recs -> capd_plen);
                daten += recs -> capd_plen;
        }
        *res = hdr;
        *list = recs;
        ERREP(err, fnname, NULL);
        return err;
}
