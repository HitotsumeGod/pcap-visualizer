#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

void usage(void);

int main(int argc, char *argv[])
{
        struct errep *err;
        struct pcap cap;
        struct pcap_hdr *hdr;
        struct pcap_rec *recs;
        FILE *pcap;
        byte *daten;
        int flen;

        if ((pcap = fopen(argv[1], "rb")) == NULL) {
                if (errno == ENOENT)
                        fprintf(stderr, "%s\n", "You must provide a valid file path!");
                else
                        perror("main(): fopen() err");
                return EXIT_FAILURE;
        }
        fseek(pcap, 0, SEEK_END);
        flen = ftell(pcap);
        rewind(pcap);
        if ((daten = malloc(sizeof(byte) * flen)) == NULL) {
                perror("main(): malloc() err");
                return EXIT_FAILURE;
        }
        if (fread(daten, flen, 1, pcap) != flen)
                if (!feof) {
                        perror("main(): fread() err");
                        return EXIT_FAILURE;
                }
        if ((err = parse_pcap_file(daten, flen, &hdr, &recs)) -> msg != NULL) {
                fprintf(stderr, "%s", ptools_format_errors(err));
                return EXIT_FAILURE;
        }
        cap.header = hdr;
        cap.records = recs;
        if ((err = print_pcap_info(&cap)) -> msg != NULL) {
                fprintf(stderr, "%s", ptools_format_errors(err));
                return EXIT_FAILURE;
        }
        free(daten);
        return EXIT_SUCCESS;
}

void usage(void)
{
}