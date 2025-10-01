#include "main.h"
#include <stdlib.h>
#include <string.h>

struct errep *print_pcap_info(struct pcap *cap)
{
        struct errep *err;
        char *fnname = "print_pcap_info()";

        printf("PCAP Magic Number is : %d\n", cap -> header -> magic);
        printf("PCAP Major Version is : %d\n", cap -> header -> majorv);
        printf("PCAP Minor Version is : %d\n", cap -> header -> minorv);
        printf("PCAP Snapshot Length is : %d\n", cap -> header -> snaplen);
        printf("PCAP LinkType is : %d\n", cap -> header -> linktype);
        ERREP(err, fnname, NULL);
        return err;
}