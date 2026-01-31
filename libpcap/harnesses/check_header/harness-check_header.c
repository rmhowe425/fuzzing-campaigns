#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_INPUT_SIZE   (128 * 1024)
#define MAX_ITERATIONS   1000

int main(void) {
    static uint8_t buf[MAX_INPUT_SIZE];

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(MAX_ITERATIONS)) {

        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len < 16)
            continue;

        char errbuf[PCAP_ERRBUF_SIZE];
        memset(errbuf, 0, sizeof(errbuf));

        /* ---- In-memory file, no I/O ---- */
        FILE *fp = fmemopen(buf, len, "rb");
        if (!fp)
            continue;

        /* ---- Open capture (pcap OR pcapng) ---- */
        pcap_t *p = pcap_fopen_offline(fp, errbuf);
        if (!p) {
            /* libpcap did NOT take ownership */
            fclose(fp);
            continue;
        }

        /* ---- Aggressive but legal snaplen churn ---- */
        int snaplen = 16 + (buf[0] << 8);
        if (snaplen < 16) snaplen = 16;
        if (snaplen > 65535) snaplen = 65535;
        pcap_set_snaplen(p, snaplen);

        /* ---- Drain packets fully ---- */
        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int rc;

        while ((rc = pcap_next_ex(p, &hdr, &pkt)) == 1) {

            /* Touch header fields to force reads */
            volatile uint32_t caplen = hdr->caplen;
            volatile uint32_t plen   = hdr->len;
            (void)caplen;
            (void)plen;

            /* Optional snaplen mutation mid-stream (allowed) */
            if (buf[1] & 0x01) {
                int new_snap = 32 + ((buf[2] << 4) & 0x3fff);
                if (new_snap > 65535) new_snap = 65535;
                pcap_set_snaplen(p, new_snap);
            }
        }

        /* ---- Error path coverage ---- */
        if (rc == -1) {
            (void)pcap_geterr(p);
        }

        /* ---- Clean shutdown ---- */
        /* pcap_close() WILL fclose(fp) internally */
        pcap_close(p);
    }

    return 0;
}
