#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_INPUT_SIZE (128 * 1024)

/* =========================
 * Valid aggressive callback
 * ========================= */
static void fuzz_cb(u_char *user,
                    const struct pcap_pkthdr *h,
                    const u_char *bytes)
{
    (void)user;

    /* Force header field reads */
    volatile uint32_t cap = h->caplen;
    volatile uint32_t len = h->len;
    (void)cap;
    (void)len;

    /* Touch payload edges */
    if (bytes && h->caplen) {
        ((volatile uint8_t *)bytes)[0];
        ((volatile uint8_t *)bytes)[h->caplen - 1];
    }
}

/* =========================
 * Drain strategies
 * ========================= */
static void drain_next_ex(pcap_t *p, int limit)
{
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;

    while (limit-- > 0 && (rc = pcap_next_ex(p, &hdr, &pkt)) >= 0) {
        if (rc == 1 && pkt && hdr->caplen) {
            ((volatile uint8_t *)pkt)[hdr->caplen - 1];
        }
    }

    /* EOF / error read (legal) */
    pcap_next_ex(p, &hdr, &pkt);
}

static void drain_dispatch(pcap_t *p, int cnt)
{
    pcap_dispatch(p, cnt, fuzz_cb, NULL);
}

static void drain_loop(pcap_t *p, int cnt)
{
    pcap_loop(p, cnt, fuzz_cb, NULL);
}

/* =========================
 * Main
 * ========================= */
int main(int argc, char **argv)
{
    static uint8_t buf[MAX_INPUT_SIZE];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <crash_file>\n", argv[0]);
        return 1;
    }

    /* Read crash file */
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    ssize_t len = read(fd, buf, sizeof(buf));
    close(fd);

    if (len <= 0) {
        fprintf(stderr, "Failed to read input\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    /* Multiple reopen cycles from same buffer */
    for (int round = 0; round < 2; round++) {

        FILE *fp = fmemopen(buf, len, "rb");
        if (!fp)
            break;

        pcap_t *p = pcap_fopen_offline(fp, errbuf);
        if (!p) {
            fclose(fp);
            break;
        }

        /* Aggressive but legal snaplen changes */
        int snaplen = (buf[round] << 8) | buf[(round + 1) % len];
        pcap_set_snaplen(p, snaplen);

        /* API mixing based on input */
        switch (buf[round] & 7) {
        case 0:
            drain_next_ex(p, 8);
            break;
        case 1:
            drain_dispatch(p, 4);
            drain_next_ex(p, 4);
            break;
        case 2:
            drain_loop(p, 4);
            break;
        case 3:
            drain_next_ex(p, 2);
            drain_dispatch(p, 2);
            drain_loop(p, 2);
            break;
        case 4:
            drain_dispatch(p, 8);
            break;
        case 5:
            drain_loop(p, 1);
            drain_next_ex(p, 8);
            break;
        default:
            drain_next_ex(p, 1);
            drain_dispatch(p, 1);
            break;
        }

        /* Error path probing */
        const char *e = pcap_geterr(p);
        if (e && e[0]) {
            volatile char c = e[0];
            (void)c;
        }

        pcap_close(p);
    }

    return 0;
}
