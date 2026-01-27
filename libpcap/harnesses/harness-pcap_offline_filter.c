#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define MAX_INPUT_SIZE    8192
#define MAX_FILTER_SIZE   2048
#define MAX_PACKET_SIZE   4096
#define MAX_ITERATIONS    5000

/* Diverse DLTs exercising distinct runtime decode paths */
static const int dlt_table[] = {
    DLT_RAW,
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_NULL,
    DLT_LOOP,
    DLT_IPV4,
    DLT_IPV6,
};

#define NUM_DLTs (sizeof(dlt_table) / sizeof(dlt_table[0]))

static pcap_t *pcaps[NUM_DLTs];

static inline int pick_dlt_idx(uint8_t b) {
    return b % NUM_DLTs;
}

static inline uint32_t pick_u32(const uint8_t *buf, size_t len, size_t off) {
    if (off + 4 > len)
        return 0;
    uint32_t v;
    memcpy(&v, buf + off, 4);
    return v;
}

int main(void) {
    uint8_t buf[MAX_INPUT_SIZE];

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    /* Initialize persistent dead pcaps (one per DLT) */
    for (size_t i = 0; i < NUM_DLTs; i++) {
        pcaps[i] = pcap_open_dead(dlt_table[i], 65535);
    }

    while (__AFL_LOOP(MAX_ITERATIONS)) {

        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len < 8)
            continue;

        /* --- Control bytes --- */
        uint8_t flags    = buf[0];
        uint8_t dlt_sel  = buf[1];
        uint8_t snap_sel = buf[2];
        uint8_t split_sel = buf[3];

        size_t off = 4;

        /* --- Select persistent pcap --- */
        int dlt_idx = pick_dlt_idx(dlt_sel);
        pcap_t *pcap = pcaps[dlt_idx];
        if (!pcap)
            continue;

        /* --- Snaplen variation --- */
        int snaplen = 64 + ((int)snap_sel << 8);
        if (snaplen > 65535)
            snaplen = 65535;

        pcap_set_snaplen(pcap, snaplen);

        /* --- Filter extraction (ALWAYS NUL-TERMINATED) --- */
        size_t remaining = len - off;
        if (remaining == 0)
            continue;

        /* Bias filter/packet split using control byte */
        size_t filter_len = remaining / 2;
        if (split_sel & 0x01)
            filter_len = remaining / 3;
        if (split_sel & 0x02)
            filter_len = remaining * 2 / 3;

        if (filter_len > MAX_FILTER_SIZE)
            filter_len = MAX_FILTER_SIZE;
        if (filter_len == 0)
            filter_len = remaining < MAX_FILTER_SIZE ? remaining : MAX_FILTER_SIZE;

        char filter[MAX_FILTER_SIZE + 1];
        memcpy(filter, buf + off, filter_len);
        filter[filter_len] = '\0';  /* REQUIRED */

        off += filter_len;
        if (off >= (size_t)len)
            continue;

        /* --- Packet bytes --- */
        size_t packet_len = len - off;
        if (packet_len > MAX_PACKET_SIZE)
            packet_len = MAX_PACKET_SIZE;

        uint8_t packet[MAX_PACKET_SIZE];
        memcpy(packet, buf + off, packet_len);

        /* --- Compile filter --- */
        struct bpf_program prog;
        memset(&prog, 0, sizeof(prog));

        int optimize = (flags & 0x01) ? 1 : 0;

        bpf_u_int32 netmask =
            (flags & 0x02) ? 0xFFFFFFFF :
            (flags & 0x04) ? 0xFFFFFF00 :
            pick_u32(buf, len, 8);

        if (pcap_compile(pcap, &prog, filter, optimize, netmask) != 0) {
            (void)pcap_geterr(pcap);
            continue;
        }

        /* --- Prepare packet header --- */
        struct pcap_pkthdr hdr;
        memset(&hdr, 0, sizeof(hdr));

        hdr.caplen = packet_len;
        hdr.len    = packet_len;

        /* Controlled length inconsistencies (API-respecting) */
        if ((flags & 0x08) && packet_len > 0)
            hdr.len += packet_len;

        if ((flags & 0x10) && hdr.len > 0)
            hdr.caplen = hdr.len - 1;

        if ((flags & 0x20) && hdr.caplen < packet_len)
            hdr.caplen = packet_len;

        /* --- Execute filter multiple times --- */
        int rounds = 1 + (flags & 0x03);
        for (int i = 0; i < rounds; i++) {
            (void)pcap_offline_filter(&prog, &hdr, packet);
        }

        pcap_freecode(&prog);
    }

    for (size_t i = 0; i < NUM_DLTs; i++) {
        if (pcaps[i])
            pcap_close(pcaps[i]);
    }

    return 0;
}
