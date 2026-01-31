#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_OUT  (128 * 1024)

/* PCAP magic values */
#define PCAP_MAGIC      0xa1b2c3d4
#define PCAP_MAGIC_SWAP 0xd4c3b2a1
#define PCAPNG_MAGIC    0x0A0D0D0A

static uint8_t *out_buf;
static size_t   out_size;

/* =========================
 * AFL hooks
 * ========================= */
void afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    srand(seed);
    out_buf = malloc(MAX_OUT);
    if (!out_buf)
        abort();
}

void afl_custom_deinit(void *afl) {
    (void)afl;
    free(out_buf);
}

/* =========================
 * Helpers
 * ========================= */
static inline uint32_t rnd(uint32_t n) {
    return n ? (uint32_t)(rand() % n) : 0;
}

static inline int one_in(int n) {
    return n && ((rand() % n) == 0);
}

static inline uint32_t rd32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static inline void wr32(uint8_t *p, uint32_t v) {
    memcpy(p, &v, 4);
}

/* =========================
 * PCAP mutations
 * ========================= */
static void mutate_pcap(uint8_t *buf, size_t len) {
    if (len < 24)
        return;

    /* global header */
    if (one_in(2)) {
        /* snaplen */
        wr32(buf + 16, rnd(0x10000));
    }

    if (one_in(3)) {
        /* linktype */
        wr32(buf + 20, rnd(300));
    }

    /* per-packet records */
    size_t off = 24;
    while (off + 16 <= len) {
        uint32_t caplen = rd32(buf + off + 8);
        uint32_t plen   = rd32(buf + off + 12);

        if (caplen > plen && one_in(2))
            wr32(buf + off + 8, plen);

        if (one_in(4))
            wr32(buf + off + 12, rnd(0x10000));

        if (caplen == 0 || off + 16 + caplen > len)
            break;

        off += 16 + caplen;
        if (one_in(6))
            break;
    }
}

/* =========================
 * PCAPNG mutations
 * ========================= */
static void mutate_pcapng(uint8_t *buf, size_t len) {
    size_t off = 0;

    while (off + 12 <= len) {
        uint32_t block_type = rd32(buf + off);
        uint32_t block_len  = rd32(buf + off + 4);

        if (block_len < 12 || off + block_len > len)
            break;

        /* Section Header Block */
        if (block_type == 0x0A0D0D0A && one_in(2)) {
            /* Byte-order magic */
            wr32(buf + off + 8, rnd(2) ? 0x1A2B3C4D : 0x4D3C2B1A);
        }

        /* Interface Description Block */
        if (block_type == 1 && one_in(2)) {
            /* snaplen */
            wr32(buf + off + 12, rnd(0x10000));
        }

        /* Enhanced Packet Block */
        if (block_type == 6 && block_len >= 32) {
            if (one_in(2)) {
                /* captured len */
                wr32(buf + off + 20, rnd(0x10000));
            }
            if (one_in(3)) {
                /* packet len */
                wr32(buf + off + 24, rnd(0x10000));
            }
        }

        off += block_len;
        if (one_in(6))
            break;
    }
}

/* =========================
 * AFL fuzz entry
 * ========================= */
size_t afl_custom_fuzz(void *afl,
                       uint8_t *buf,
                       size_t len,
                       uint8_t **out,
                       uint8_t *add_buf,
                       size_t add_len,
                       size_t max_size) {
    (void)afl;
    (void)add_buf;
    (void)add_len;

    if (!buf || len < 4 || max_size == 0) {
        *out = buf;
        return len;
    }

    if (len > MAX_OUT)
        len = MAX_OUT;

    memcpy(out_buf, buf, len);
    out_size = len;

    uint32_t magic = rd32(out_buf);

    /* Decide format */
    if (magic == PCAP_MAGIC || magic == PCAP_MAGIC_SWAP) {
        mutate_pcap(out_buf, out_size);
    } else if (magic == PCAPNG_MAGIC) {
        mutate_pcapng(out_buf, out_size);
    } else {
        /* fallback havoc but keep magic intact */
        size_t n = 1 + rnd(16);
        for (size_t i = 0; i < n && out_size > 8; i++) {
            size_t pos = 4 + rnd(out_size - 4);
            out_buf[pos] ^= (uint8_t)rnd(255);
        }
    }

    if (out_size > max_size)
        out_size = max_size;

    *out = out_buf;
    return out_size;
}
