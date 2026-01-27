#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "afl-fuzz.h"

#define MAX_OUT 8192
#define MAX_FILTER 2048
#define CTRL_SIZE 4

static uint8_t *out_buf;
static size_t out_size;

/* AFL-required */
void afl_custom_init(void *afl, unsigned int seed) {
    srand(seed);
    out_buf = malloc(MAX_OUT);
}

/* Utilities */
static inline uint32_t rnd(uint32_t n) {
    return n ? rand() % n : 0;
}

static inline int one_in(int n) {
    return (rand() % n) == 0;
}

/* Known-good grammar anchors (high compile success) */
static const char *good_atoms[] = {
    "ip",
    "tcp",
    "udp",
    "icmp",
    "arp",
    "ip6",
    "ether",
};

/* Runtime / optimizer stressors */
static const char *evil_atoms[] = {
    "ip[0]",
    "ip[0:4]",
    "ip[12:4]",
    "tcp[0]",
    "tcp[12:4]",
    "udp[0:2]",
    "ether[0:14]",
    "ether[12:2]",
    "len",
    "len <= 0",
    "len >= 4294967295",
    "ip[999999999]",
};

/* Expression wrappers (grammar depth & precedence) */
static const char *wrappers[] = {
    "(%s)",
    "not (%s)",
    "(%s) and (%s)",
    "(%s) or (%s)",
};

/* Minimal DLT-specific packet prefixes */
static const uint8_t eth_hdr[14]  = {0};
static const uint8_t null_hdr[4]  = {0};
static const uint8_t loop_hdr[4]  = {0};
static const uint8_t sll_hdr[16]  = {0};
static const uint8_t sll2_hdr[20] = {0};

/* ----------------------------
 * Grammar-aware filter builder
 * ---------------------------- */
static size_t build_filter(char *dst, size_t max) {
    char tmp[512];
    const char *a = good_atoms[rnd(sizeof(good_atoms)/sizeof(good_atoms[0]))];
    const char *b = evil_atoms[rnd(sizeof(evil_atoms)/sizeof(evil_atoms[0]))];

    /* Start with something that compiles */
    snprintf(tmp, sizeof(tmp), "%s", a);

    /* Increase depth */
    int depth = 1 + rnd(4);
    for (int i = 0; i < depth; i++) {
        const char *w = wrappers[rnd(sizeof(wrappers)/sizeof(wrappers[0]))];
        char next[512];

        if (strstr(w, "%s") && strstr(w + 1, "%s")) {
            snprintf(next, sizeof(next), w, tmp, b);
        } else {
            snprintf(next, sizeof(next), w, tmp);
        }
        strncpy(tmp, next, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = 0;
    }

    size_t len = strlen(tmp);
    if (len >= max) len = max - 1;
    memcpy(dst, tmp, len);
    dst[len] = '\0';
    return len + 1;
}

/* ----------------------------
 * Packet shaping per DLT
 * ---------------------------- */
static size_t shape_packet(uint8_t *pkt, size_t max, uint8_t dlt) {
    size_t off = 0;

    switch (dlt % 8) {
    case 1: /* EN10MB */
        memcpy(pkt, eth_hdr, sizeof(eth_hdr));
        off = sizeof(eth_hdr);
        break;
    case 2: /* SLL */
        memcpy(pkt, sll_hdr, sizeof(sll_hdr));
        off = sizeof(sll_hdr);
        break;
    case 3: /* SLL2 */
        memcpy(pkt, sll2_hdr, sizeof(sll2_hdr));
        off = sizeof(sll2_hdr);
        break;
    case 4: /* NULL */
    case 5: /* LOOP */
        memcpy(pkt, null_hdr, sizeof(null_hdr));
        off = sizeof(null_hdr);
        break;
    default:
        off = 0;
        break;
    }

    /* Fill payload with chaos */
    size_t remain = max - off;
    for (size_t i = 0; i < remain; i++)
        pkt[off + i] = rnd(256);

    return off + remain;
}

/* ----------------------------
 * AFL entry point
 * ---------------------------- */
size_t afl_custom_fuzz(void *afl,
                       uint8_t *buf,
                       size_t len,
                       uint8_t **out,
                       uint8_t *add_buf,
                       size_t add_len,
                       size_t max_size) {

    if (len < CTRL_SIZE) {
        *out = buf;
        return len;
    }

    memcpy(out_buf, buf, len);
    out_size = len;

    uint8_t *flags = &out_buf[0];
    uint8_t *dlt   = &out_buf[1];
    uint8_t *snap  = &out_buf[2];
    uint8_t *split = &out_buf[3];

    int mode = rand() % 100;

    /* --------------------------------
     * 60%: structure-aware cooperation
     * -------------------------------- */
    if (mode < 60) {

        /* Flag pressure */
        *flags ^= (1 << rnd(6));

        /* Force caplen/len chaos sometimes */
        if (one_in(3))
            *flags |= 0x38;

        /* Snaplen jumps */
        *snap ^= rnd(64);

        /* Split bias */
        *split ^= rnd(3);

        /* DLT drift */
        if (one_in(2))
            *dlt = rnd(8);
    }

    /* --------------------------------
     * 25%: grammar-aware filter rebuild
     * -------------------------------- */
    else if (mode < 85) {

        size_t off = CTRL_SIZE;
        if (off + 8 >= MAX_OUT)
            goto done;

        size_t flen = build_filter((char *)(out_buf + off),
                                   MAX_FILTER);
        off += flen;

        /* Optional splicing */
        if (add_buf && add_len > CTRL_SIZE && one_in(3)) {
            size_t copy = add_len - CTRL_SIZE;
            if (off + copy < MAX_OUT) {
                memcpy(out_buf + off,
                       add_buf + CTRL_SIZE,
                       copy);
                off += copy;
            }
        }

        out_size = off;
    }

    /* --------------------------------
     * 15%: runtime decode cornering
     * -------------------------------- */
    else {

        size_t off = CTRL_SIZE;

        /* Rebuild filter */
        size_t flen = build_filter((char *)(out_buf + off),
                                   MAX_FILTER);
        off += flen;

        /* Shape packet to match DLT */
        size_t pkt_len = shape_packet(out_buf + off,
                                      MAX_OUT - off,
                                      *dlt);
        off += pkt_len;

        /* Force length contradictions */
        *flags |= 0x18;

        out_size = off;
    }

done:
    if (out_size > max_size)
        out_size = max_size;

    *out = out_buf;
    return out_size;
}

/* Cleanup */
void afl_custom_deinit(void *afl) {
    free(out_buf);
}
