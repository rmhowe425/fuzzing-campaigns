#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * AFL++ custom mutator for libpcap pcap_compile()
 * No afl-fuzz.h dependency, no afl_state internals.
 */

#define MUT_BUF_MAX 8192

static uint8_t *mut_buf;

/* ---- Grammar fragments ---- */

static const char *tokens[] = {
    "tcp", "udp", "icmp", "ip", "ip6",
    "arp", "rarp",
    "ether", "broadcast", "multicast",
    "and", "or", "not",
    "src", "dst",
    "port", "portrange",
    "less", "greater",
    "len", "proto"
};

static const char *expressions[] = {
    "ip[0]",
    "ip[0:4]",
    "ip[12:2]",
    "ip[16:4]",
    "ip[-1:1]",
    "ip[65535:65535]",
    "tcp[13]",
    "tcp[-4:2]",
    "udp[6:2]",
    "ether[0:6]",
    "ip6[40]"
};

static const char *comparisons[] = {
    " = ", " != ", " < ", " > ", " <= ", " >= ", " & ", " | "
};

static const char *constants[] = {
    "0",
    "1",
    "-1",
    "0xff",
    "0xffff",
    "0xffffffff",
    "0x80000000",
    "4294967295",
    "18446744073709551615"
};

/* ---- Helpers ---- */

static inline size_t min_sz(size_t a, size_t b) {
    return a < b ? a : b;
}

static inline size_t rand_pos(size_t lo, size_t hi) {
    if (hi <= lo) return lo;
    return lo + (rand() % (hi - lo));
}

/* ---- AFL custom mutator API ---- */

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    srand(seed);

    mut_buf = malloc(MUT_BUF_MAX);
    if (!mut_buf)
        return NULL;

    return mut_buf;
}

void afl_custom_deinit(void *data) {
    (void)data;
    free(mut_buf);
}

size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

    (void)data;

    if (!buf || buf_size < 2 || !mut_buf) {
        *out_buf = buf;
        return buf_size;
    }

    size_t max_len = min_sz(max_size - 1, MUT_BUF_MAX - 1);
    size_t len = min_sz(buf_size, max_len);

    memcpy(mut_buf, buf, len);
    mut_buf[len] = '\0';

    /* Protect selector byte most of the time */
    size_t start = (rand() % 8 == 0) ? 0 : 1;
    size_t pos   = rand_pos(start, len);

    /* Bias strategy selection */
    int r = rand() % 100;
    int strategy;

    if (r < 40)      strategy = 0; /* grammar growth */
    else if (r < 70) strategy = 1; /* expression splice */
    else if (r < 90) strategy = 2; /* numeric corruption */
    else             strategy = 3; /* structural damage */

    switch (strategy) {

        /* 0) Token injection */
        case 0: {
            const char *tok = tokens[rand() % (sizeof(tokens)/sizeof(tokens[0]))];
            size_t tlen = strlen(tok);

            if (len + tlen + 1 < max_len) {
                memmove(mut_buf + pos + tlen + 1,
                        mut_buf + pos,
                        len - pos + 1);
                memcpy(mut_buf + pos, tok, tlen);
                mut_buf[pos + tlen] = ' ';
                len += tlen + 1;
            }
            break;
        }

        /* 1) Expression splicing (prefer add_buf) */
        case 1: {
            const char *expr = NULL;

            if (add_buf && add_buf_size > 4) {
                size_t cut = rand_pos(0, add_buf_size - 1);
                expr = (const char *)(add_buf + cut);
            } else {
                expr = expressions[rand() % (sizeof(expressions)/sizeof(expressions[0]))];
            }

            char tmp[192];
            snprintf(tmp, sizeof(tmp), "(%s%s%s)",
                     expr,
                     comparisons[rand() % (sizeof(comparisons)/sizeof(comparisons[0]))],
                     constants[rand() % (sizeof(constants)/sizeof(constants[0]))]);

            size_t elen = strlen(tmp);

            if (elen && len + elen < max_len) {
                memmove(mut_buf + pos + elen,
                        mut_buf + pos,
                        len - pos + 1);
                memcpy(mut_buf + pos, tmp, elen);
                len += elen;
            }
            break;
        }

        /* 2) Numeric extremification */
        case 2: {
            for (size_t i = pos; i + 1 < len; i++) {
                if (mut_buf[i] >= '0' && mut_buf[i] <= '9') {
                    const char *cst = constants[rand() % (sizeof(constants)/sizeof(constants[0]))];
                    size_t clen = strlen(cst);

                    if (len + clen < max_len) {
                        memmove(mut_buf + i + clen,
                                mut_buf + i + 1,
                                len - i);
                        memcpy(mut_buf + i, cst, clen);
                        len += clen - 1;
                    }
                    break;
                }
            }
            break;
        }

        /* 3) Structural damage (bounded) */
        case 3: {
            static const char *ops[] = { " and ", " or ", " not " };
            const char *op = ops[rand() % 3];
            size_t olen = strlen(op);

            if (len + olen + 2 < max_len) {
                memmove(mut_buf + pos + olen + 2,
                        mut_buf + pos,
                        len - pos + 1);
                mut_buf[pos] = '(';
                memcpy(mut_buf + pos + 1, op, olen);
                mut_buf[pos + olen + 1] = ')';
                len += olen + 2;
            }
            break;
        }
    }

    mut_buf[len] = '\0';
    *out_buf = mut_buf;
    return len;
}
