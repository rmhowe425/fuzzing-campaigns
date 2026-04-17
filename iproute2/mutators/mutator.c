#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


/* ================= CONFIG ================= */

#define MAX_ATTRS   64
#define HEADER_SIZE 5
#define MAX_PAYLOAD 512
#define OUT_SIZE    8192
#define MAX_DEPTH   5

/* ================= FAST RNG ================= */

static uint32_t rng_state = 0x12345678;

static inline uint32_t xorshift32(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

static inline uint8_t rnd8(void) {
    return (uint8_t)xorshift32();
}

/* ================= HELPERS ================= */

static inline size_t clamp(size_t v, size_t max) {
    return v > max ? max : v;
}

/* ================= ATTRIBUTE SEMANTICS ================= */

typedef enum {
    ATTR_GENERIC = 0,
    ATTR_IFLA,
    ATTR_RTA,
    ATTR_TCA
} attr_family_t;

static inline attr_family_t classify_type(uint16_t type) {
    if (type < 16) return ATTR_IFLA;
    if (type < 32) return ATTR_RTA;
    if (type < 48) return ATTR_TCA;
    return ATTR_GENERIC;
}

/* ================= SAFE WRITE ================= */

static inline int write_bytes(uint8_t *out, size_t *out_len,
                              const void *src, size_t len) {
    if (*out_len + len > OUT_SIZE)
        return 0;

    memcpy(out + *out_len, src, len);
    *out_len += len;
    return 1;
}

/* ================= ALIGNMENT MODEL (NETLINK-LIKE) ================= */

static inline size_t align4(size_t n) {
    return (n + 3) & ~3;
}

/* ================= ATTRIBUTE STRUCT ================= */

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t  flag;
    uint8_t *payload;
    size_t   payload_len;
} attr_t;

/* ================= FAMILY MUTATION ================= */

static inline void mutate_by_family(attr_t *a, attr_family_t fam) {

    int r = xorshift32() % 100;

    switch (fam) {

        case ATTR_IFLA:
            if (r < 25) a->type ^= (1 << (rnd8() % 6));
            else if (r < 50) a->len ^= (1 << (rnd8() % 10));
            else if (r < 75) a->flag ^= 0x01;
            break;

        case ATTR_RTA:
            if (r < 35) a->len ^= (1 << (rnd8() % 12));
            else if (r < 65) a->type = (a->type + rnd8()) % 64;
            else if (r < 85) a->flag ^= 0x02;
            break;

        case ATTR_TCA:
            if (r < 40) a->flag ^= 0x03;
            else if (r < 70) a->len = (a->len / 2) + rnd8();
            else if (r < 90) a->type ^= (rnd8() & 0x0F);
            break;

        default:
            if (r < 50) a->type = (a->type + 1) % 64;
            break;
    }
}

/* ================= CORE RECURSIVE ENGINE ================= */

static size_t emit_attr(uint8_t *out,
                         size_t *out_len,
                         uint8_t *data,
                         size_t len,
                         int depth)
{
    attr_t attrs[MAX_ATTRS];
    int attr_count = 0;

    size_t i = 0;

    /* ================= PARSE ================= */

    while (i + HEADER_SIZE <= len && attr_count < MAX_ATTRS) {

        attr_t *a = &attrs[attr_count];

        memcpy(&a->type, data + i, 2);
        memcpy(&a->len,  data + i + 2, 2);
        a->flag = data[i + 4];

        i += HEADER_SIZE;

        a->type %= 64;

        a->payload_len = clamp((a->len & 0x03FF), MAX_PAYLOAD);

        if (i + a->payload_len > len)
            a->payload_len = len - i;

        a->payload = data + i;
        i += a->payload_len;

        attr_count++;
    }

    /* ================= MUTATE ================= */

    for (int j = 0; j < attr_count; j++) {

        attr_family_t fam = classify_type(attrs[j].type);

        mutate_by_family(&attrs[j], fam);

        int mode = xorshift32() % 100;

        if (mode < 15) {
            attrs[j].len ^= (1 << (rnd8() % 12));
        }
        else if (mode < 30) {
            attrs[j].type = (attrs[j].type + rnd8()) % 64;
        }
        else if (mode < 40) {
            attrs[j].flag ^= 0x03;
        }

        /* ================= ALIGNMENT DRIFT ================= */
        if ((xorshift32() % 100) < 20) {
            attrs[j].len = align4(attrs[j].len);
        }
    }

    /* ================= ATTRIBUTE COLLISION INJECTION ================= */

    if ((xorshift32() % 100) < 30 && attr_count > 1) {
        int a = xorshift32() % attr_count;
        int b = xorshift32() % attr_count;

        attrs[b].type = attrs[a].type;   /* duplicate type injection */
    }

    /* ================= REORDER ================= */

    if ((xorshift32() % 100) < 40) {
        for (int j = attr_count - 1; j > 0; j--) {
            int k = xorshift32() % (j + 1);

            attr_t tmp = attrs[j];
            attrs[j] = attrs[k];
            attrs[k] = tmp;
        }
    }

    /* ================= EMIT ================= */

    for (int j = 0; j < attr_count; j++) {

        attr_t *a = &attrs[j];

        /* family-driven nesting probability */
        int nest_prob =
            (a->type < 16) ? 25 :
            (a->type < 32) ? 40 :
            (a->type < 48) ? 50 : 30;

        if (depth < MAX_DEPTH &&
            a->payload_len > 8 &&
            (xorshift32() % 100) < nest_prob) {

            uint16_t nested_type = a->type ^ (rnd8() & 0x0F);
            uint16_t nested_len  = a->payload_len / 2;
            uint8_t  nested_flag = a->flag ^ 0x03;

            write_bytes(out, out_len, &nested_type, 2);
            write_bytes(out, out_len, &nested_len, 2);
            write_bytes(out, out_len, &nested_flag, 1);

            emit_attr(out,
                      out_len,
                      a->payload,
                      a->payload_len,
                      depth + 1);
        }
        else {

            write_bytes(out, out_len, &a->type, 2);
            write_bytes(out, out_len, &a->len, 2);
            write_bytes(out, out_len, &a->flag, 1);
            write_bytes(out, out_len, a->payload, a->payload_len);
        }
    }

    return *out_len;
}

/* ================= AFL++ API ================= */

void *afl_custom_init(void* *afl, unsigned int seed) {
    (void)afl;
    rng_state ^= seed;
    return NULL;
}

size_t afl_custom_fuzz(void* *afl,
                       void *data,
                       uint8_t *buf,
                       size_t buf_size,
                       uint8_t **out_buf,
                       uint8_t *add_buf,
                       size_t add_buf_size,
                       size_t max_size)
{
    (void)afl;
    (void)add_buf;
    (void)add_buf_size;

    uint8_t *out = malloc(OUT_SIZE);
    if (!out) return 0;

    memset(out, 0, OUT_SIZE);

    size_t out_len = 0;

    emit_attr(out, &out_len, buf, buf_size, 0);

    if (out_len > max_size)
        out_len = max_size;

    *out_buf = out;
    return out_len;
}

void afl_custom_deinit(void *data) {
    (void)data;
}
