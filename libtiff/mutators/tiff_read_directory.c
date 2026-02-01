#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ================= Configuration ================= */

#define MAX_FILE        (256 * 1024)
#define MAX_IFD_ENTRIES 256
#define MAX_IFD_DEPTH   4

/* TIFF types */
#define TIFF_BYTE      1
#define TIFF_ASCII     2
#define TIFF_SHORT     3
#define TIFF_LONG      4
#define TIFF_RATIONAL  5
#define TIFF_SLONG     9
#define TIFF_SRATIONAL 10
#define TIFF_IFD       13

#define TAG_SUBIFD     330

/* ================= Utilities ================= */

static inline uint16_t rd16(const uint8_t *b, int le) {
    return le ? (b[0] | (b[1] << 8)) : ((b[0] << 8) | b[1]);
}

static inline uint32_t rd32(const uint8_t *b, int le) {
    return le ? (b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24)
              : (b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
}

static inline void wr16(uint8_t *b, uint16_t v, int le) {
    if (le) { b[0] = v & 0xff; b[1] = v >> 8; }
    else    { b[0] = v >> 8; b[1] = v & 0xff; }
}

static inline void wr32(uint8_t *b, uint32_t v, int le) {
    if (le) {
        b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24;
    } else {
        b[0] = v >> 24; b[1] = v >> 16; b[2] = v >> 8; b[3] = v;
    }
}

/* ================= RNG (Option 1) ================= */

static inline uint32_t urand(uint32_t limit) {
    return limit ? ((uint32_t)rand() % limit) : 0;
}

/* ================= Mutator State ================= */

typedef struct {
    uint8_t out[MAX_FILE];
} tiff_mutator_t;

/* ================= IFD Discovery ================= */

typedef struct {
    uint32_t off;
    uint16_t count;
} ifd_loc_t;

static uint32_t collect_ifds(uint8_t *buf, size_t len, int le,
                             ifd_loc_t *out, uint32_t max) {

    uint32_t n = 0;
    if (len < 8) return 0;

    uint32_t off = rd32(buf + 4, le);
    uint32_t depth = 0;

    while (off >= 8 && off + 2 < len && n < max && depth++ < MAX_IFD_DEPTH) {

        if (off >= len || off + 2 > len) break;

        uint8_t *ifd = buf + off;
        uint16_t cnt = rd16(ifd, le);
        if (cnt == 0 || cnt > MAX_IFD_ENTRIES) break;

        /* Check that entire IFD fits in buffer */
        if (2 + cnt * 12 + 4 > len - off) break;

        out[n++] = (ifd_loc_t){ off, cnt };

        for (uint16_t i = 0; i < cnt; i++) {
            uint8_t *ent = ifd + 2 + i * 12;
            if (ent + 12 > buf + len) break;

            uint16_t tag  = rd16(ent, le);
            uint16_t type = rd16(ent + 2, le);
            uint32_t cntv = rd32(ent + 4, le);
            uint32_t val  = rd32(ent + 8, le);

            if (tag == TAG_SUBIFD && type == TIFF_IFD && cntv > 0) {
                if (val >= 8 && val + 2 < len && n < max) {
                    uint16_t sub_cnt = rd16(buf + val, le);
                    if (val + 2 + sub_cnt * 12 + 4 <= len) {
                        out[n++] = (ifd_loc_t){ val, sub_cnt };
                    }
                }
            }
        }

        /* Move to next IFD offset */
        uint32_t next_off = rd32(ifd + 2 + cnt * 12, le);
        if (next_off <= off || next_off >= len) break;
        off = next_off;
    }

    return n;
}

/* ================= AFL Custom Mutator API ================= */

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    srand(seed);
    return calloc(1, sizeof(tiff_mutator_t));
}

void afl_custom_deinit(void *data) {
    free(data);
}

size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t len,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_len,
                       size_t max_size) {

    (void)add_buf;
    (void)add_len;
    (void)max_size;

    tiff_mutator_t *m = data;

    if (len < 8 || len > MAX_FILE)
        return len;

    memcpy(m->out, buf, len);

    int le;
    if (!memcmp(m->out, "II", 2)) le = 1;
    else if (!memcmp(m->out, "MM", 2)) le = 0;
    else return len;

    if (rd16(m->out + 2, le) != 42)
        return len;

    ifd_loc_t ifds[16];
    uint32_t n_ifd = collect_ifds(m->out, len, le, ifds, 16);
    if (n_ifd == 0)
        return len;

    ifd_loc_t *tgt = &ifds[urand(n_ifd)];
    uint8_t *ifd = m->out + tgt->off;

    uint32_t idx = urand(tgt->count);
    uint8_t *ent = ifd + 2 + idx * 12;

    /* Extra safety bounds check */
    if (ent + 12 > m->out + len) goto done;

    uint16_t tag  = rd16(ent + 0, le);
    uint16_t type = rd16(ent + 2, le);
    uint32_t cnt  = rd32(ent + 4, le);

    switch (urand(7)) {
        case 0: /* count * type overflow */
            cnt = 0x40000001u;
            wr32(ent + 4, cnt, le);
            break;

        case 1: /* inline ↔ offset boundary */
            wr16(ent + 2, TIFF_LONG, le);
            wr32(ent + 4, 2, le);
            break;

        case 2: /* type confusion (safe-ish set) */
            type = (type == TIFF_SHORT) ? TIFF_LONG :
                   (type == TIFF_LONG)  ? TIFF_RATIONAL :
                                          TIFF_SHORT;
            wr16(ent + 2, type, le);
            break;

        case 3: /* SubIFD self-alias */
            wr16(ent + 0, TAG_SUBIFD, le);
            wr16(ent + 2, TIFF_IFD, le);
            wr32(ent + 4, 1, le);
            wr32(ent + 8, tgt->off, le);
            break;

        case 4: /* duplicate-ish tag */
            wr16(ent + 0, tag ^ 0x0100, le);
            break;

        case 5: /* zero-count edge */
            wr32(ent + 4, 0, le);
            break;

        case 6: /* near-end offset */
            wr32(ent + 8, len > 8 ? len - 8 : 0, le);
            break;
    }

done:
    *out_buf = m->out;
    return len;
}
