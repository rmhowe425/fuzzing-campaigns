#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- BIFF record IDs ---------------- */

#define BIFF_BOF        0x0809
#define BIFF_EOF        0x000A
#define BIFF_DIMENSIONS 0x0200

#define BIFF_SST        0x00FC
#define BIFF_CONTINUE   0x003C
#define BIFF_FORMULA    0x0006
#define BIFF_LABELSST   0x00FD
#define BIFF_NUMBER     0x0203

#define MAX_RECORDS     4096
#define MAX_OUT_SIZE    (1 << 20)

/* ---------------- types ---------------- */

typedef struct {
    uint8_t  *data;
    uint32_t  cap;
    uint16_t  id;
    uint16_t  len;
    uint32_t  total;
} record_t;

typedef struct {
    record_t  recs[MAX_RECORDS];
    size_t    rec_cnt;
    uint8_t  *out;
    size_t    out_sz;
} mut_state_t;

/* ---------------- helpers ---------------- */

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline void wr16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xff;
    p[1] = v >> 8;
}

static inline uint32_t min_u32(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

/* ---------------- classification ---------------- */

static inline int is_spine(uint16_t id) {
    return (id == BIFF_BOF || id == BIFF_EOF || id == BIFF_DIMENSIONS);
}

static inline int is_cell(uint16_t id) {
    return (id == BIFF_LABELSST || id == BIFF_NUMBER);
}

/* ---------------- record parsing ---------------- */

static size_t parse_records(mut_state_t *ms,
                            const uint8_t *buf,
                            size_t sz) {
    size_t off = 0;
    ms->rec_cnt = 0;

    while (off + 4 <= sz && ms->rec_cnt < MAX_RECORDS) {
        uint16_t len = rd16(buf + off + 2);
        size_t need = 4 + len;
        if (off + need > sz)
            break;

        record_t *r = &ms->recs[ms->rec_cnt];

        if (r->cap < need) {
            uint8_t *tmp = realloc(r->data, need);
            if (!tmp) break;
            r->data = tmp;
            r->cap  = need;
        }

        memcpy(r->data, buf + off, need);

        r->id    = rd16(buf + off);
        r->len   = len;
        r->total = need;

        ms->rec_cnt++;
        off += need;
    }

    return ms->rec_cnt;
}

/* ---------------- local mutations (existing) ---------------- */

static void sst_payload_mutate(record_t *r) {
    if (r->len < 8) return;
    size_t off = 8 + (rand() % (r->len - 8));
    r->data[4 + off] ^= (1u << (rand() % 8));
}

static void formula_token_mutate(record_t *r) {
    if (r->len < 20) return;
    size_t off = 20 + (rand() % (r->len - 20));
    r->data[4 + off] ^= (rand() & 0x1F);
}

static void cell_ref_mutate(record_t *r) {
    if (r->len < 6) return;
    size_t off = 4 + (rand() % 4);
    r->data[off] ^= (1u << (rand() % 8));
}

static void continue_payload_mutate(record_t *r) {
    if (r->len < 4) return;
    size_t off = 4 + (rand() % r->len);
    r->data[off] ^= 0xFF;
}

static void corrupt_length(record_t *r) {
    if (!r->data || r->len < 1) return;

    uint16_t newlen = r->len;
    switch (rand() % 3) {
        case 0: newlen += 1; break;
        case 1: if (newlen > 1) newlen -= 1; break;
        default:newlen ^= 1 << (rand() % 4); break;
    }

    if (newlen > r->cap - 4)
        newlen = r->cap - 4;

    r->len   = newlen;
    r->total = 4 + newlen;
    wr16(r->data + 2, newlen);
}

/* ---------------- NEW: cross-record mutations ---------------- */

/* duplicate a record (state desync) */
static void duplicate_record(mut_state_t *ms, size_t idx) {
    if (ms->rec_cnt >= MAX_RECORDS) return;

    record_t *src = &ms->recs[idx];
    record_t *dst = &ms->recs[ms->rec_cnt];

    dst->cap = src->total;
    dst->data = malloc(dst->cap);
    if (!dst->data) return;

    memcpy(dst->data, src->data, src->total);
    dst->id    = src->id;
    dst->len   = src->len;
    dst->total = src->total;

    ms->rec_cnt++;
}

/* swap two adjacent records (ordering violation) */
static void swap_adjacent(mut_state_t *ms, size_t idx) {
    if (idx + 1 >= ms->rec_cnt) return;
    record_t tmp = ms->recs[idx];
    ms->recs[idx] = ms->recs[idx + 1];
    ms->recs[idx + 1] = tmp;
}

/* break SST–CONTINUE size relationship */
static void break_continue_chain(mut_state_t *ms, size_t idx) {
    if (ms->recs[idx].id != BIFF_SST) return;

    for (size_t i = idx + 1; i < ms->rec_cnt; i++) {
        if (ms->recs[i].id == BIFF_CONTINUE) {
            corrupt_length(&ms->recs[i]);
            break;
        }
        if (ms->recs[i].id != BIFF_CONTINUE)
            break;
    }
}

/* ---------------- AFL++ API ---------------- */

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    srand(seed);
    return calloc(1, sizeof(mut_state_t));
}

void afl_custom_deinit(void *data) {
    mut_state_t *ms = data;
    if (!ms) return;
    for (size_t i = 0; i < MAX_RECORDS; i++)
        free(ms->recs[i].data);
    free(ms->out);
    free(ms);
}

size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t buf_sz,
                       uint8_t **out_buf,
                       uint8_t *add, size_t add_sz,
                       size_t max_sz) {
    (void)add; (void)add_sz;

    if (buf_sz < 8) {
        *out_buf = buf;
        return buf_sz;
    }

    mut_state_t *ms = data;
    if (!parse_records(ms, buf, buf_sz)) {
        *out_buf = buf;
        return buf_sz;
    }

    size_t idx = rand() % ms->rec_cnt;
    record_t *r = &ms->recs[idx];

    /* ---------------- mutation policy ---------------- */

    int action = rand() % 14;

    if (action < 3 && r->id == BIFF_SST)
        sst_payload_mutate(r);
    else if (action < 5 && r->id == BIFF_FORMULA)
        formula_token_mutate(r);
    else if (action < 7 && is_cell(r->id))
        cell_ref_mutate(r);
    else if (action < 9 && r->id == BIFF_CONTINUE)
        continue_payload_mutate(r);
    else if (action == 9)
        corrupt_length(r);
    else if (action == 10)
        duplicate_record(ms, idx);
    else if (action == 11)
        swap_adjacent(ms, idx);
    else if (action == 12)
        break_continue_chain(ms, idx);
    /* action == 13: no-op (diversity) */

    /* ---------------- rebuild output ---------------- */

    size_t total = 0;
    for (size_t i = 0; i < ms->rec_cnt; i++) {
        if (total + ms->recs[i].total > max_sz)
            break;
        total += ms->recs[i].total;
    }

    if (!total) total = buf_sz;
    if (total > MAX_OUT_SIZE) total = MAX_OUT_SIZE;

    if (ms->out_sz < total) {
        uint8_t *tmp = realloc(ms->out, total);
        if (!tmp) {
            *out_buf = buf;
            return buf_sz;
        }
        ms->out = tmp;
        ms->out_sz = total;
    }

    size_t off = 0;
    for (size_t i = 0; i < ms->rec_cnt && off < total; i++) {
        size_t n = min_u32(ms->recs[i].total, total - off);
        memcpy(ms->out + off, ms->recs[i].data, n);
        off += n;
    }

    *out_buf = ms->out;
    return off;
}
