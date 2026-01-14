#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ---------------- BIFF record IDs ---------------- */

#define MAX_RECORDS     4096
#define MAX_OUT_SIZE    (1 << 20)

/* ---------------- Type Definitions ---------------- */

typedef struct {
    uint8_t  *data;
    uint32_t cap;
    uint16_t id;
    uint16_t len;
    uint32_t total;
} record_t;

typedef struct {
    record_t recs[MAX_RECORDS];
    size_t   rec_cnt;
    uint8_t *out;
    size_t   out_sz;
} mut_state_t;

/* ---------------- helpers ---------------- */

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline void wr16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xff;
    p[1] = v >> 8;
}

/* ---------------- Record Parsing ---------------- */

static size_t parse_records(mut_state_t *ms,
                            const uint8_t *buf,
                            size_t sz)
{
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
            if (!tmp)
                break;
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

/* ---------------- Mutations ---------------- */

static void corrupt_record_length(record_t *r)
{
    if (!r || r->cap < 4)
        return;

    uint16_t new_len = (uint16_t)(rand() % 1000);

    if ((size_t)4 + new_len > r->cap)
        return;

    wr16(r->data + 2, new_len);
    r->len   = new_len;
    r->total = 4 + new_len;
}

static void swap_records(mut_state_t *ms, size_t a, size_t b)
{
    if (!ms || a >= ms->rec_cnt || b >= ms->rec_cnt || a == b)
        return;

    record_t tmp = ms->recs[a];
    ms->recs[a] = ms->recs[b];
    ms->recs[b] = tmp;
}

static void insert_random_data(record_t *r)
{
    if (!r || r->len == 0)
        return;

    size_t insert_pos = (size_t)(rand() % r->len);
    size_t data_size  = (size_t)(rand() % 10 + 1);

    if ((size_t)4 + r->len + data_size > r->cap)
        return;

    memmove(r->data + 4 + insert_pos + data_size,
            r->data + 4 + insert_pos,
            r->len - insert_pos);

    for (size_t i = 0; i < data_size; i++)
        r->data[4 + insert_pos + i] = (uint8_t)(rand() & 0xff);

    r->len   += data_size;
    r->total  = 4 + r->len;

    wr16(r->data + 2, r->len);
}

/* ---------------- AFL++ API ---------------- */

void *afl_custom_init(void *afl, unsigned int seed)
{
    (void)afl;
    srand(seed);

    mut_state_t *ms = calloc(1, sizeof(mut_state_t));
    if (!ms)
        return NULL;

    ms->out = malloc(MAX_OUT_SIZE);
    if (!ms->out) {
        free(ms);
        return NULL;
    }

    return ms;
}

void afl_custom_deinit(void *data)
{
    mut_state_t *ms = data;
    if (!ms)
        return;

    for (size_t i = 0; i < MAX_RECORDS; i++)
        free(ms->recs[i].data);

    free(ms->out);
    free(ms);
}

size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t buf_sz,
                       uint8_t **out_buf,
                       uint8_t *add, size_t add_sz,
                       size_t max_sz)
{
    (void)add;
    (void)add_sz;

    if (!data || buf_sz < 8) {
        *out_buf = buf;
        return buf_sz;
    }

    mut_state_t *ms = data;

    if (parse_records(ms, buf, buf_sz) == 0) {
        *out_buf = buf;
        return buf_sz;
    }

    if (ms->rec_cnt == 0) {
        *out_buf = buf;
        return buf_sz;
    }

    size_t idx = (size_t)(rand() % ms->rec_cnt);
    record_t *r = &ms->recs[idx];

    switch (rand() % 4) {
        case 0:
            corrupt_record_length(r);
            break;
        case 1:
            swap_records(ms, idx,
                         (size_t)(rand() % ms->rec_cnt));
            break;
        case 2:
            insert_random_data(r);
            break;
        default:
            break;
    }

    size_t total = 0;
    for (size_t i = 0; i < ms->rec_cnt; i++) {
        if (total + ms->recs[i].total > max_sz)
            break;
        total += ms->recs[i].total;
    }

    if (total == 0)
        total = buf_sz;

    if (total > MAX_OUT_SIZE)
        total = MAX_OUT_SIZE;

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
        memcpy(ms->out + off,
               ms->recs[i].data,
               ms->recs[i].total);
        off += ms->recs[i].total;
    }

    *out_buf = ms->out;
    return off;
}
