#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE        (512 * 1024)
#define MAX_IFD_ENTRIES 512
#define MAX_IFD_DEPTH   16
#define MAX_IFDS        128

#define CHAOS_PROB          20
#define HEAVY_DATA_PROB     30
#define MAX_HEAVY_MUTATIONS 256

#define TIFF_RATIONAL  5

#define TAG_COMPRESSION   259
#define TAG_PREDICTOR     317
#define TAG_PLANARCONFIG  284
#define TAG_IMAGEWIDTH    256
#define TAG_IMAGELENGTH   257
#define TAG_STRIPOFFSETS  273
#define TAG_STRIPBYTECOUNT 279
#define TAG_TILEOFFSETS   324
#define TAG_TILEBYTECOUNT 325

static inline uint16_t rd16(const uint8_t *b, int le) {
    return le ? (b[0] | (b[1]<<8)) : ((b[0]<<8) | b[1]);
}

static inline uint32_t rd32(const uint8_t *b, int le) {
    return le ? (b[0]|b[1]<<8|b[2]<<16|b[3]<<24) : (b[0]<<24|b[1]<<16|b[2]<<8|b[3]);
}

static inline uint64_t rd64(const uint8_t *b, int le) {
    if (le) return ((uint64_t)b[0]|((uint64_t)b[1]<<8)|((uint64_t)b[2]<<16)|((uint64_t)b[3]<<24)|
                    ((uint64_t)b[4]<<32)|((uint64_t)b[5]<<40)|((uint64_t)b[6]<<48)|((uint64_t)b[7]<<56));
    else    return ((uint64_t)b[0]<<56|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|
                    ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|((uint64_t)b[6]<<8)|b[7]);
}

static inline void wr16(uint8_t *b, uint16_t v, int le) {
    if (le) { b[0]=v; b[1]=v>>8; } else { b[0]=v>>8; b[1]=v; }
}

static inline void wr32(uint8_t *b, uint32_t v, int le) {
    if (le) { b[0]=v; b[1]=v>>8; b[2]=v>>16; b[3]=v>>24; }
    else    { b[0]=v>>24; b[1]=v>>16; b[2]=v>>8; b[3]=v; }
}

static inline void wr64(uint8_t *b, uint64_t v, int le) {
    if (le) {
        for (int i=0;i<8;i++) b[i] = v >> (8*i);
    } else {
        for (int i=0;i<8;i++) b[i] = v >> (56-8*i);
    }
}

static inline uint32_t urand(uint32_t limit) {
    return limit ? (uint32_t)rand() % limit : 0;
}

typedef struct {
    uint8_t out[MAX_FILE];
} tiff_mutator_t;

typedef struct {
    uint64_t off;
    uint16_t count;
} ifd_loc_t;

static void chaos_mutate(uint8_t *buf, size_t len) {
    uint32_t flips = 16 + urand(128);
    for (uint32_t i=0;i<flips;i++) {
        uint32_t pos = urand(len);
        buf[pos] ^= (uint8_t)(1u << urand(8));
    }
}

static void heavy_mutate_region(uint8_t *buf, size_t len, uint32_t off, uint32_t size) {
    if (off >= len) return;
    if (off+size>len) size = len-off;
    if (size<8) return;
    uint32_t mutations = 32 + urand(MAX_HEAVY_MUTATIONS);
    for (uint32_t i=0;i<mutations;i++) {
        uint32_t pos = off + urand(size);
        buf[pos] ^= (uint8_t)(1u << urand(8));
    }
}

static uint32_t collect_ifds(uint8_t *buf, size_t len, int le, int big, ifd_loc_t *out, uint32_t max) {
    uint32_t n = 0;
    if (len < 8) return 0;
    uint64_t off = big ? rd64(buf+4, le) : rd32(buf+4, le);
    uint32_t depth = 0;

    while (off>=8 && n<max && depth++<MAX_IFD_DEPTH) {
        if (off >= len) break;
        uint8_t *ifd = buf + off;
        uint16_t cnt = rd16(ifd, le);
        uint64_t ifd_size = 2 + (uint64_t)cnt*12 + (big?8:4);
        if (cnt==0 || cnt>MAX_IFD_ENTRIES || off+ifd_size>len) break;
        out[n++] = (ifd_loc_t){ off, cnt };
        uint64_t next = big ? rd64(ifd+2+cnt*12, le) : rd32(ifd+2+cnt*12, le);
        if (next <= off || next >= len) break;
        off = next;
    }
    return n;
}

static uint8_t *find_entry(uint8_t *buf, size_t len, int le, ifd_loc_t *loc, uint16_t tag) {
    uint8_t *ifd = buf + loc->off;
    for (uint16_t i=0;i<loc->count;i++) {
        uint8_t *ent = ifd + 2 + i*12;
        if (ent+12>buf+len) break;
        if (rd16(ent, le)==tag) return ent;
    }
    return NULL;
}

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    srand(seed);
    return calloc(1,sizeof(tiff_mutator_t));
}

void afl_custom_deinit(void *data) {
    free(data);
}

size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t len,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_len,
                       size_t max_size) {

    (void)add_buf; (void)add_len; (void)max_size;

    if (len < 8 || len > MAX_FILE) return len;
    tiff_mutator_t *m = data;
    memcpy(m->out, buf, len);

    int le;
    int big = 0;
    if (!memcmp(m->out,"II",2)) le=1;
    else if (!memcmp(m->out,"MM",2)) le=0;
    else { chaos_mutate(m->out,len); *out_buf=m->out; return len; }

    uint16_t magic = rd16(m->out+2, le);
    if (magic==42) big=0;
    else if (magic==43) big=1;
    else { chaos_mutate(m->out,len); *out_buf=m->out; return len; }

    if (urand(100)<CHAOS_PROB) {
        chaos_mutate(m->out,len);
        *out_buf = m->out;
        return len;
    }

    ifd_loc_t ifds[MAX_IFDS];
    uint32_t n_ifd = collect_ifds(m->out,len,le,big,ifds,MAX_IFDS);
    if (!n_ifd) {
        chaos_mutate(m->out,len);
        *out_buf=m->out;
        return len;
    }

    int mutations = 1 + urand(6);
    while (mutations--) {
        ifd_loc_t *loc = &ifds[urand(n_ifd)];
        uint8_t *ifd = m->out + loc->off;

        switch (urand(6)) {
            case 0: {
                uint32_t idx = urand(loc->count);
                uint8_t *ent = ifd + 2 + idx*12;
                if (ent+12>m->out+len) break;
                switch (urand(6)) {
                    case 0: wr32(ent+4, 0xFFFFFFFFu, le); break;
                    case 1: wr16(ent+2, TIFF_RATIONAL, le); break;
                    case 2: wr32(ent+8, len>8?len-8:0, le); break;
                    case 3: wr16(ent+2, 0x0E + (urand(3)), le); break;
                    case 4: wr32(ent+8, urand(16)+1, le); break;
                    case 5: chaos_mutate(m->out,len); break;
                }
                break;
            }
            case 1:
                wr16(ifd, 0xFFFF, le);
                break;
            case 2:
                if (big) wr64(ifd+2+loc->count*12, loc->off, le);
                else wr32(ifd+2+loc->count*12, loc->off, le);
                break;
            case 3:
                if (urand(100)<HEAVY_DATA_PROB) {
                    uint32_t off = urand(len);
                    uint32_t size = 64+urand(2048);
                    heavy_mutate_region(m->out,len,off,size);
                }
                break;
            case 4: {
                uint8_t *pred = find_entry(m->out,len,le,loc,TAG_PREDICTOR);
                uint8_t *plan = find_entry(m->out,len,le,loc,TAG_PLANARCONFIG);
                uint8_t *comp = find_entry(m->out,len,le,loc,TAG_COMPRESSION);
                uint8_t *w = find_entry(m->out,len,le,loc,TAG_IMAGEWIDTH);
                uint8_t *h = find_entry(m->out,len,le,loc,TAG_IMAGELENGTH);
                uint8_t *strip = find_entry(m->out,len,le,loc,TAG_STRIPOFFSETS);
                uint8_t *bc = find_entry(m->out,len,le,loc,TAG_STRIPBYTECOUNT);
                uint8_t *tile = find_entry(m->out,len,le,loc,TAG_TILEOFFSETS);
                uint8_t *tb = find_entry(m->out,len,le,loc,TAG_TILEBYTECOUNT);
                if (pred) wr32(pred+4, 2, le);
                if (plan) wr32(plan+4, 2, le);
                if (comp) wr32(comp+4, (uint32_t)(rand()%9==0?7:urand(10)), le);
                if (w) wr32(w+4, 65535+urand(256), le);
                if (h) wr32(h+4, 65535+urand(256), le);
                if (strip) wr32(strip+4, urand(len), le);
                if (bc) wr32(bc+4, urand(len/2), le);
                if (tile) wr32(tile+4, urand(len), le);
                if (tb) wr32(tb+4, urand(len/2), le);
                break;
            }
            case 5:
                chaos_mutate(m->out,len);
                break;
        }
    }

    *out_buf = m->out;
    return len;
}
