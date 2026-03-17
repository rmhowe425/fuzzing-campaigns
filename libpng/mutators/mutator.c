#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <zlib.h>
#include <time.h>

#define MAX_CHUNKS 256
#define MAX_CHUNK_LENGTH (1 << 20)
#define MAX_OUTPUT_SIZE (1 << 20)
#define MAX_SAFE_CHUNK 65536

static unsigned char *mut_buf = NULL;
static size_t mut_buf_size = 0;

/* ================= Minimal PNG ================= */

static const unsigned char MINIMAL_PNG[] = {
  0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A,
  0x00,0x00,0x00,0x0D,'I','H','D','R',
  0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
  0x08,0x02,0x00,0x00,0x00,
  0x90,0x77,0x53,0xDE,
  0x00,0x00,0x00,0x08,'I','D','A','T',
  0x78,0x9c,0x63,0x00,0x00,0x00,0x02,0x00,
  0x01,0x05,0x5c,0x0b,0x02,
  0x00,0x00,0x00,0x00,'I','E','N','D',
  0xAE,0x42,0x60,0x82
};

typedef struct {
  uint32_t length;
  char type[5];
  unsigned char *data;
  uint32_t crc;
} png_chunk_t;

/* ================= Utilities ================= */

static uint32_t read_be32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  |
         ((uint32_t)p[3]);
}

static void write_be32(unsigned char *p, uint32_t v) {
  p[0]=(v>>24)&0xff;
  p[1]=(v>>16)&0xff;
  p[2]=(v>>8)&0xff;
  p[3]=v&0xff;
}

static uint32_t compute_crc(const char *type,
                            const unsigned char *data,
                            uint32_t len) {

  uint32_t crc = crc32(0L,(const unsigned char*)type,4);

  if (data && len)
    crc = crc32(crc,data,len);

  return crc;
}

/* ================= Parser ================= */

static int parse_png_chunks(const unsigned char *buf,
                            size_t size,
                            png_chunk_t **chunks_out,
                            int *count_out) {

  if (size < 8) return -1;
  if (memcmp(buf,"\x89PNG\r\n\x1a\n",8)) return -1;

  size_t pos = 8;
  int count = 0;

  png_chunk_t *chunks = calloc(MAX_CHUNKS,sizeof(png_chunk_t));
  if (!chunks) return -1;

  while (pos + 12 <= size && count < MAX_CHUNKS) {

    uint32_t len = read_be32(buf+pos);

    if (len > MAX_CHUNK_LENGTH) break;
    if (pos + 12 + len > size) break;

    memcpy(chunks[count].type,buf+pos+4,4);
    chunks[count].type[4]=0;

    chunks[count].length=len;

    chunks[count].data = NULL;
    if (len) {
      chunks[count].data = malloc(len);
      if (!chunks[count].data) break;
      memcpy(chunks[count].data,buf+pos+8,len);
    }

    chunks[count].crc = read_be32(buf+pos+8+len);

    pos += 12 + len;
    count++;
  }

  *chunks_out = chunks;
  *count_out = count;

  return 0;
}

static void free_chunks(png_chunk_t *chunks,int count) {
  if (!chunks) return;
  for (int i=0;i<count;i++)
    free(chunks[i].data);
  free(chunks);
}

/* ================= Mutation Helpers ================= */

static void mutate_bytes(unsigned char *data, size_t len) {
  if (!data || !len) return;

  size_t n = (rand() % 32) + 1;

  for (size_t i=0;i<n;i++) {
    size_t pos = rand() % len;
    data[pos] ^= (1 << (rand()%8));
  }
}

/* ================= Core Mutator ================= */

static size_t png_mutate(unsigned char *data,
                         size_t size,
                         unsigned char *out,
                         size_t max_size) {

  /* -------- Chaos mode (CRITICAL) -------- */
  if (rand() % 5 == 0) {
    size_t n = size < max_size ? size : max_size;
    memcpy(out, data, n);

    for (size_t i=0;i<n;i++)
      if (rand()%3==0)
        out[i] ^= rand();

    return n;
  }

  /* -------- AFL bypass mode -------- */
  if (rand() % 5 == 0) {
    size_t n = size < max_size ? size : max_size;
    memcpy(out, data, n);
    return n;
  }

  png_chunk_t *chunks=NULL;
  int chunk_count=0;

  int parsed = (parse_png_chunks(data,size,&chunks,&chunk_count)==0);

  size_t pos=0;

  /* sometimes start from scratch */
  if (!parsed || rand()%4==0) {
    size_t n = sizeof(MINIMAL_PNG);
    if (n > max_size) n = max_size;
    memcpy(out, MINIMAL_PNG, n);
    pos = n;
  } else {
    memcpy(out, "\x89PNG\r\n\x1a\n", 8);
    pos = 8;
  }

  if (parsed && chunk_count > 1 && rand()%3==0) {
    int a = rand()%chunk_count;
    int b = rand()%chunk_count;
    png_chunk_t tmp = chunks[a];
    chunks[a] = chunks[b];
    chunks[b] = tmp;
  }

  for (int i=0;i<chunk_count;i++) {

    png_chunk_t *c = &chunks[i];

    if (rand()%5==0) continue; /* drop chunk */

    uint32_t len = c->length;

    if (len > MAX_SAFE_CHUNK)
      len = MAX_SAFE_CHUNK;

    if (pos + 12 + len > max_size)
      break;

    unsigned char *tmp = NULL;

    if (len) {
      tmp = malloc(len);
      if (!tmp) break;
      memcpy(tmp, c->data, len);
    }

    /* mutate IHDR heavily */
    if (!strcmp(c->type,"IHDR") && len >= 13) {

      write_be32(tmp, rand()%20000);
      write_be32(tmp+4, rand()%20000);

      tmp[8]  = (rand()%5==0) ? (rand()%256) : (1 << (rand()%4));
      tmp[9]  = rand()%7;
      tmp[10] = rand()%2;
      tmp[11] = rand()%2;
      tmp[12] = rand()%2;
    }

    /* mutate IDAT and others */
    if (!strcmp(c->type,"IDAT") || (c->type[0]&0x20)) {

      mutate_bytes(tmp, len);

      /* zlib corruption */
      if (len > 2 && rand()%3==0) {
        tmp[0] = 0x78;
        tmp[1] = (rand()%2) ? 0x9c : 0xda;
      }
    }

    /* random duplication */
    int repeat = (rand()%10==0) ? 2 : 1;

    for (int r=0;r<repeat;r++) {

      write_be32(out+pos,len);
      memcpy(out+pos+4,c->type,4);

      if (len)
        memcpy(out+pos+8,tmp,len);

      uint32_t crc;

      if (rand()%2)
        crc = compute_crc(c->type,tmp,len);
      else
        crc = rand(); /* corrupt CRC */

      write_be32(out+pos+8+len,crc);

      pos += 12 + len;

      if (pos >= max_size) break;
    }

    free(tmp);

    if (pos >= max_size) break;
  }

  /* optional IEND */
  if (rand()%2 && pos + 12 <= max_size) {
    memcpy(out+pos,"\x00\x00\x00\x00IEND",8);
    write_be32(out+pos+8, rand()); /* maybe corrupt */
    pos += 12;
  }

  if (parsed)
    free_chunks(chunks,chunk_count);

  if (!pos) {
    out[0]=0;
    pos=1;
  }

  return pos;
}

/* ================= AFL Hooks ================= */

unsigned int afl_custom_init(void **data, unsigned int seed) {

  srand(seed ? seed : time(NULL));

  mut_buf_size = MAX_OUTPUT_SIZE;
  mut_buf = malloc(mut_buf_size);

  *data=NULL;

  return 0;
}

void afl_custom_deinit(void *data) {
  (void)data;
  free(mut_buf);
}

size_t afl_custom_fuzz(
  void *data,
  unsigned char *buf,
  size_t buf_size,
  unsigned char **out_buf,
  unsigned char *add_buf,
  size_t add_buf_size,
  size_t max_size
) {

  (void)data;
  (void)add_buf;
  (void)add_buf_size;

  if (!mut_buf)
    return 0;

  size_t new_size = png_mutate(buf,buf_size,mut_buf,max_size);

  *out_buf = mut_buf;

  return new_size;
}
