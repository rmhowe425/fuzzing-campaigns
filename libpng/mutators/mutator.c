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

/* ---------------- PNG Minimal Structures ---------------- */

// PNG header + IHDR (1x1 RGB)
static const unsigned char MINIMAL_IHDR[] = {
  0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A,
  0x00,0x00,0x00,0x0D,
  'I','H','D','R',
  0x00,0x00,0x00,0x01,
  0x00,0x00,0x00,0x01,
  0x08,0x02,0x00,0x00,0x00,
  0x90,0x77,0x53,0xDE
};

// minimal IDAT (compressed empty block)
static const unsigned char MINIMAL_IDAT[] = {
  0x00,0x00,0x00,0x08,
  'I','D','A','T',
  0x78,0x9c,0x63,0x00,0x00,0x00,0x02,0x00,
  0x01,0x05,0x5c,0x0b,0x02
};

// IEND
static const unsigned char MINIMAL_IEND[] = {
  0x00,0x00,0x00,0x00,
  'I','E','N','D',
  0xAE,0x42,0x60,0x82
};

typedef struct {
  uint32_t length;
  char type[5];
  unsigned char *data;
  uint32_t crc;
} png_chunk_t;

/* ---------------- Utility ---------------- */

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

/* ---------------- PNG Parser ---------------- */

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

/* ---------------- Mutation Engine ---------------- */

static size_t png_mutate(unsigned char *data,
                         size_t size,
                         unsigned char *out,
                         size_t max_size) {

  png_chunk_t *chunks=NULL;
  int chunk_count=0;

  int parsed = (parse_png_chunks(data,size,&chunks,&chunk_count)==0);

  size_t pos=0;

  /* always emit valid header */
  size_t hdr = sizeof(MINIMAL_IHDR);

  if (hdr > max_size) hdr = max_size;

  memcpy(out,MINIMAL_IHDR,hdr);
  pos = hdr;

  int saw_idat=0;

  if (parsed) {

    for (int i=0;i<chunk_count;i++) {

      png_chunk_t *c = &chunks[i];

      if (!c->data || !c->length) continue;

      uint32_t len=c->length;

      if (len>MAX_SAFE_CHUNK) len=MAX_SAFE_CHUNK;

      if (pos + 12 + len > max_size) break;

      unsigned char *tmp = malloc(len);
      if (!tmp) break;

      memcpy(tmp,c->data,len);

      /* mutate IDAT or ancillary chunks */
      if (!strcmp(c->type,"IDAT") || (c->type[0]&0x20)) {

        uint32_t mutate_len = len>4096 ? 4096 : len;

        for (uint32_t j=0;j<mutate_len;j++)
          if (rand()%2)
            tmp[j] ^= 1 << (rand()%8);

      }

      if (!strcmp(c->type,"IDAT"))
        saw_idat=1;

      uint32_t crc = compute_crc(c->type,tmp,len);

      write_be32(out+pos,len);
      memcpy(out+pos+4,c->type,4);
      memcpy(out+pos+8,tmp,len);
      write_be32(out+pos+8+len,crc);

      pos += 12 + len;

      free(tmp);
    }
  }

  /* ensure IDAT exists */
  if (!saw_idat && pos + sizeof(MINIMAL_IDAT) < max_size) {
    memcpy(out+pos,MINIMAL_IDAT,sizeof(MINIMAL_IDAT));
    pos += sizeof(MINIMAL_IDAT);
  }

  /* always append IEND */
  if (pos + sizeof(MINIMAL_IEND) < max_size) {
    memcpy(out+pos,MINIMAL_IEND,sizeof(MINIMAL_IEND));
    pos += sizeof(MINIMAL_IEND);
  }

  if (parsed)
    free_chunks(chunks,chunk_count);

  if (!pos) {
    out[0]=0;
    pos=1;
  }

  return pos;
}

/* ---------------- AFL++ Hooks ---------------- */

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

/* required AFL++ fuzz hook */

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
