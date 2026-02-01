#define _GNU_SOURCE
#include <tiffio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_INPUT_SIZE (256 * 1024)
#define AFL_PERSIST_ITERATIONS 1000

/* ================= In-memory TIFF I/O ================= */

typedef struct {
  const uint8_t *data;
  size_t size;
  size_t offset;
} mem_tiff_t;

static tsize_t mem_read(thandle_t h, tdata_t buf, tsize_t size) {
  mem_tiff_t *m = (mem_tiff_t *)h;
  if (m->offset >= m->size) return 0;
  if (m->offset + size > m->size)
    size = m->size - m->offset;
  memcpy(buf, m->data + m->offset, size);
  m->offset += size;
  return size;
}

static tsize_t mem_write(thandle_t h, tdata_t buf, tsize_t size) {
  (void)h; (void)buf; (void)size;
  return 0;
}

static toff_t mem_seek(thandle_t h, toff_t off, int whence) {
  mem_tiff_t *m = (mem_tiff_t *)h;
  toff_t new_off;

  switch (whence) {
    case SEEK_SET: new_off = off; break;
    case SEEK_CUR: new_off = (toff_t)m->offset + off; break;
    case SEEK_END: new_off = (toff_t)m->size + off; break;
    default: return (toff_t)-1;
  }

  if (new_off < 0 || (size_t)new_off > m->size)
    return (toff_t)-1;

  m->offset = (size_t)new_off;
  return new_off;
}

static int mem_close(thandle_t h) {
  (void)h;
  return 0;
}

static toff_t mem_size(thandle_t h) {
  mem_tiff_t *m = (mem_tiff_t *)h;
  return (toff_t)m->size;
}

static int mem_map(thandle_t h, tdata_t *base, toff_t *size) {
  mem_tiff_t *m = (mem_tiff_t *)h;
  *base = (tdata_t)m->data;
  *size = (toff_t)m->size;
  return 1;
}

static void mem_unmap(thandle_t h, tdata_t base, toff_t size) {
  (void)h; (void)base; (void)size;
}

/* ================= Decode helpers ================= */

static void fuzz_decode_strips(TIFF *tif) {
  tstrip_t nstrips = TIFFNumberOfStrips(tif);
  if (nstrips == 0 || nstrips > 4096) return;

  tsize_t bufsize = TIFFStripSize(tif);
  if (bufsize <= 0 || bufsize > (1 << 20)) return;

  uint8_t *buf = (uint8_t *)_TIFFmalloc(bufsize);
  if (!buf) return;

  for (tstrip_t i = 0; i < nstrips; i++) {
    /* Intentionally ignore return value */
    TIFFReadEncodedStrip(tif, i, buf, bufsize);
  }

  _TIFFfree(buf);
}

static void fuzz_decode_tiles(TIFF *tif) {
  ttile_t ntiles = TIFFNumberOfTiles(tif);
  if (ntiles == 0 || ntiles > 4096) return;

  tsize_t bufsize = TIFFTileSize(tif);
  if (bufsize <= 0 || bufsize > (1 << 20)) return;

  uint8_t *buf = (uint8_t *)_TIFFmalloc(bufsize);
  if (!buf) return;

  for (ttile_t i = 0; i < ntiles; i++) {
    TIFFReadEncodedTile(tif, i, buf, bufsize);
  }

  _TIFFfree(buf);
}

/* ================= Harness Core ================= */

static void fuzz_tiff(const uint8_t *data, size_t size) {
  if (size < 8 || size > MAX_INPUT_SIZE)
    return;

  mem_tiff_t mem = {
    .data = data,
    .size = size,
    .offset = 0
  };

  TIFF *tif = TIFFClientOpen(
      "mem",
      "r",
      (thandle_t)&mem,
      mem_read,
      mem_write,
      mem_seek,
      mem_close,
      mem_size,
      mem_map,
      mem_unmap);

  if (!tif)
    return;

  /* -------- Pass 1: directory walk + decode -------- */
  do {
    fuzz_decode_strips(tif);
    fuzz_decode_tiles(tif);
  } while (TIFFReadDirectory(tif));

  /* -------- Pass 2: rewind + re-walk -------- */
  if (TIFFSetDirectory(tif, 0)) {
    do {
      fuzz_decode_strips(tif);
      fuzz_decode_tiles(tif);
    } while (TIFFReadDirectory(tif));
  }

  /* -------- Pass 3: directory hopping -------- */
  uint16_t dircount = TIFFNumberOfDirectories(tif);
  if (dircount > 0 && dircount < 128) {
    uint16_t mid = dircount / 2;
    TIFFSetDirectory(tif, mid);
    fuzz_decode_strips(tif);
    fuzz_decode_tiles(tif);

    TIFFSetDirectory(tif, dircount - 1);
    fuzz_decode_strips(tif);
    fuzz_decode_tiles(tif);
  }

  /* -------- Pass 4: recovery after failure -------- */
  TIFFSetDirectory(tif, 0);
  fuzz_decode_strips(tif);

  TIFFClose(tif);
}

/* ================= AFL Persistent Entry ================= */

int main(void) {
  static uint8_t buf[MAX_INPUT_SIZE];

  while (__AFL_LOOP(AFL_PERSIST_ITERATIONS)) {
    ssize_t len = read(0, buf, sizeof(buf));
    if (len <= 0)
      break;

    fuzz_tiff(buf, (size_t)len);
  }

  return 0;
}
