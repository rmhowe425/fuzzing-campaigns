#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include <unistd.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
#include <unistd.h>
#endif

#define MAX_FILE  (1 << 20)
#define MAX_CHUNK 4096

static uint8_t buf[MAX_FILE];

/* ================= Progressive callbacks ================= */

static void info_callback(png_structp png_ptr, png_infop info_ptr) {
    (void)png_ptr;
    (void)info_ptr;
}

static void row_callback(png_structp png_ptr, png_bytep new_row,
                         png_uint_32 row_num, int pass) {
    (void)png_ptr;
    (void)pass;

    if (new_row) {
        volatile uint8_t x = new_row[row_num % 8];
        (void)x;
    }
}

static void end_callback(png_structp png_ptr, png_infop info_ptr) {
    (void)png_ptr;
    (void)info_ptr;
}

/* ================= Custom chunk handler ================= */

static int user_chunk_handler(png_structp png_ptr, png_unknown_chunkp chunk) {
    (void)png_ptr;

    if (chunk && chunk->size && chunk->data) {
        volatile uint8_t tmp = chunk->data[chunk->size % 8];
        (void)tmp;
    }

    return PNG_HANDLE_CHUNK_AS_DEFAULT;
}

/* ================= Random transforms ================= */

static void apply_random_transforms(png_structp png_ptr,
                                    const uint8_t *data,
                                    size_t size) {

    if (!data || size < 2)
        return;

    uint8_t flags = data[0] ^ data[size - 1];

    if (flags & 1)   png_set_expand(png_ptr);
    if (flags & 2)   png_set_strip_16(png_ptr);
    if (flags & 4)   png_set_packing(png_ptr);
    if (flags & 8)   png_set_gray_to_rgb(png_ptr);
    if (flags & 16)  png_set_palette_to_rgb(png_ptr);
    if (flags & 32)  png_set_tRNS_to_alpha(png_ptr);
    if (flags & 64)  png_set_bgr(png_ptr);
    if (flags & 128) png_set_swap_alpha(png_ptr);
}

/* ================= Memory-backed read callback ================= */

static void memory_read_fn(png_structp png_ptr, png_bytep outBytes, png_size_t byteCountToRead) {
    uint8_t **p = (uint8_t **)png_get_io_ptr(png_ptr);
    memcpy(outBytes, *p, byteCountToRead);
    *p += byteCountToRead;
}

/* ================= Progressive mode ================= */

static void fuzz_progressive(const uint8_t *data, size_t size) {

    png_structp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

    if (!png_ptr) return;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    png_set_user_limits(png_ptr, 16384, 16384);
    png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

    png_set_progressive_read_fn(png_ptr, NULL,
                                info_callback, row_callback, end_callback);

    png_set_read_user_chunk_fn(png_ptr, NULL, user_chunk_handler);

    if (size < 8) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    png_process_data(png_ptr, info_ptr, (png_bytep)data, 8);

    apply_random_transforms(png_ptr, data, size);

    size_t offset = 8;

    while (offset < size) {
        size_t chunk = (size - offset) > MAX_CHUNK ?
                       ((data[offset] % MAX_CHUNK) + 1) :
                       (size - offset);
        if (chunk == 0) chunk = 1;

        png_process_data(png_ptr, info_ptr,
                         (png_bytep)(data + offset), chunk);
        offset += chunk;
    }

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
}

/* ================= Full decode mode ================= */

static void fuzz_full(const uint8_t *data, size_t size) {

    png_structp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

    if (!png_ptr) return;

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
    png_set_read_fn(png_ptr, (png_voidp)&data, memory_read_fn);

    if (size >= 8)
        png_read_info(png_ptr, info_ptr);

    apply_random_transforms(png_ptr, data, size);

    png_read_update_info(png_ptr, info_ptr);

    png_uint_32 width, height;
    int bit_depth, color_type;

    png_get_IHDR(png_ptr, info_ptr,
                 &width, &height,
                 &bit_depth, &color_type,
                 NULL, NULL, NULL);

    if (width == 0 || height == 0 || width > 16384 || height > 16384) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    png_bytep row = (png_bytep)malloc(rowbytes ? rowbytes : 1);
    if (!row) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return;
    }

    for (png_uint_32 y = 0; y < height; y++) {
        png_read_row(png_ptr, row, NULL);
        volatile uint8_t x = row[y % (rowbytes ? rowbytes : 1)];
        (void)x;
    }

    free(row);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
}

/* ================= Main ================= */

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(1000)) {
        ssize_t len = read(STDIN_FILENO, buf, MAX_FILE);
        if (len <= 0) continue;

        size_t size = (size_t)len;
        if (size < 8) continue;

        if (buf[0] & 1)
            fuzz_progressive(buf, size);
        else
            fuzz_full(buf, size);
    }

    return 0;
}
