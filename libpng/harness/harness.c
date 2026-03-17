#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include <unistd.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
#include <unistd.h>
#endif

#define MAX_FILE  (1 << 20)   /* 1 MB max input */
#define MAX_CHUNK 4096         /* incremental feed chunk */

/* --- Progressive callbacks --- */
static void info_callback(png_structp png_ptr, png_infop info_ptr) {
    (void)png_ptr;
    (void)info_ptr;
}

static void row_callback(png_structp png_ptr, png_bytep new_row,
                         png_uint_32 row_num, int pass) {
    (void)png_ptr;
    (void)new_row;
    (void)row_num;
    (void)pass;
}

static void end_callback(png_structp png_ptr, png_infop info_ptr) {
    (void)png_ptr;
    (void)info_ptr;
}

/* --- Custom chunk handler (safe) --- */
static int user_chunk_handler(png_structp png_ptr, png_unknown_chunkp chunk) {
    (void)png_ptr;
    if (chunk && chunk->size >= 1 && chunk->data) {
        volatile uint8_t tmp = chunk->data[0];
        (void)tmp;
    }
    return PNG_HANDLE_CHUNK_AS_DEFAULT;
}

/* --- Randomized transforms after header --- */
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

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    static uint8_t buf[MAX_FILE];

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(1000)) {

        ssize_t len = read(STDIN_FILENO, buf, MAX_FILE);
        if (len <= 0)
            continue;

        const uint8_t *data = buf;
        size_t size = (size_t)len;

        if (size < 8)  // Minimum PNG signature size
            continue;

        png_structp png_ptr = png_create_read_struct(
            PNG_LIBPNG_VER_STRING,
            NULL, NULL, NULL);

        if (!png_ptr)
            continue;

        png_infop info_ptr = png_create_info_struct(png_ptr);
        if (!info_ptr) {
            png_destroy_read_struct(&png_ptr, NULL, NULL);
            continue;
        }

        /* --- Setjmp for libpng errors --- */
        if (setjmp(png_jmpbuf(png_ptr))) {
            png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
            continue;
        }

        /* Prevent excessive memory allocations */
        png_set_user_limits(png_ptr, 4096, 4096);

        /* Allow malformed CRCs for fuzzing */
        png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

        /* Progressive callbacks */
        png_set_progressive_read_fn(png_ptr, NULL,
                                    info_callback, row_callback, end_callback);

        /* Safe user chunk handler */
        png_set_read_user_chunk_fn(png_ptr, NULL, user_chunk_handler);

        /* --- Feed first 8 bytes (PNG signature) --- */
        if (setjmp(png_jmpbuf(png_ptr))) {
            png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
            continue;
        }
        png_process_data(png_ptr, info_ptr, (png_bytep)data, 8);

        /* --- Apply transforms safely after header --- */
        apply_random_transforms(png_ptr, data, size);

        /* --- Incremental feed of remaining data --- */
        size_t offset = 8;
        while (offset < size) {
            size_t chunk = (size - offset) > MAX_CHUNK ? 
                           ((data[offset] % MAX_CHUNK) + 1) : (size - offset);

            if (chunk == 0)
                chunk = 1;  // Always feed at least 1 byte

            if (setjmp(png_jmpbuf(png_ptr))) {
                break;  // Skip remaining data on internal libpng error
            }

            png_process_data(png_ptr, info_ptr, (png_bytep)(data + offset), chunk);
            offset += chunk;
        }

        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    }

    return 0;
}
