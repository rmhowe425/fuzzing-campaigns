#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xls.h>
#include <limits.h>
#include <time.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

/* ===================== CONFIG ===================== */

#define MAX_FUZZ_SIZE        (1 << 20)
#define MAX_SHEETS           256
#define MAX_PARSE_PASSES     6
#define MAX_OPEN_PASSES      4

#define PERSIST_ITERS        100
#define HARD_RESET_ITERS     3000

#define MUTATE_SPEED          10
#define MAX_BIFF_MUTATIONS    1000  // Limit the number of mutations for efficiency

/* ===================== SAFE MEMORY TOUCH ===================== */

static inline void touch_mem(const volatile void *p, size_t n) {
    if (!p || n == 0) return;
    const volatile unsigned char *b = p;
    volatile unsigned char acc = 0;
    for (size_t i = 0; i < n; i++)
        acc ^= b[i];
    (void)acc;
}

/* ===================== AGGRESSIVE BIFF MUTATIONS ===================== */

static void mutate_biff_stream(uint8_t *raw, size_t *raw_sz) {
    if (*raw_sz < 8) return;

    size_t max_mutations = rand() % MAX_BIFF_MUTATIONS;

    for (size_t i = 0; i < *raw_sz && i < max_mutations; i++) {
        // Aggressive bit-flip mutation: flip a random bit in a byte
        if (rand() % MUTATE_SPEED == 0) {
            raw[i] ^= (1 << (rand() % 8));  // Flip a random bit
        }

        // Sheet count mutation
        if (i == 4 && rand() % 2 == 0) {
            *(uint16_t*)&raw[i] = rand() % MAX_SHEETS;
        }

        // Randomly corrupt record size or truncate file size
        if (i == 6 && rand() % 2 == 0) {
            *raw_sz = rand() % (*raw_sz);  
        }

        // Random record size change
        if (rand() % 2 == 0 && i < *raw_sz - 2) {
            uint16_t *record_size = (uint16_t*)&raw[i];
            *record_size = rand() % 0xFFFF;  
        }

        // Corrupting invalid values
        if (i == 8 && rand() % 3 == 0) {
            *(uint16_t*)&raw[i] = rand() % 1000;
        }
    }
}

/* ===================== FUZZ ENTRY ===================== */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    static unsigned long execs = 0;

    if (++execs % HARD_RESET_ITERS == 0)
        _exit(0);

    if (Size < 8 || Size > MAX_FUZZ_SIZE)
        return 0;

    static uint8_t *buf = NULL;
    static size_t   buf_sz = 0;

    if (buf_sz < Size) {
        uint8_t *new_buf = realloc(buf, Size);
        if (!new_buf)
            return 0;
        buf = new_buf;
        buf_sz = Size;
    }

    memcpy(buf, Data, Size);

    xls_error_t err = 0;
    unsigned opens = 1;
    if (Size > 0)
        opens += buf[Size - 1] & 3;

    if (opens > MAX_OPEN_PASSES)
        opens = MAX_OPEN_PASSES;

    // Apply intelligent mutations to the BIFF stream before running
    mutate_biff_stream(buf, &Size);

    for (unsigned i = 0; i < opens; i++) {

        xlsWorkBook *wb = xls_open_buffer(buf, Size, NULL, &err);
        if (!wb)
            continue;

        // Stress test with mutations
        stress_workbook_stream(wb, buf, Size);

        if (Size > 4 && (buf[(i + 3) % Size] & 1)) {
            xls_close_WB(wb);
            wb = xls_open_buffer(buf, Size, NULL, &err);
            if (wb) {
                stress_workbook_stream(wb, buf, Size);
                xls_close_WB(wb);
            }
        } else {
            xls_close_WB(wb);
        }
    }

    return 0;
}
