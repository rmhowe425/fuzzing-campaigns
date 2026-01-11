#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <xls.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

#define MAX_FUZZ_SIZE     (1 << 20)
#define MAX_ITER_ROWS    50000
#define MAX_ITER_COLS    16384
#define MAX_SST_STRINGS  200000
#define MAX_STRING_LEN   4096  /* SAFE STRING BOUND */

#define PERSIST_ITERS    100
#define HARD_RESET_ITERS 5000

/* ---------------- Safe Memory Touch ---------------- */

static inline void touch_mem(const volatile void *p, size_t n) {
    if (!p || n == 0) return;
    const volatile unsigned char *b = p;
    volatile unsigned char acc = 0;
    for (size_t i = 0; i < n; i++)
        acc ^= b[i];
    (void)acc;
}

static size_t safe_strlen(const char *s, size_t max_len) {
    if (!s) return 0;
    size_t i = 0;
    for (; i < max_len && s[i]; i++);
    return i;
}

/* ---------------- SST Exploration ---------------- */

static void explore_sst(xlsWorkBook *wb,
                        const uint8_t *raw,
                        size_t raw_sz) {
    if (!wb) return;

    touch_mem(&wb->sst.count, sizeof(wb->sst.count));
    if (wb->sst.count > MAX_SST_STRINGS) return;

    for (DWORD i = 0; i < wb->sst.count; i++) {
        char *s = wb->sst.string[i].str;
        size_t len = safe_strlen(s, MAX_STRING_LEN);
        if (len) touch_mem(s, len);
        if (len) touch_mem(s + len - 1, 1);
    }

    if (wb->sst.count && raw_sz) {
        DWORD idx = raw[raw_sz / 2] % (wb->sst.count * 2);
        if (idx < wb->sst.count) {
            char *s = wb->sst.string[idx].str;
            touch_mem(s, safe_strlen(s, MAX_STRING_LEN));
        }
    }
}

/* ---------------- Worksheet Exploration ---------------- */

static void explore_sheet(xlsWorkSheet *ws,
                          const uint8_t *raw,
                          size_t raw_sz) {
    if (!ws) return;

    xls_parseWorkSheet(ws);

    DWORD max_r = ws->rows.lastrow;
    DWORD max_c = ws->rows.lastcol;

    if (max_r > MAX_ITER_ROWS) max_r = MAX_ITER_ROWS;
    if (max_c > MAX_ITER_COLS) max_c = MAX_ITER_COLS;

    touch_mem(&ws->rows.lastrow, sizeof(ws->rows.lastrow));
    touch_mem(&ws->rows.lastcol, sizeof(ws->rows.lastcol));

    for (DWORD r = 0; r <= max_r;
         r += (raw_sz ? (raw[r % raw_sz] + 1) : 1)) {

        for (DWORD c = 0; c <= max_c;
             c += (raw_sz ? (raw[(r + c) % raw_sz] + 1) : 1)) {

            xlsCell *cell = xls_cell(ws, r, c);
            if (!cell) continue;

            touch_mem(&cell->id, sizeof(cell->id));

            switch (cell->id) {
            case XLS_RECORD_LABEL:
            case XLS_RECORD_RSTRING:
            case XLS_RECORD_FORMULA:
                if (cell->str)
                    touch_mem(cell->str, safe_strlen(cell->str, MAX_STRING_LEN));
                break;

            case XLS_RECORD_NUMBER:
                touch_mem(&cell->d, sizeof(cell->d));
                break;

            default:
                break;
            }

            if (cell->id == XLS_RECORD_FORMULA)
                touch_mem(&cell->l, sizeof(cell->l));
        }
    }
}

/* ---------------- Fuzzer Entry ---------------- */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static unsigned long execs = 0;

    if (++execs % HARD_RESET_ITERS == 0)
        _exit(0);

    if (Size < 8 || Size > MAX_FUZZ_SIZE)
        return 0;

    uint8_t *buf = malloc(Size);
    if (!buf)
        return 0;
    memcpy(buf, Data, Size);

    xls_error_t err = 0;
    xlsWorkBook *wb = xls_open_buffer(buf, Size, NULL, &err);

    explore_sst(wb, buf, Size);

    if (wb) {
        for (WORD i = 0; i < wb->sheets.count; i++) {
            xlsWorkSheet *ws = xls_getWorkSheet(wb, i);
            if (!ws) continue;
            explore_sheet(ws, buf, Size);
            xls_close_WS(ws);
        }
        xls_close_WB(wb);
    }

    free(buf);
    return 0;
}

/* ---------------- AFL++ Persistent Loop ---------------- */

#ifdef __AFL_HAVE_MANUAL_CONTROL
int main(void) {
    __AFL_INIT();
    while (__AFL_LOOP(PERSIST_ITERS)) {
        LLVMFuzzerTestOneInput(
            __AFL_FUZZ_TESTCASE_BUF,
            __AFL_FUZZ_TESTCASE_LEN
        );
    }
    return 0;
}
#endif
