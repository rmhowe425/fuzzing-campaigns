#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xls.h>

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

/* ===================== SAFE MEMORY TOUCH ===================== */

static inline void touch_mem(const volatile void *p, size_t n) {
    if (!p || n == 0) return;
    const volatile unsigned char *b = p;
    volatile unsigned char acc = 0;
    for (size_t i = 0; i < n; i++)
        acc ^= b[i];
    (void)acc;
}

/* ===================== BIFF STREAM STRESS ===================== */

/*
 * Aggressively re-enter worksheet parsing without touching
 * high-level semantics (cells, SST, formulas).
 *
 * CMPLog-friendly:
 *  - comparison-gated re-entry
 *  - deterministic behavior
 */
static void stress_worksheet_stream(xlsWorkSheet *ws,
                                    const uint8_t *raw,
                                    size_t raw_sz)
{
    if (!ws) return;

    /* Touch BIFF-derived bounds (comparison-heavy) */
    touch_mem(&ws->rows.lastrow, sizeof(ws->rows.lastrow));
    touch_mem(&ws->rows.lastcol, sizeof(ws->rows.lastcol));

    unsigned passes = 1;
    if (raw_sz > 2)
        passes += raw[1] & 3;  /* +0..3 */

    if (passes > MAX_PARSE_PASSES)
        passes = MAX_PARSE_PASSES;

    for (unsigned i = 0; i < passes; i++) {

        /* Re-entrant parse (hostile by design) */
        xls_parseWorkSheet(ws);

        /* Touch again to catch stale or partially updated state */
        touch_mem(&ws->rows.lastrow, sizeof(ws->rows.lastrow));
        touch_mem(&ws->rows.lastcol, sizeof(ws->rows.lastcol));

        /*
         * CMPLog-friendly conditional re-entry:
         * comparison-gated, deterministic, no noise.
         */
        if (raw_sz > 4 && (raw[(i + 2) % raw_sz] & 1)) {
            xls_parseWorkSheet(ws);
        }
    }
}

/*
 * Workbook-level BIFF stream abuse:
 *  - stresses sheet enumeration
 *  - worksheet lifetime rules
 *  - stream reset logic
 */
static void stress_workbook_stream(xlsWorkBook *wb,
                                   const uint8_t *raw,
                                   size_t raw_sz)
{
    if (!wb) return;

    /*
     * libxls-1.6.3 does NOT expose a biff_version field.
     * These fields together control BIFF parsing behavior.
     */
    touch_mem(&wb->is5ver,   sizeof(wb->is5ver));
    touch_mem(&wb->is1904,   sizeof(wb->is1904));
    touch_mem(&wb->codepage, sizeof(wb->codepage));

    /* Sheet enumeration is comparison-heavy */
    touch_mem(&wb->sheets.count, sizeof(wb->sheets.count));

    WORD max_sheets = wb->sheets.count;
    if (max_sheets > MAX_SHEETS)
        max_sheets = MAX_SHEETS;

    for (WORD i = 0; i < max_sheets; i++) {

        xlsWorkSheet *ws = xls_getWorkSheet(wb, i);
        if (!ws)
            continue;

        stress_worksheet_stream(ws, raw, raw_sz);
        xls_close_WS(ws);

        /*
         * Comparison-gated reopen:
         * stresses BIFF stream cursor and lifetime assumptions.
         */
        if (raw_sz && (raw[i % raw_sz] & 1)) {
            ws = xls_getWorkSheet(wb, i);
            if (ws) {
                stress_worksheet_stream(ws, raw, raw_sz);
                xls_close_WS(ws);
            }
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

    /* Long-lived reusable buffer (intentional, leak-free) */
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

    /*
     * CMPLog-friendly multi-open:
     * gated by input comparisons, deterministic.
     */
    unsigned opens = 1;
    if (Size > 0)
        opens += buf[Size - 1] & 3;  /* +0..3 */

    if (opens > MAX_OPEN_PASSES)
        opens = MAX_OPEN_PASSES;

    for (unsigned i = 0; i < opens; i++) {

        xlsWorkBook *wb = xls_open_buffer(buf, Size, NULL, &err);
        if (!wb)
            continue;

        stress_workbook_stream(wb, buf, Size);

        /*
         * Lifetime churn: close and optionally reopen
         * under comparison control (CMPLog-friendly).
         */
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

/* ===================== AFL++ PERSISTENT ===================== */

#ifdef __AFL_HAVE_MANUAL_CONTROL
int main(void)
{
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
