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
#define MAX_FORMULA_CELLS    150000
#define MAX_FORMULA_PASSES   3
#define MAX_STRING_LEN       4096

#define PERSIST_ITERS        100
#define HARD_RESET_ITERS     4000

/* ===================== SAFE MEMORY TOUCH ===================== */

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

/* ===================== FORMULA MUTATOR ===================== */

/* 
 * Mutates formula-related content in cell references, operators, and formula strings.
 * The goal is to introduce errors that test formula evaluation and handling.
 */
static void mutate_formula(uint8_t *raw, size_t *raw_sz) {
    if (*raw_sz < 8) return;

    // Randomly mutate formula parts
    for (size_t i = 0; i < *raw_sz; i++) {
        if (rand() % 4 == 0) {
            // Randomly corrupt cell references (e.g., A1 -> B2)
            if (raw[i] >= 'A' && raw[i] <= 'Z' && i + 1 < *raw_sz && raw[i + 1] >= '1' && raw[i + 1] <= '9') {
                raw[i] = 'A' + (rand() % 26);  // Randomize column
                raw[i + 1] = '1' + (rand() % 9);  // Randomize row
            }
        }

        if (rand() % 3 == 0) {
            // Randomly corrupt formula operators (e.g., +, -, *, /)
            if (raw[i] == '+' || raw[i] == '-' || raw[i] == '*' || raw[i] == '/') {
                raw[i] = "+-*/"[rand() % 4];  // Randomize operator
            }
        }

        if (rand() % 5 == 0) {
            // Add invalid commas or arguments to formula functions
            if (raw[i] == 'S' && raw[i + 1] == 'U' && raw[i + 2] == 'M') {
                if (raw[i + 3] == '(') {
                    raw[i + 4] = ',';  // Malformed SUM function: SUM(A1,,B2)
                }
            }
        }

        if (rand() % 2 == 0) {
            // Introduce invalid function arguments (e.g., missing parentheses)
            if (raw[i] == '(') {
                raw[i + 2] = ')';  // Corrupt arguments
            }
        }
    }
}

/* ===================== FORMULA STRESS CORE ===================== */

/*
 * Focused on mutating formula-related state, ensuring no metadata or sheet churn.
 */
static void stress_formula_cell(xlsCell *cell,
                                const uint8_t *raw,
                                size_t raw_sz,
                                uint32_t salt)
{
    if (!cell) return;

    /* Identity & location */
    touch_mem(&cell->id,  sizeof(cell->id));
    touch_mem(&cell->row, sizeof(cell->row));
    touch_mem(&cell->col, sizeof(cell->col));

    /* Cached formula result */
    touch_mem(&cell->l, sizeof(cell->l));

    /* Formula string result (if present) */
    if (cell->str) {
        size_t len = safe_strlen(cell->str, MAX_STRING_LEN);
        if (len) {
            touch_mem(cell->str, len);
            touch_mem(cell->str + (salt % len), 1);
        }
    }

    /* Deterministic re-touching to vary access order */
    if (raw_sz) {
        switch (raw[salt % raw_sz] & 3) {
        case 0:
            touch_mem(&cell->l, sizeof(cell->l));
            break;
        case 1:
            if (cell->str)
                touch_mem(cell->str,
                          safe_strlen(cell->str, MAX_STRING_LEN));
            break;
        case 2:
            touch_mem(&cell->row, sizeof(cell->row));
            touch_mem(&cell->col, sizeof(cell->col));
            break;
        default:
            break;
        }
    }
}

/* ===================== FORMULA WALK ===================== */

/*
 * Iterates through worksheet formula cells and applies stress and mutations.
 */
static void explore_formulas(xlsWorkSheet *ws,
                             const uint8_t *raw,
                             size_t raw_sz)
{
    if (!ws) return;

    /* Initial parse */
    xls_parseWorkSheet(ws);

    DWORD max_r = ws->rows.lastrow;
    DWORD max_c = ws->rows.lastcol;

    /* Hard safety caps */
    if (max_r > 20000) max_r = 20000;
    if (max_c > 8192)  max_c = 8192;

    uint32_t seen = 0;

    /* First pass: find and stress formula cells only */
    for (DWORD r = 0; r <= max_r && seen < MAX_FORMULA_CELLS; r++) {
        for (DWORD c = 0; c <= max_c && seen < MAX_FORMULA_CELLS; c++) {
            xlsCell *cell = xls_cell(ws, r, c);
            if (!cell || cell->id != XLS_RECORD_FORMULA)
                continue;

            stress_formula_cell(cell, raw, raw_sz, (r << 16) ^ c);
            seen++;
        }
    }

    /* Controlled re-parse passes */
    unsigned passes = 1;
    if (raw_sz)
        passes += (raw[0] & 1);

    if (passes > MAX_FORMULA_PASSES)
        passes = MAX_FORMULA_PASSES;

    for (unsigned p = 0; p < passes; p++) {
        xls_parseWorkSheet(ws);

        for (DWORD r = 0; r <= max_r && seen < MAX_FORMULA_CELLS; r++) {
            for (DWORD c = 0; c <= max_c && seen < MAX_FORMULA_CELLS; c++) {
                xlsCell *cell = xls_cell(ws, r, c);
                if (!cell || cell->id != XLS_RECORD_FORMULA)
                    continue;

                stress_formula_cell(cell, raw, raw_sz, 0xA5A50000u ^ (p << 16) ^ (r + c));
                seen++;
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
    xlsWorkBook *wb = xls_open_buffer(buf, Size, NULL, &err);
    if (!wb)
        return 0;

    /* Only iterate worksheets; no SST, no metadata churn */
    for (WORD i = 0; i < wb->sheets.count; i++) {
        xlsWorkSheet *ws = xls_getWorkSheet(wb, i);
        if (!ws) continue;

        explore_formulas(ws, buf, Size);
        xls_close_WS(ws);
    }

    xls_close_WB(wb);
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
