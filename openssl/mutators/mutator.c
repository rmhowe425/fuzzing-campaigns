#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const char **afl_custom_dict;
extern size_t afl_custom_dict_len;

#define MAX_TLS_HEADER 5
#define MAX_BUF 65536

// ------------------ Utilities ------------------

static int is_der_sequence(const uint8_t *data, size_t size) {
    return size > 2 && (data[0] & 0x1F) <= 0x1F && data[0] >= 0x30;
}

static int der_length_bytes(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    if ((data[1] & 0x80) == 0) return 1; 
    return 1 + (data[1] & 0x7F);
}

static int rand_range(int min, int max) {
    return min + rand() % (max - min + 1);
}

// ------------------ Mutation Functions ------------------

static void mutate_tls_header(uint8_t *data, size_t size) {
    if (size < MAX_TLS_HEADER) return;
    int r = rand_range(0, 6);
    switch (r) {
        case 0: data[0] = 0x16; break;
        case 1: data[1] ^= 0x03; break;
        case 2: data[2] ^= 0x03; break;
        case 3: data[3] ^= 0xFF; break;
        case 4: data[4] ^= 0xFF; break;
        case 5: data[0] = 0x14; break;
        case 6: data[0] = 0x17; break;
    }
}

static void mutate_der(uint8_t *data, size_t size) {
    if (!is_der_sequence(data, size)) return;
    size_t idx = rand_range(0, size - 1);
    data[idx] ^= (uint8_t)(rand() & 0xFF);
    if (idx + 1 < size && rand_range(0, 1)) data[idx + 1] ^= (uint8_t)(rand() & 0xFF);

    int len_bytes = der_length_bytes(data, size);
    for (int i = 0; i < len_bytes; i++) {
        size_t pos = 1 + i;
        if (pos < size) data[pos] ^= (uint8_t)(rand() & 0xFF);
    }

    if (size > 6 && rand_range(0, 3) == 0) {
        size_t mid = size / 2;
        for (size_t i = 0; i < mid; i++) {
            uint8_t tmp = data[i];
            data[i] = data[mid + i];
            data[mid + i] = tmp;
        }
    }
}

static void mutate_evp_string(uint8_t *data, size_t size) {
    if (size < 3) return;
    size_t pos = rand_range(0, size - 1);
    data[pos] = (uint8_t)('A' + rand() % 26);
    if (rand_range(0, 2) == 0 && size > 1) data[size - 1] = 0;
    else if (rand_range(0, 2) == 1 && size + 1 < MAX_BUF) data[size] = (uint8_t)('Z');
}

static void inject_dict_token(uint8_t *data, size_t *size) {
    if (afl_custom_dict_len == 0 || *size >= MAX_BUF / 2) return;
    size_t token_idx = rand_range(0, afl_custom_dict_len - 1);
    const char *tok = afl_custom_dict[token_idx];
    size_t tok_len = strlen(tok);
    if (*size + tok_len >= MAX_BUF) return;
    size_t pos = rand_range(0, *size);
    memmove(data + pos + tok_len, data + pos, *size - pos);
    memcpy(data + pos, tok, tok_len);
    *size += tok_len;
}

static void mutate_tls_fragment(uint8_t *data, size_t *size) {
    if (*size < 5) return;
    size_t cut = rand_range(1, *size / 2);
    memmove(data + cut, data, *size - cut);
}

static void havoc_mutation(uint8_t *data, size_t *size) {
    if (*size == 0) return;
    int action = rand_range(0, 3);
    switch (action) {
        case 0: mutate_tls_header(data, *size); break;
        case 1: mutate_der(data, *size); break;
        case 2: mutate_evp_string(data, *size); break;
        case 3: mutate_tls_fragment(data, size); break;
    }
}

// ------------------ AFL++ Interface ------------------

int afl_custom_init(void *afl) {
    srand((unsigned int)time(NULL));
    return 0;
}

void afl_custom_deinit(void) {
    // Nothing to free for now
}

size_t afl_custom_mutator(uint8_t *data, size_t size, uint8_t *out, size_t max_size, unsigned int seed) {
    if (size > max_size) size = max_size;
    memcpy(out, data, size);
    size_t new_size = size;
    srand(seed ^ (uint32_t)time(NULL));

    if (size == 0) return 0;

    if (rand_range(0, 1)) mutate_tls_header(out, new_size);
    if (rand_range(0, 1)) mutate_der(out, new_size);
    if (rand_range(0, 1)) mutate_evp_string(out, new_size);
    if (rand_range(0, 1)) inject_dict_token(out, &new_size);
    if (rand_range(0, 1)) mutate_tls_fragment(out, &new_size);
    if (rand_range(0, 1)) havoc_mutation(out, &new_size);

    if (new_size > MAX_BUF) new_size = MAX_BUF;
    return new_size;
}

size_t afl_custom_crossover(uint8_t *out, size_t out_size,
                            const uint8_t *src1, size_t src1_size,
                            const uint8_t *src2, size_t src2_size,
                            unsigned int seed) {
    srand(seed ^ (uint32_t)time(NULL));
    size_t copy1 = src1_size / 2;
    if (copy1 > out_size) copy1 = out_size;
    memcpy(out, src1, copy1);
    size_t copy2 = src2_size / 2;
    if (copy1 + copy2 > out_size) copy2 = out_size - copy1;
    memcpy(out + copy1, src2, copy2);
    size_t final_size = copy1 + copy2;
    if (final_size == 0 && out_size > 0) out[0] = 0;
    return final_size;
}
