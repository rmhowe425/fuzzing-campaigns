// afl_iproute2_attr_harness_safe_v2.c

#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnetlink.h"
#include "utils.h"

#ifndef MAX_MSG
#define MAX_MSG 4096
#endif

#ifndef MAX_ATTR
#define MAX_ATTR 256
#endif

#ifndef MAX_ATTR_PAYLOAD
#define MAX_ATTR_PAYLOAD 1024
#endif

static uint8_t global_buf[MAX_MSG];

int main(void)
{
    static uint8_t input_buf[4096];

    while (__AFL_LOOP(1000)) {

        ssize_t len = read(0, input_buf, sizeof(input_buf));
        if (len <= 0)
            continue;

        memset(global_buf, 0, sizeof(global_buf));

        struct nlmsghdr *nlh = (struct nlmsghdr *)global_buf;
        nlh->nlmsg_len = NLMSG_LENGTH(0);

        uint8_t *p = input_buf;
        size_t remaining = (size_t)len;

        int attr_index = 0;

        while (remaining >= 5 && attr_index < MAX_ATTR - 1) {

            uint16_t type;
            uint16_t len_hint;

            memcpy(&type, p, sizeof(type));
            p += 2; remaining -= 2;

            memcpy(&len_hint, p, sizeof(len_hint));
            p += 2; remaining -= 2;

            uint8_t flag = *p;
            p += 1; remaining -= 1;

            /* Keep type in a reasonable attribute namespace */
            type %= 64;

            /* Avoid modulo bias; keep fuzz signal intact */
            size_t payload_len = len_hint & 0x03FF;  // 0..1023 range

            if (payload_len > remaining)
                payload_len = remaining;

            if (payload_len > MAX_ATTR_PAYLOAD)
                payload_len = MAX_ATTR_PAYLOAD;

            uint8_t *payload = p;

            p += payload_len;
            remaining -= payload_len;

            /* SAFER FLAG HANDLING */
            uint8_t f = flag & 0x07;

            if (f & 0x01) {
                addattr_l(nlh, MAX_MSG, type, payload, payload_len);
            }

            if ((f & 0x02) && payload_len >= sizeof(uint32_t)) {
                uint32_t v32;
                memcpy(&v32, payload, sizeof(v32));
                addattr32(nlh, MAX_MSG, type, v32);
            }

            if ((f & 0x04) && payload_len >= sizeof(uint64_t)) {
                uint64_t v64;
                memcpy(&v64, payload, sizeof(v64));
                addattr64(nlh, MAX_MSG, type, v64);
            }

            attr_index++;
        }

        /* =========================
         * SAFE PARSING PHASE
         * ========================= */

        if (nlh->nlmsg_len < NLMSG_LENGTH(0) || nlh->nlmsg_len > MAX_MSG)
            continue;

        int parse_len = nlh->nlmsg_len - NLMSG_LENGTH(0);

        if (parse_len <= 0 || parse_len > (int)(MAX_MSG - NLMSG_LENGTH(0)))
            continue;

        struct rtattr *tb[MAX_ATTR];
        memset(tb, 0, sizeof(tb));

        uint8_t *data = (uint8_t *)NLMSG_DATA(nlh);

        parse_rtattr(tb, MAX_ATTR - 1, (struct rtattr *)data, parse_len);

        /* Mask flags to avoid pathological parsing behavior */
        uint32_t flags = input_buf[0] & 0xFF;

        parse_rtattr_flags(tb,
                            MAX_ATTR - 1,
                            (struct rtattr *)data,
                            parse_len,
                            flags);

        /* Separate table for nested parsing (prevents overwrite issues) */
        for (int i = 0; i < 8; i++) {
            if (tb[i]) {
                struct rtattr *tb2[MAX_ATTR];
                memset(tb2, 0, sizeof(tb2));

                parse_rtattr_nested(tb2, MAX_ATTR - 1, tb[i]);
            }
        }

        /* Prevent compiler optimizing away */
        volatile uint32_t sink = nlh->nlmsg_len;
        (void)sink;
    }

    return 0;
}
