#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>


#define MAX_FILTER_LEN 4096
#define MAX_ITERATIONS 5000

static pcap_t *pcap = NULL;

/* Diverse DLTs that exercise distinct code paths */
static const int dlt_table[] = {
    DLT_RAW,
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_IPV4,
    DLT_IPV6,
    DLT_NULL,
    DLT_LOOP
};

static inline int pick_dlt(uint8_t b) {
    return dlt_table[b % (sizeof(dlt_table) / sizeof(dlt_table[0]))];
}

int main(void) {
    uint8_t buf[MAX_FILTER_LEN + 1];

    /* One-time initialization */
    pcap = pcap_open_dead(DLT_RAW, 65535);
    if (!pcap)
        return 1;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(MAX_ITERATIONS)) {

        ssize_t len = read(STDIN_FILENO, buf, MAX_FILTER_LEN);
        if (len <= 0)
            continue;

        buf[len] = '\0';

        uint8_t selector = buf[0];

        /* Optional controlled truncation to help AFL escape grammar plateaus */
        if (selector & 0x80 && len > 1) {
            len >>= 1;
            buf[len] = '\0';
        }

        int dlt = pick_dlt(selector);

        /* Reconfigure DLT – skip invalid transitions */
        if (pcap_set_datalink(pcap, dlt) != 0)
            continue;

        /* Snaplen variation affects codegen paths */
        int snaplen = 64 + ((int)selector << 8);
        if (snaplen > 65535)
            snaplen = 65535;

        pcap_set_snaplen(pcap, snaplen);

        struct bpf_program program;
        memset(&program, 0, sizeof(program));

        /* Multi-pass compilation stresses internal state handling */
        for (int i = 0; i < 3; i++) {
            int optimize = i & 1;
            int netmask;

            switch (i) {
                case 0:
                    netmask = 0;
                    break;
                case 1:
                    netmask = 0xFFFFFFFF;
                    break;
                default:
                    netmask = (selector & 0x40) ? 0xFFFFFF00 : 0;
                    break;
            }

            int ret = pcap_compile(
                pcap,
                &program,
                (const char *)buf,
                optimize,
                netmask
            );

            if (ret == 0) {
                pcap_freecode(&program);
                memset(&program, 0, sizeof(program));
            }
        }
    }

    pcap_close(pcap);
    return 0;
}

