/* bench.c -- замер производительности: циклов на байт (раздел 10.3). */

#include "dedalyan.h"
#include "kernels.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#  define RDTSC() __rdtsc()
#elif defined(__x86_64__) || defined(__i386__)
#  include <x86intrin.h>
#  define RDTSC() __rdtsc()
#else
#  define RDTSC() ((uint64_t)0)     /* нет счётчика тактов -- только время */
#endif

static double now_sec(void)
{
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

static void report(const char *what, uint64_t cycles, double secs, size_t bytes)
{
    double cpb = bytes ? (double)cycles / (double)bytes : 0.0;
    double mibs = secs > 0.0 ? (double)bytes / secs / (1024.0 * 1024.0) : 0.0;
    if (cycles)
        printf("  %-22s %8.2f cycles/byte   %8.2f MiB/s\n", what, cpb, mibs);
    else
        printf("  %-22s %8s cycles/byte   %8.2f MiB/s\n", what, "n/a", mibs);
}

int main(int argc, char **argv)
{
    size_t mib = 64;
    size_t nbytes;
    uint8_t *buf;
    uint8_t key[32], counter[12];
    dedalyan_ctx ctx;
    uint64_t c0, c1;
    double t0, t1;
    size_t i;

    if (argc > 1) mib = (size_t)strtoul(argv[1], NULL, 10);
    if (mib == 0) mib = 1;
    nbytes = mib * 1024u * 1024u;

    buf = (uint8_t *)malloc(nbytes);
    if (!buf) { fprintf(stderr, "out of memory\n"); return 1; }
    memset(buf, 0xA5, nbytes);

    for (i = 0; i < 32; i++) key[i] = (uint8_t)(i * 11 + 3);
    memset(counter, 0, 12);

    printf("Dedalyan benchmark -- %s\n", dedalyan_version());
    printf("Buffer: %llu MiB\n\n", (unsigned long long)mib);

    /* Инициализация ключа. */
    {
        const size_t NKEYS = 200000;
        c0 = RDTSC(); t0 = now_sec();
        for (i = 0; i < NKEYS; i++) {
            key[0] = (uint8_t)i;
            dedalyan_key_setup(&ctx, key);
        }
        c1 = RDTSC(); t1 = now_sec();
        printf("  %-22s %8.1f cycles/setup  %8.0f setups/s\n", "key setup",
               (double)(c1 - c0) / (double)NKEYS,
               (double)NKEYS / (t1 - t0 > 0 ? t1 - t0 : 1e-9));
    }

    dedalyan_key_setup(&ctx, key);

    /* CTR: основной режим для потоковых данных. */
    c0 = RDTSC(); t0 = now_sec();
    dedalyan_ctr(&ctx, counter, buf, buf, nbytes, 16);
    c1 = RDTSC(); t1 = now_sec();
    report("CTR encrypt", c1 - c0, t1 - t0, nbytes);

    /* ECB-подобный пакетный проход: чистая скорость примитива. */
    {
        size_t nblocks = nbytes / 16;   /* по 2 uint64 на блок */
        uint64_t *io = (uint64_t *)buf;
        c0 = RDTSC(); t0 = now_sec();
        dedalyan_encrypt_blocks(&ctx, io, nblocks, 16);
        c1 = RDTSC(); t1 = now_sec();
        report("block encrypt (bulk)", c1 - c0, t1 - t0, nblocks * 12);

        c0 = RDTSC(); t0 = now_sec();
        dedalyan_decrypt_blocks(&ctx, io, nblocks, 16);
        c1 = RDTSC(); t1 = now_sec();
        report("block decrypt (bulk)", c1 - c0, t1 - t0, nblocks * 12);
    }

    free(buf);
    return 0;
}
