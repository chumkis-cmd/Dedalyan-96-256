/* kernels.c -- горячие циклы для криптоаналитического набора. */

#include "kernels.h"
#include <string.h>

#define MASK DEDALYAN_MASK

#if defined(_MSC_VER)
#  define KIN static __forceinline
#else
#  define KIN static inline __attribute__((always_inline))
#endif

/* --- вспомогательное ----------------------------------------------------- */

uint64_t ded_k_splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

KIN uint64_t sm64(uint64_t *s) { return ded_k_splitmix64(s); }

KIN unsigned popcount64(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned)__builtin_popcountll(x);
#else
    x = x - ((x >> 1) & UINT64_C(0x5555555555555555));
    x = (x & UINT64_C(0x3333333333333333)) + ((x >> 2) & UINT64_C(0x3333333333333333));
    x = (x + (x >> 4)) & UINT64_C(0x0F0F0F0F0F0F0F0F);
    return (unsigned)((x * UINT64_C(0x0101010101010101)) >> 56);
#endif
}

KIN unsigned parity64(uint64_t x) { return popcount64(x) & 1u; }

KIN unsigned ctz64(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned)__builtin_ctzll(x);
#else
    unsigned n = 0;
    if (!x) return 64;
    while (!(x & 1u)) { x >>= 1; n++; }
    return n;
#endif
}

/* Раскладывает 96-битную разность по счётчикам, обходя только единичные биты. */
KIN void tally_bits(uint64_t l, uint64_t r, uint64_t *out)
{
    while (r) { unsigned b = ctz64(r); out[b]++;      r &= r - 1; }
    while (l) { unsigned b = ctz64(l); out[b + 48]++; l &= l - 1; }
}

/* Случайный 48-битный полублок. */
KIN uint64_t rnd48(uint64_t *s) { return sm64(s) & MASK; }

/* Псевдослучайный 32-байтовый ключ из потока. */
KIN void rnd_key(uint64_t *s, uint8_t key[32])
{
    int i, j;
    for (i = 0; i < 4; i++) {
        uint64_t v = sm64(s);
        for (j = 0; j < 8; j++) key[i * 8 + j] = (uint8_t)(v >> (56 - 8 * j));
    }
}

/* Установка/чтение бита блока по индексу 0..95. */
KIN void flip_block_bit(uint64_t *l, uint64_t *r, unsigned b)
{
    if (b < 48) *r ^= UINT64_C(1) << b;
    else        *l ^= UINT64_C(1) << (b - 48);
}

/* --- дифференциальный криптоанализ -------------------------------------- */

void ded_k_diff_bitcount(const dedalyan_ctx *ctx, unsigned rounds,
                         uint64_t dl, uint64_t dr,
                         size_t n, uint64_t seed, uint64_t out[96])
{
    uint64_t st = seed;
    size_t i;
    memset(out, 0, 96 * sizeof(uint64_t));
    dl &= MASK; dr &= MASK;
    for (i = 0; i < n; i++) {
        dedalyan_block a, b;
        a.l = rnd48(&st); a.r = rnd48(&st);
        b.l = a.l ^ dl;   b.r = a.r ^ dr;
        a = dedalyan_encrypt_r(ctx, a, rounds);
        b = dedalyan_encrypt_r(ctx, b, rounds);
        tally_bits(a.l ^ b.l, a.r ^ b.r, out);
    }
}

void ded_k_diff_nibble_seen(const dedalyan_ctx *ctx, unsigned rounds,
                            uint64_t dl, uint64_t dr,
                            size_t n, uint64_t seed, uint8_t seen[24 * 16])
{
    uint64_t st = seed;
    size_t i;
    unsigned j;
    memset(seen, 0, 24 * 16);
    dl &= MASK; dr &= MASK;
    for (i = 0; i < n; i++) {
        dedalyan_block a, b;
        uint64_t ol, orr;
        a.l = rnd48(&st); a.r = rnd48(&st);
        b.l = a.l ^ dl;   b.r = a.r ^ dr;
        a = dedalyan_encrypt_r(ctx, a, rounds);
        b = dedalyan_encrypt_r(ctx, b, rounds);
        orr = a.r ^ b.r;
        ol  = a.l ^ b.l;
        for (j = 0; j < 12; j++) {
            seen[j * 16 + (unsigned)((orr >> (4 * j)) & 0xF)] = 1;
            seen[(j + 12) * 16 + (unsigned)((ol >> (4 * j)) & 0xF)] = 1;
        }
    }
}

uint64_t ded_k_diff_exact(const dedalyan_ctx *ctx, unsigned rounds,
                          uint64_t dl, uint64_t dr, uint64_t ol, uint64_t orr,
                          size_t n, uint64_t seed)
{
    uint64_t st = seed, hits = 0;
    size_t i;
    dl &= MASK; dr &= MASK; ol &= MASK; orr &= MASK;
    for (i = 0; i < n; i++) {
        dedalyan_block a, b;
        a.l = rnd48(&st); a.r = rnd48(&st);
        b.l = a.l ^ dl;   b.r = a.r ^ dr;
        a = dedalyan_encrypt_r(ctx, a, rounds);
        b = dedalyan_encrypt_r(ctx, b, rounds);
        if ((a.l ^ b.l) == ol && (a.r ^ b.r) == orr) hits++;
    }
    return hits;
}

/* --- диффузия ------------------------------------------------------------ */

void ded_k_diffusion_cover(const dedalyan_ctx *ctx, unsigned rounds,
                           size_t n, uint64_t seed, uint64_t out[192])
{
    uint64_t st = seed;
    size_t i;
    unsigned b;
    memset(out, 0, 192 * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        dedalyan_block p, c0;
        p.l = rnd48(&st); p.r = rnd48(&st);
        c0 = dedalyan_encrypt_r(ctx, p, rounds);
        for (b = 0; b < 96; b++) {
            dedalyan_block q = p, c1;
            flip_block_bit(&q.l, &q.r, b);
            c1 = dedalyan_encrypt_r(ctx, q, rounds);
            out[2 * b]     |= c0.l ^ c1.l;
            out[2 * b + 1] |= c0.r ^ c1.r;
        }
    }
}

void ded_k_diffusion_count(const dedalyan_ctx *ctx, unsigned rounds,
                           size_t n, uint64_t seed, uint32_t out[96 * 96])
{
    uint64_t st = seed;
    size_t i;
    unsigned b;
    memset(out, 0, 96 * 96 * sizeof(uint32_t));
    for (i = 0; i < n; i++) {
        dedalyan_block p, c0;
        p.l = rnd48(&st); p.r = rnd48(&st);
        c0 = dedalyan_encrypt_r(ctx, p, rounds);
        for (b = 0; b < 96; b++) {
            dedalyan_block q = p, c1;
            uint64_t dl, dr;
            uint32_t *row = out + (size_t)b * 96;
            flip_block_bit(&q.l, &q.r, b);
            c1 = dedalyan_encrypt_r(ctx, q, rounds);
            dr = c0.r ^ c1.r;
            dl = c0.l ^ c1.l;
            while (dr) { unsigned k = ctz64(dr); row[k]++;      dr &= dr - 1; }
            while (dl) { unsigned k = ctz64(dl); row[k + 48]++; dl &= dl - 1; }
        }
    }
}

void ded_k_avalanche(const dedalyan_ctx *ctx, unsigned rounds,
                     size_t n, uint64_t seed,
                     uint64_t *sum_hd, uint64_t *sum_hd2)
{
    uint64_t st = seed, s1 = 0, s2 = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        dedalyan_block p, q, c0, c1;
        unsigned bit = (unsigned)(sm64(&st) % 96), hd;
        p.l = rnd48(&st); p.r = rnd48(&st);
        q = p;
        flip_block_bit(&q.l, &q.r, bit);
        c0 = dedalyan_encrypt_r(ctx, p, rounds);
        c1 = dedalyan_encrypt_r(ctx, q, rounds);
        hd = popcount64(c0.l ^ c1.l) + popcount64(c0.r ^ c1.r);
        s1 += hd;
        s2 += (uint64_t)hd * hd;
    }
    *sum_hd = s1;
    *sum_hd2 = s2;
}

/* --- линейный криптоанализ ---------------------------------------------- */

void ded_k_linear_pairs(const dedalyan_ctx *ctx, unsigned rounds,
                        const uint64_t *masks, size_t npairs,
                        size_t n, uint64_t seed, uint64_t *counts)
{
    uint64_t st = seed;
    size_t i, m;
    memset(counts, 0, npairs * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        dedalyan_block p, c;
        p.l = rnd48(&st); p.r = rnd48(&st);
        c = dedalyan_encrypt_r(ctx, p, rounds);
        for (m = 0; m < npairs; m++) {
            const uint64_t *mk = masks + 4 * m;
            unsigned bit = parity64((p.l & mk[0]) ^ (p.r & mk[1]) ^
                                    (c.l & mk[2]) ^ (c.r & mk[3]));
            counts[m] += (bit == 0);
        }
    }
}

/* --- бумеранг ------------------------------------------------------------ */

uint64_t ded_k_boomerang(const dedalyan_ctx *ctx, unsigned rounds,
                         uint64_t al, uint64_t ar, uint64_t dl, uint64_t dr,
                         size_t n, uint64_t seed)
{
    uint64_t st = seed, hits = 0;
    size_t i;
    al &= MASK; ar &= MASK; dl &= MASK; dr &= MASK;
    for (i = 0; i < n; i++) {
        dedalyan_block p1, p2, c1, c2, c3, c4, p3, p4;
        p1.l = rnd48(&st); p1.r = rnd48(&st);
        p2.l = p1.l ^ al;  p2.r = p1.r ^ ar;
        c1 = dedalyan_encrypt_r(ctx, p1, rounds);
        c2 = dedalyan_encrypt_r(ctx, p2, rounds);
        c3.l = c1.l ^ dl;  c3.r = c1.r ^ dr;
        c4.l = c2.l ^ dl;  c4.r = c2.r ^ dr;
        p3 = dedalyan_decrypt_r(ctx, c3, rounds);
        p4 = dedalyan_decrypt_r(ctx, c4, rounds);
        if ((p3.l ^ p4.l) == al && (p3.r ^ p4.r) == ar) hits++;
    }
    return hits;
}

/* --- интегральный криптоанализ ------------------------------------------ */

void ded_k_integral_sum(const dedalyan_ctx *ctx, unsigned rounds,
                        uint64_t base_l, uint64_t base_r,
                        const uint8_t *active_bits, unsigned nactive,
                        uint64_t *sum_l, uint64_t *sum_r)
{
    uint64_t l = base_l & MASK, r = base_r & MASK;
    uint64_t sl = 0, sr = 0, total, v;
    unsigned i;

    if (nactive > 32) nactive = 32;

    /* Обнуляем активные биты: базовая точка подпространства. */
    for (i = 0; i < nactive; i++) {
        unsigned b = active_bits[i];
        if (b < 48) r &= ~(UINT64_C(1) << b);
        else        l &= ~(UINT64_C(1) << (b - 48));
    }

    total = UINT64_C(1) << nactive;
    for (v = 0; v < total; v++) {
        dedalyan_block b;
        b.l = l; b.r = r;
        b = dedalyan_encrypt_r(ctx, b, rounds);
        sl ^= b.l;
        sr ^= b.r;
        if (v + 1 < total) {
            /* Код Грея: между v и v+1 меняется ровно один бит. */
            unsigned t = ctz64(v + 1);
            flip_block_bit(&l, &r, active_bits[t]);
        }
    }
    *sum_l = sl;
    *sum_r = sr;
}

/* --- расписание ключей --------------------------------------------------- */

void ded_k_key_avalanche(unsigned rounds, size_t n, uint64_t seed,
                         uint32_t out[256 * 96])
{
    uint64_t st = seed;
    size_t i;
    unsigned kb;
    memset(out, 0, 256 * 96 * sizeof(uint32_t));
    for (i = 0; i < n; i++) {
        uint8_t key[32], key2[32];
        dedalyan_ctx c0, c1;
        dedalyan_block p, e0, e1;

        rnd_key(&st, key);
        p.l = rnd48(&st); p.r = rnd48(&st);
        dedalyan_key_setup(&c0, key);
        e0 = dedalyan_encrypt_r(&c0, p, rounds);

        for (kb = 0; kb < 256; kb++) {
            uint64_t dl, dr;
            uint32_t *row = out + (size_t)kb * 96;
            memcpy(key2, key, 32);
            /* Бит kb ключа: kb = 0 -- младший бит последнего байта. */
            key2[31 - kb / 8] ^= (uint8_t)(1u << (kb % 8));
            dedalyan_key_setup(&c1, key2);
            e1 = dedalyan_encrypt_r(&c1, p, rounds);
            dr = e0.r ^ e1.r;
            dl = e0.l ^ e1.l;
            while (dr) { unsigned k = ctz64(dr); row[k]++;      dr &= dr - 1; }
            while (dl) { unsigned k = ctz64(dl); row[k + 48]++; dl &= dl - 1; }
        }
    }
}

void ded_k_subkey_avalanche(size_t n, uint64_t seed,
                            uint64_t sum_hd[16], uint64_t sum_hd2[16])
{
    uint64_t st = seed;
    size_t i;
    unsigned j;
    memset(sum_hd, 0, 16 * sizeof(uint64_t));
    memset(sum_hd2, 0, 16 * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        uint8_t key[32], key2[32];
        uint64_t rk0[16], rk1[16];
        unsigned kb;

        rnd_key(&st, key);
        kb = (unsigned)(sm64(&st) & 255u);
        memcpy(key2, key, 32);
        key2[31 - kb / 8] ^= (uint8_t)(1u << (kb % 8));

        dedalyan_key_schedule(key, rk0);
        dedalyan_key_schedule(key2, rk1);
        for (j = 0; j < 16; j++) {
            unsigned hd = popcount64(rk0[j] ^ rk1[j]);
            sum_hd[j] += hd;
            sum_hd2[j] += (uint64_t)hd * hd;
        }
    }
}

void ded_k_relkey_bitcount(unsigned rounds, const uint8_t dk[32],
                           size_t n, uint64_t seed, uint64_t out[96])
{
    uint64_t st = seed;
    size_t i;
    memset(out, 0, 96 * sizeof(uint64_t));
    for (i = 0; i < n; i++) {
        uint8_t key[32], key2[32];
        dedalyan_ctx c0, c1;
        dedalyan_block p, e0, e1;
        int j;

        rnd_key(&st, key);
        for (j = 0; j < 32; j++) key2[j] = (uint8_t)(key[j] ^ dk[j]);
        p.l = rnd48(&st); p.r = rnd48(&st);

        dedalyan_key_setup(&c0, key);
        dedalyan_key_setup(&c1, key2);
        e0 = dedalyan_encrypt_r(&c0, p, rounds);
        e1 = dedalyan_encrypt_r(&c1, p, rounds);
        tally_bits(e0.l ^ e1.l, e0.r ^ e1.r, out);
    }
}

void ded_k_key_fingerprint(unsigned rounds, uint64_t pl, uint64_t pr,
                           size_t n, uint64_t seed, uint64_t *out)
{
    uint64_t st = seed;
    size_t i;
    for (i = 0; i < n; i++) {
        uint8_t key[32];
        dedalyan_ctx c;
        dedalyan_block b;
        rnd_key(&st, key);
        dedalyan_key_setup(&c, key);
        b.l = pl & MASK; b.r = pr & MASK;
        b = dedalyan_encrypt_r(&c, b, rounds);
        out[2 * i]     = b.l;
        out[2 * i + 1] = b.r;
    }
}

void ded_k_subkey_dump(size_t n, uint64_t seed, uint64_t *out)
{
    uint64_t st = seed;
    size_t i;
    for (i = 0; i < n; i++) {
        uint8_t key[32];
        rnd_key(&st, key);
        dedalyan_key_schedule(key, out + 16 * i);
    }
}

void ded_k_labyrinth_fixpoints(size_t n, uint64_t seed, uint8_t *out)
{
    uint64_t st = seed;
    size_t i;
    for (i = 0; i < n; i++) {
        uint8_t T[2][16];
        unsigned t, j, fp = 0;
        dedalyan_build_labyrinth(sm64(&st), T);
        for (t = 0; t < 2; t++)
            for (j = 0; j < 16; j++)
                if (T[t][j] == (uint8_t)j) fp++;
        out[i] = (uint8_t)fp;
    }
}

/* --- ротационный криптоанализ -------------------------------------------- */

uint64_t ded_k_rotational(unsigned rounds, unsigned rot, int key_rot,
                          size_t n, uint64_t seed)
{
    uint64_t st = seed, hits = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        uint8_t key[32], key2[32];
        dedalyan_ctx c0, c1;
        dedalyan_block p, q, e0, e1;

        rnd_key(&st, key);
        memcpy(key2, key, 32);
        if (key_rot) {
            /* Вращаем каждое 48-битное слово ключа K₀..K₃ на rot. */
            int w;
            for (w = 0; w < 4; w++) {
                uint8_t *pw = key2 + 8 + 6 * w;
                uint64_t v = ((uint64_t)pw[0] << 40) | ((uint64_t)pw[1] << 32) |
                             ((uint64_t)pw[2] << 24) | ((uint64_t)pw[3] << 16) |
                             ((uint64_t)pw[4] <<  8) | ((uint64_t)pw[5]);
                v = dedalyan_rotl(v, rot);
                pw[0] = (uint8_t)(v >> 40); pw[1] = (uint8_t)(v >> 32);
                pw[2] = (uint8_t)(v >> 24); pw[3] = (uint8_t)(v >> 16);
                pw[4] = (uint8_t)(v >>  8); pw[5] = (uint8_t)(v);
            }
        }

        p.l = rnd48(&st); p.r = rnd48(&st);
        q.l = dedalyan_rotl(p.l, rot);
        q.r = dedalyan_rotl(p.r, rot);

        dedalyan_key_setup(&c0, key);
        dedalyan_key_setup(&c1, key2);
        e0 = dedalyan_encrypt_r(&c0, p, rounds);
        e1 = dedalyan_encrypt_r(&c1, q, rounds);

        if (e1.l == dedalyan_rotl(e0.l, rot) && e1.r == dedalyan_rotl(e0.r, rot))
            hits++;
    }
    return hits;
}

/* --- потоки для статистики ----------------------------------------------- */

void ded_k_ctr_stream(const dedalyan_ctx *ctx, unsigned rounds,
                      uint64_t ctr_hi, uint64_t ctr_lo, uint8_t *out, size_t len)
{
    uint8_t counter[12];
    counter[0] = (uint8_t)(ctr_hi >> 40); counter[1] = (uint8_t)(ctr_hi >> 32);
    counter[2] = (uint8_t)(ctr_hi >> 24); counter[3] = (uint8_t)(ctr_hi >> 16);
    counter[4] = (uint8_t)(ctr_hi >>  8); counter[5] = (uint8_t)(ctr_hi);
    counter[6] = (uint8_t)(ctr_lo >> 40); counter[7] = (uint8_t)(ctr_lo >> 32);
    counter[8] = (uint8_t)(ctr_lo >> 24); counter[9] = (uint8_t)(ctr_lo >> 16);
    counter[10]= (uint8_t)(ctr_lo >>  8); counter[11]= (uint8_t)(ctr_lo);
    dedalyan_ctr(ctx, counter, NULL, out, len, rounds);
}

void ded_k_random_ecb(const dedalyan_ctx *ctx, unsigned rounds,
                      size_t n, uint64_t seed, uint64_t *out)
{
    uint64_t st = seed;
    size_t i;
    for (i = 0; i < n; i++) {
        dedalyan_block b;
        b.l = rnd48(&st); b.r = rnd48(&st);
        b = dedalyan_encrypt_r(ctx, b, rounds);
        out[2 * i]     = b.l;
        out[2 * i + 1] = b.r;
    }
}
