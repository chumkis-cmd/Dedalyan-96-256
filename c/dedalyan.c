/* dedalyan.c -- Dedalyan-96/256, реализация по спецификации 1.0. */

#include "dedalyan.h"
#include <string.h>

#define MASK DEDALYAN_MASK
#define W    DEDALYAN_W

#if defined(_MSC_VER)
#  define DED_INLINE __forceinline
#else
#  define DED_INLINE static inline __attribute__((always_inline))
#endif
#if defined(_MSC_VER)
#  define DED_STATIC_INLINE static __forceinline
#else
#  define DED_STATIC_INLINE static inline __attribute__((always_inline))
#endif

/* Умножение по модулю 2^48.
 *
 * unsigned __int128 НЕ НУЖЕН, вопреки замечанию раздела 10.1 спецификации:
 * произведение uint64_t по стандарту C сворачивается по модулю 2^64, а младшие
 * 48 бит от (a·b mod 2^64) совпадают с младшими 48 битами истинного
 * произведения. Дополнительная точность отбрасывается маской в любом случае.
 * Это важно ещё и потому, что MSVC не поддерживает __int128. */
#define MUL48(a, b) ((((uint64_t)(a)) * ((uint64_t)(b))) & MASK)
#define ADD48(a, b) ((((uint64_t)(a)) + ((uint64_t)(b))) & MASK)

/* Раундовые константы RC_i = ((i + 44) ⊙ φ) mod 2^48, раздел 2. */
static const uint64_t DED_RC[DEDALYAN_ROUNDS] = {
    UINT64_C(0x3188EBE1E0B8), UINT64_C(0xCFC0659B6002),
    UINT64_C(0x6DF7DF54DF4C), UINT64_C(0x0C2F590E5E96),
    UINT64_C(0xAA66D2C7DDE0), UINT64_C(0x489E4C815D2A),
    UINT64_C(0xE6D5C63ADC74), UINT64_C(0x850D3FF45BBE),
    UINT64_C(0x2344B9ADDB08), UINT64_C(0xC17C33675A52),
    UINT64_C(0x5FB3AD20D99C), UINT64_C(0xFDEB26DA58E6),
    UINT64_C(0x9C22A093D830), UINT64_C(0x3A5A1A4D577A),
    UINT64_C(0xD8919406D6C4), UINT64_C(0x76C90DC0560E)
};

/* Позиции бит-селекторов лабиринта: b_j = 4·((j + 6) mod 12) + 2, раздел 6.3. */
static const unsigned DED_SELBIT[12] = {
    26, 30, 34, 38, 42, 46, 2, 6, 10, 14, 18, 22
};

/* --- примитивы ---------------------------------------------------------- */

/* Циклический сдвиг в 48-битном регистре.
 * При s == 0 выражение x >> 48 корректно (48 < 64, не UB), и результат x. */
DED_STATIC_INLINE uint64_t ded_rotl(uint64_t x, unsigned s)
{
    s %= W;
    return ((x << s) | (x >> (W - s))) & MASK;
}

DED_STATIC_INLINE uint64_t ded_rotr(uint64_t x, unsigned s)
{
    s %= W;
    return ((x >> s) | (x << (W - s))) & MASK;
}

/* Раундовая функция, раздел 3. rc передаётся готовым: в горячем цикле он
 * берётся из таблицы, а не пересчитывается. */
DED_STATIC_INLINE uint64_t ded_F(uint64_t r, uint64_t k, uint64_t rc)
{
    uint64_t y  = MUL48(ADD48(r, k), DEDALYAN_GAMMA1);
    uint64_t x0 = ADD48(y, ded_rotr(y, 7)) ^ MUL48(r, DEDALYAN_DELTA);
    uint64_t x1 = ADD48(x0, rc);
    uint64_t x2 = ADD48(x1, k) ^ ded_rotl(y, 3);
    return MUL48(ADD48(x2, rc), DEDALYAN_GAMMA2);
}

DED_STATIC_INLINE uint64_t ded_rc_of(unsigned i)
{
    return MUL48((uint64_t)i + 44u, DEDALYAN_PHI);
}

/* Lab(x), раздел 6.3. Все селекторы берутся из ИСХОДНОГО x. */
DED_STATIC_INLINE uint64_t ded_lab(uint64_t x, const uint8_t T[2][16])
{
    uint64_t y = 0;
    unsigned j;
    for (j = 0; j < 12; j++) {
        unsigned b = (unsigned)((x >> DED_SELBIT[j]) & 1u);
        y |= (uint64_t)T[b][(x >> (4u * j)) & 0xFu] << (4u * j);
    }
    return y;
}

/* --- публичные обёртки над примитивами ---------------------------------- */

uint64_t dedalyan_rc(unsigned i)                  { return ded_rc_of(i); }
uint64_t dedalyan_rotl(uint64_t x, unsigned s)    { return ded_rotl(x & MASK, s); }
uint64_t dedalyan_rotr(uint64_t x, unsigned s)    { return ded_rotr(x & MASK, s); }

uint64_t dedalyan_f(uint64_t r, uint64_t k, unsigned i)
{
    return ded_F(r & MASK, k & MASK, ded_rc_of(i));
}

uint64_t dedalyan_apply_labyrinth(uint64_t x, const uint8_t T[2][16])
{
    return ded_lab(x & MASK, T);
}

const char *dedalyan_version(void) { return "Dedalyan-96/256 spec 1.0"; }

/* --- лабиринт, раздел 6 -------------------------------------------------- */

void dedalyan_build_labyrinth(uint64_t kl, uint8_t T[2][16])
{
    uint8_t  nu[36];
    uint64_t u, v;
    unsigned t, j, s, n;

    u = (kl >> 16) & MASK;                       /* старшие 48 бит K_L */
    v = (kl & MASK) ^ DEDALYAN_LAB_DELTA;

    /* Три вызова F дают 36 нибблов; порядок -- от младшего к старшему. */
    n = 0;
    for (t = 0; t < 3; t++) {
        v = ded_F(v, u, ded_rc_of(t));
        for (j = 0; j < 12; j++)
            nu[n++] = (uint8_t)((v >> (4u * j)) & 0xFu);
    }

    /* Фишер--Йетс, потребляющий поток последовательно (первые 30 нибблов). */
    s = 0;
    for (t = 0; t < 2; t++) {
        for (j = 0; j < 16; j++)
            T[t][j] = (uint8_t)j;
        for (j = 15; j >= 1; j--) {
            unsigned r = nu[s++] % (j + 1u);
            uint8_t tmp = T[t][j];
            T[t][j] = T[t][r];
            T[t][r] = tmp;
        }
    }
}

/* --- расписание ключей, раздел 7 ---------------------------------------- */

static uint64_t ded_load_be48(const uint8_t *p)
{
    return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32) |
           ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16) |
           ((uint64_t)p[4] <<  8) | ((uint64_t)p[5]);
}

static uint64_t ded_load_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]);
}

void dedalyan_key_setup(dedalyan_ctx *ctx, const uint8_t key[DEDALYAN_KEY_BYTES])
{
    uint64_t s[4];
    int i;
    unsigned j;

    /* Раздел 5: K = K_L ‖ K₃ ‖ K₂ ‖ K₁ ‖ K₀, K_L -- старшие 64 бита. */
    dedalyan_build_labyrinth(ded_load_be64(key), ctx->T);
    s[3] = ded_load_be48(key +  8);
    s[2] = ded_load_be48(key + 14);
    s[1] = ded_load_be48(key + 20);
    s[0] = ded_load_be48(key + 26);

    /* i = -4..-1 -- прогрев, подключ не выдаётся. */
    for (i = -DEDALYAN_WARMUP; i < DEDALYAN_ROUNDS; i++) {
        unsigned rot;
        int im;

        /* (a) параллельно */
        for (j = 0; j < 4; j++) s[j] = ded_lab(s[j], (const uint8_t (*)[16])ctx->T);

        /* (b) ПОСЛЕДОВАТЕЛЬНО: при j == 3 берётся уже обновлённое s[0]. */
        s[0] = ADD48(s[0], s[1]);
        s[1] = ADD48(s[1], s[2]);
        s[2] = ADD48(s[2], s[3]);
        s[3] = ADD48(s[3], s[0]);

        /* (c) параллельно. В C оператор % усекает к нулю, поэтому для
         * отрицательного i приводим результат к неотрицательному явно:
         * −4 mod 24 = 20, r = 45. */
        im = i % 24;
        if (im < 0) im += 24;
        rot = (unsigned)(2 * im + 5) % W;
        for (j = 0; j < 4; j++) s[j] = ded_rotl(s[j], rot);

        /* (d) параллельно */
        for (j = 0; j < 4; j++) s[j] = ded_lab(s[j], (const uint8_t (*)[16])ctx->T);

        /* (e) выдача подключа */
        if (i >= 0)
            ctx->rk[i] = ADD48(s[(unsigned)i & 3u], DED_RC[i]);
    }

    s[0] = s[1] = s[2] = s[3] = 0;
}

void dedalyan_key_schedule(const uint8_t key[DEDALYAN_KEY_BYTES],
                           uint64_t rk[DEDALYAN_ROUNDS])
{
    dedalyan_ctx ctx;
    dedalyan_key_setup(&ctx, key);
    memcpy(rk, ctx.rk, sizeof(ctx.rk));
    dedalyan_ctx_wipe(&ctx);
}

void dedalyan_ctx_wipe(dedalyan_ctx *ctx)
{
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    size_t n = sizeof(*ctx);
    while (n--) *p++ = 0;
}

/* --- шифрование блока, раздел 4 ----------------------------------------- */

dedalyan_block dedalyan_encrypt_r(const dedalyan_ctx *ctx, dedalyan_block b,
                                  unsigned rounds)
{
    uint64_t l = b.l & MASK, r = b.r & MASK;
    unsigned i;
    if (rounds > DEDALYAN_ROUNDS) rounds = DEDALYAN_ROUNDS;
    for (i = 0; i < rounds; i++) {
        uint64_t t = l ^ ded_F(r, ctx->rk[i], DED_RC[i]);
        l = r;
        r = t;
    }
    b.l = l; b.r = r;
    return b;
}

dedalyan_block dedalyan_decrypt_r(const dedalyan_ctx *ctx, dedalyan_block b,
                                  unsigned rounds)
{
    uint64_t l = b.l & MASK, r = b.r & MASK;
    unsigned i;
    if (rounds > DEDALYAN_ROUNDS) rounds = DEDALYAN_ROUNDS;
    /* Подключи в обратном порядке, но номер раунда (а значит RC_i) тот же. */
    for (i = rounds; i-- > 0; ) {
        uint64_t t = r ^ ded_F(l, ctx->rk[i], DED_RC[i]);
        r = l;
        l = t;
    }
    b.l = l; b.r = r;
    return b;
}

dedalyan_block dedalyan_encrypt(const dedalyan_ctx *ctx, dedalyan_block b)
{
    return dedalyan_encrypt_r(ctx, b, DEDALYAN_ROUNDS);
}

dedalyan_block dedalyan_decrypt(const dedalyan_ctx *ctx, dedalyan_block b)
{
    return dedalyan_decrypt_r(ctx, b, DEDALYAN_ROUNDS);
}

void dedalyan_encrypt_trace(const dedalyan_ctx *ctx, dedalyan_block b,
                            unsigned rounds, uint64_t *trace_f,
                            uint64_t *trace_l, uint64_t *trace_r)
{
    uint64_t l = b.l & MASK, r = b.r & MASK;
    unsigned i;
    if (rounds > DEDALYAN_ROUNDS) rounds = DEDALYAN_ROUNDS;
    for (i = 0; i < rounds; i++) {
        uint64_t f = ded_F(r, ctx->rk[i], DED_RC[i]);
        uint64_t t = l ^ f;
        l = r;
        r = t;
        if (trace_f) trace_f[i] = f;
        if (trace_l) trace_l[i] = l;
        if (trace_r) trace_r[i] = r;
    }
}

/* --- байтовые обёртки ---------------------------------------------------- */

static void ded_store_be48(uint8_t *p, uint64_t x)
{
    p[0] = (uint8_t)(x >> 40); p[1] = (uint8_t)(x >> 32);
    p[2] = (uint8_t)(x >> 24); p[3] = (uint8_t)(x >> 16);
    p[4] = (uint8_t)(x >>  8); p[5] = (uint8_t)(x);
}

void dedalyan_encrypt_bytes(const dedalyan_ctx *ctx,
                            const uint8_t in[DEDALYAN_BLOCK_BYTES],
                            uint8_t out[DEDALYAN_BLOCK_BYTES])
{
    dedalyan_block b;
    b.l = ded_load_be48(in);
    b.r = ded_load_be48(in + 6);
    b = dedalyan_encrypt_r(ctx, b, DEDALYAN_ROUNDS);
    ded_store_be48(out, b.l);
    ded_store_be48(out + 6, b.r);
}

void dedalyan_decrypt_bytes(const dedalyan_ctx *ctx,
                            const uint8_t in[DEDALYAN_BLOCK_BYTES],
                            uint8_t out[DEDALYAN_BLOCK_BYTES])
{
    dedalyan_block b;
    b.l = ded_load_be48(in);
    b.r = ded_load_be48(in + 6);
    b = dedalyan_decrypt_r(ctx, b, DEDALYAN_ROUNDS);
    ded_store_be48(out, b.l);
    ded_store_be48(out + 6, b.r);
}

/* --- пакетная обработка -------------------------------------------------- */

void dedalyan_encrypt_blocks(const dedalyan_ctx *ctx, uint64_t *io, size_t n,
                             unsigned rounds)
{
    size_t i;
    if (rounds > DEDALYAN_ROUNDS) rounds = DEDALYAN_ROUNDS;
    for (i = 0; i < n; i++) {
        uint64_t l = io[2 * i] & MASK, r = io[2 * i + 1] & MASK;
        unsigned j;
        for (j = 0; j < rounds; j++) {
            uint64_t t = l ^ ded_F(r, ctx->rk[j], DED_RC[j]);
            l = r;
            r = t;
        }
        io[2 * i] = l;
        io[2 * i + 1] = r;
    }
}

void dedalyan_decrypt_blocks(const dedalyan_ctx *ctx, uint64_t *io, size_t n,
                             unsigned rounds)
{
    size_t i;
    if (rounds > DEDALYAN_ROUNDS) rounds = DEDALYAN_ROUNDS;
    for (i = 0; i < n; i++) {
        uint64_t l = io[2 * i] & MASK, r = io[2 * i + 1] & MASK;
        unsigned j;
        for (j = rounds; j-- > 0; ) {
            uint64_t t = r ^ ded_F(l, ctx->rk[j], DED_RC[j]);
            r = l;
            l = t;
        }
        io[2 * i] = l;
        io[2 * i + 1] = r;
    }
}

/* --- режим CTR ----------------------------------------------------------- */

void dedalyan_ctr(const dedalyan_ctx *ctx,
                  const uint8_t counter[DEDALYAN_BLOCK_BYTES],
                  const uint8_t *in, uint8_t *out, size_t len, unsigned rounds)
{
    uint8_t ctr[DEDALYAN_BLOCK_BYTES];
    uint8_t ks[DEDALYAN_BLOCK_BYTES];
    size_t off;

    memcpy(ctr, counter, DEDALYAN_BLOCK_BYTES);
    if (rounds > DEDALYAN_ROUNDS) rounds = DEDALYAN_ROUNDS;

    for (off = 0; off < len; off += DEDALYAN_BLOCK_BYTES) {
        dedalyan_block b;
        size_t chunk = len - off;
        size_t i;
        int c;

        if (chunk > DEDALYAN_BLOCK_BYTES) chunk = DEDALYAN_BLOCK_BYTES;

        b.l = ded_load_be48(ctr);
        b.r = ded_load_be48(ctr + 6);
        b = dedalyan_encrypt_r(ctx, b, rounds);
        ded_store_be48(ks, b.l);
        ded_store_be48(ks + 6, b.r);

        if (in) {
            for (i = 0; i < chunk; i++) out[off + i] = in[off + i] ^ ks[i];
        } else {
            for (i = 0; i < chunk; i++) out[off + i] = ks[i];
        }

        /* Инкремент 96-битного счётчика по модулю 2^96, big-endian. */
        for (c = DEDALYAN_BLOCK_BYTES - 1; c >= 0; c--)
            if (++ctr[c] != 0) break;
    }

    memset(ks, 0, sizeof(ks));
}
