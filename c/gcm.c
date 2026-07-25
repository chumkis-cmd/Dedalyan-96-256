/* gcm.c -- Dedalyan-GCM-96. См. заголовок gcm.h и dedalyan_gcm.py. */

#include "gcm.h"
#include <string.h>

/* Константа редукции в отражённом представлении GCM.
 * Коэффициент при x^j лежит в бите (95 - j), поэтому младшие члены
 * многочлена x^10 + x^9 + x^6 + 1 оказываются в старших битах блока:
 * биты 85, 86, 89, 95 -- то есть 0x826000000000000000000000. */
#define GCM_R_HI UINT64_C(0x8260000000000000)
#define GCM_R_LO UINT32_C(0x00000000)

#if defined(_MSC_VER)
#  define GIN static __forceinline
#else
#  define GIN static inline __attribute__((always_inline))
#endif

/* --- загрузка и выгрузка ------------------------------------------------- */

GIN ded_gf96 gf_load(const uint8_t b[12])
{
    ded_gf96 v;
    v.hi = ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] <<  8) | ((uint64_t)b[7]);
    v.lo = ((uint32_t)b[8] << 24) | ((uint32_t)b[9] << 16) |
           ((uint32_t)b[10] << 8) | ((uint32_t)b[11]);
    return v;
}

GIN void gf_store(ded_gf96 v, uint8_t b[12])
{
    b[0]  = (uint8_t)(v.hi >> 56); b[1]  = (uint8_t)(v.hi >> 48);
    b[2]  = (uint8_t)(v.hi >> 40); b[3]  = (uint8_t)(v.hi >> 32);
    b[4]  = (uint8_t)(v.hi >> 24); b[5]  = (uint8_t)(v.hi >> 16);
    b[6]  = (uint8_t)(v.hi >>  8); b[7]  = (uint8_t)(v.hi);
    b[8]  = (uint8_t)(v.lo >> 24); b[9]  = (uint8_t)(v.lo >> 16);
    b[10] = (uint8_t)(v.lo >>  8); b[11] = (uint8_t)(v.lo);
}

GIN ded_gf96 gf_xor(ded_gf96 a, ded_gf96 b)
{
    a.hi ^= b.hi;
    a.lo ^= b.lo;
    return a;
}

/* Умножение на x: сдвиг вправо на 1 с редукцией. */
GIN ded_gf96 gf_xtime(ded_gf96 v)
{
    uint32_t carry = v.lo & 1u;
    v.lo = (v.lo >> 1) | (uint32_t)((v.hi & 1u) << 31);
    v.hi >>= 1;
    if (carry) {
        v.hi ^= GCM_R_HI;
        v.lo ^= GCM_R_LO;
    }
    return v;
}

/* Умножение на x^4.
 *
 * Разложим V на старшую часть (низкие 4 бита нулевые) и низкие 4 бита.
 * Старшая часть при умножении на x^4 сдвигается вправо без редукции --
 * выезжающие биты нулевые. Низкие 4 бита дают чистый вклад редукции,
 * который и лежит в таблице R4. */
GIN ded_gf96 gf_shift4(ded_gf96 v, const ded_gf96 *r4)
{
    unsigned j = (unsigned)(v.lo & 0xFu);
    ded_gf96 out;
    out.lo = (v.lo >> 4) | (uint32_t)((v.hi & 0xFu) << 28);
    out.hi = v.hi >> 4;
    return gf_xor(out, r4[j]);
}

/* --- инициализация ------------------------------------------------------- */

void dedalyan_gcm_init(dedalyan_gcm_ctx *ctx,
                       const uint8_t key[DEDALYAN_KEY_BYTES])
{
    dedalyan_block zero;
    uint8_t hb[12];
    ded_gf96 basis[4];
    unsigned i, t;

    dedalyan_key_setup(&ctx->cipher, key);

    /* H = E_K(0^96) */
    zero.l = 0;
    zero.r = 0;
    zero = dedalyan_encrypt(&ctx->cipher, zero);
    hb[0]  = (uint8_t)(zero.l >> 40); hb[1] = (uint8_t)(zero.l >> 32);
    hb[2]  = (uint8_t)(zero.l >> 24); hb[3] = (uint8_t)(zero.l >> 16);
    hb[4]  = (uint8_t)(zero.l >>  8); hb[5] = (uint8_t)(zero.l);
    hb[6]  = (uint8_t)(zero.r >> 40); hb[7] = (uint8_t)(zero.r >> 32);
    hb[8]  = (uint8_t)(zero.r >> 24); hb[9] = (uint8_t)(zero.r >> 16);
    hb[10] = (uint8_t)(zero.r >>  8); hb[11] = (uint8_t)(zero.r);
    ctx->H = gf_load(hb);

    /* Базис: ниббл i задаёт коэффициенты при x^0..x^3, причём старший бит
     * ниббла -- это x^0. Отсюда basis[0] = H, basis[b] = x^b * H. */
    basis[0] = ctx->H;
    basis[1] = gf_xtime(basis[0]);
    basis[2] = gf_xtime(basis[1]);
    basis[3] = gf_xtime(basis[2]);

    for (i = 0; i < 16; i++) {
        ded_gf96 acc;
        acc.hi = 0;
        acc.lo = 0;
        if (i & 8u) acc = gf_xor(acc, basis[0]);
        if (i & 4u) acc = gf_xor(acc, basis[1]);
        if (i & 2u) acc = gf_xor(acc, basis[2]);
        if (i & 1u) acc = gf_xor(acc, basis[3]);
        ctx->M[i] = acc;
    }

    /* R4[j] = j * x^4, где j занимает младшие 4 бита: чистая редукция. */
    for (i = 0; i < 16; i++) {
        ded_gf96 v;
        v.hi = 0;
        v.lo = i;
        for (t = 0; t < 4; t++) v = gf_xtime(v);
        ctx->R4[i] = v;
    }

    memset(hb, 0, sizeof(hb));
}

void dedalyan_gcm_wipe(dedalyan_gcm_ctx *ctx)
{
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    size_t n = sizeof(*ctx);
    while (n--) *p++ = 0;
}

/* --- умножение ----------------------------------------------------------- */

void dedalyan_gcm_mul_ref(const uint8_t xb[12], const uint8_t yb[12],
                          uint8_t out[12])
{
    ded_gf96 x = gf_load(xb), v = gf_load(yb), z;
    unsigned i;
    z.hi = 0;
    z.lo = 0;
    for (i = 0; i < 96; i++) {
        /* бит (95 - i) величины x */
        unsigned bit = (95u - i) >= 32u
                     ? (unsigned)((x.hi >> ((95u - i) - 32u)) & 1u)
                     : (unsigned)((x.lo >> (95u - i)) & 1u);
        if (bit) z = gf_xor(z, v);
        v = gf_xtime(v);
    }
    gf_store(z, out);
}

/* Схема Горнера по нибблам: X*H = sum_k x^(4k) * N_k * H, где N_k -- k-й
 * ниббл слева. Обход с последнего ниббла к первому даёт 24 шага вместо 96. */
GIN ded_gf96 gf_mul_h(const dedalyan_gcm_ctx *ctx, ded_gf96 x)
{
    ded_gf96 z;
    int k;
    z.hi = 0;
    z.lo = 0;
    for (k = 23; k >= 0; k--) {
        unsigned n;
        if (k >= 16) {
            /* нибблы 16..23 лежат в lo (биты 31..0) */
            unsigned sh = (unsigned)((23 - k) * 4);
            n = (unsigned)((x.lo >> sh) & 0xFu);
        } else {
            unsigned sh = (unsigned)((15 - k) * 4);
            n = (unsigned)((x.hi >> sh) & 0xFu);
        }
        z = gf_shift4(z, ctx->R4);
        z = gf_xor(z, ctx->M[n]);
    }
    return z;
}

void dedalyan_gcm_mul_h(const dedalyan_gcm_ctx *ctx, const uint8_t x[12],
                        uint8_t out[12])
{
    gf_store(gf_mul_h(ctx, gf_load(x)), out);
}

void dedalyan_gcm_ghash(const dedalyan_gcm_ctx *ctx, const uint8_t *data,
                        size_t len, uint8_t out[12])
{
    ded_gf96 y;
    size_t off;
    y.hi = 0;
    y.lo = 0;
    for (off = 0; off + 12 <= len; off += 12)
        y = gf_mul_h(ctx, gf_xor(y, gf_load(data + off)));
    gf_store(y, out);
}

/* --- AEAD ---------------------------------------------------------------- */

/* GHASH по потоку с дополнением нулями до границы блока. */
static ded_gf96 ghash_update(const dedalyan_gcm_ctx *ctx, ded_gf96 y,
                             const uint8_t *data, size_t len)
{
    size_t off = 0;
    while (off + 12 <= len) {
        y = gf_mul_h(ctx, gf_xor(y, gf_load(data + off)));
        off += 12;
    }
    if (off < len) {
        uint8_t last[12];
        memset(last, 0, 12);
        memcpy(last, data + off, len - off);
        y = gf_mul_h(ctx, gf_xor(y, gf_load(last)));
        memset(last, 0, 12);
    }
    return y;
}

static void j0_bytes(const uint8_t nonce[8], uint8_t out[12])
{
    memcpy(out, nonce, 8);
    out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 1;
}

static void inc32(uint8_t ctr[12])
{
    int i;
    for (i = 11; i >= 8; i--)
        if (++ctr[i] != 0) break;
}

static void compute_tag(const dedalyan_gcm_ctx *ctx, const uint8_t nonce[8],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len, uint8_t tag[12])
{
    ded_gf96 y;
    uint8_t lenblk[12], j0[12], mask[12];
    uint64_t abits = (uint64_t)aad_len * 8u;
    uint64_t cbits = (uint64_t)ct_len * 8u;
    unsigned i;

    y.hi = 0;
    y.lo = 0;
    y = ghash_update(ctx, y, aad, aad_len);
    y = ghash_update(ctx, y, ct, ct_len);

    /* Финальный блок: две длины в битах по 48 бит -- ровно один блок. */
    lenblk[0] = (uint8_t)(abits >> 40); lenblk[1] = (uint8_t)(abits >> 32);
    lenblk[2] = (uint8_t)(abits >> 24); lenblk[3] = (uint8_t)(abits >> 16);
    lenblk[4] = (uint8_t)(abits >>  8); lenblk[5] = (uint8_t)(abits);
    lenblk[6] = (uint8_t)(cbits >> 40); lenblk[7] = (uint8_t)(cbits >> 32);
    lenblk[8] = (uint8_t)(cbits >> 24); lenblk[9] = (uint8_t)(cbits >> 16);
    lenblk[10]= (uint8_t)(cbits >>  8); lenblk[11]= (uint8_t)(cbits);
    y = gf_mul_h(ctx, gf_xor(y, gf_load(lenblk)));

    j0_bytes(nonce, j0);
    dedalyan_encrypt_bytes(&ctx->cipher, j0, mask);
    gf_store(y, tag);
    for (i = 0; i < 12; i++) tag[i] ^= mask[i];

    memset(mask, 0, sizeof(mask));
}

int dedalyan_gcm_seal(const dedalyan_gcm_ctx *ctx, const uint8_t nonce[8],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, uint8_t *out, size_t len,
                      uint8_t tag[12])
{
    uint8_t ctr[12];

    if ((uint64_t)len > DEDALYAN_GCM_MAX_MESSAGE) return -1;

    j0_bytes(nonce, ctr);
    inc32(ctr);                     /* гамма начинается с J0 + 1 */
    dedalyan_ctr(&ctx->cipher, ctr, in, out, len, DEDALYAN_ROUNDS);
    compute_tag(ctx, nonce, aad, aad_len, out, len, tag);

    memset(ctr, 0, sizeof(ctr));
    return 0;
}

int dedalyan_gcm_open(const dedalyan_gcm_ctx *ctx, const uint8_t nonce[8],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, uint8_t *out, size_t len,
                      const uint8_t tag[12])
{
    uint8_t expected[12], ctr[12];
    unsigned diff = 0;
    unsigned i;

    if ((uint64_t)len > DEDALYAN_GCM_MAX_MESSAGE) return -1;

    compute_tag(ctx, nonce, aad, aad_len, in, len, expected);

    /* Сравнение за постоянное время: обычный memcmp выходит на первом
     * несовпавшем байте, и время ответа выдаёт, сколько байт угадано. */
    for (i = 0; i < 12; i++) diff |= (unsigned)(expected[i] ^ tag[i]);
    memset(expected, 0, sizeof(expected));
    if (diff != 0) return -1;

    j0_bytes(nonce, ctr);
    inc32(ctr);
    dedalyan_ctr(&ctx->cipher, ctr, in, out, len, DEDALYAN_ROUNDS);
    memset(ctr, 0, sizeof(ctr));
    return 0;
}
