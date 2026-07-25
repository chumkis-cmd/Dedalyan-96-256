/* test_vectors.c -- проверка C-реализации по разделу 8 спецификации.
 * Вывод намеренно на английском: русский ломается в консоли Windows. */

#include "dedalyan.h"
#include "kernels.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

static void ok(int cond, const char *what)
{
    checks++;
    if (!cond) { failures++; printf("  FAIL  %s\n", what); }
}

static void ok_u64(uint64_t got, uint64_t want, const char *what)
{
    checks++;
    if (got != want) {
        failures++;
        printf("  FAIL  %-34s got %012llx want %012llx\n", what,
               (unsigned long long)got, (unsigned long long)want);
    }
}

static void hex2bytes(const char *hex, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* ---- раздел 2: раундовые константы ------------------------------------- */

static const uint64_t RC_REF[16] = {
    UINT64_C(0x3188EBE1E0B8), UINT64_C(0xCFC0659B6002),
    UINT64_C(0x6DF7DF54DF4C), UINT64_C(0x0C2F590E5E96),
    UINT64_C(0xAA66D2C7DDE0), UINT64_C(0x489E4C815D2A),
    UINT64_C(0xE6D5C63ADC74), UINT64_C(0x850D3FF45BBE),
    UINT64_C(0x2344B9ADDB08), UINT64_C(0xC17C33675A52),
    UINT64_C(0x5FB3AD20D99C), UINT64_C(0xFDEB26DA58E6),
    UINT64_C(0x9C22A093D830), UINT64_C(0x3A5A1A4D577A),
    UINT64_C(0xD8919406D6C4), UINT64_C(0x76C90DC0560E)
};

static void test_round_constants(void)
{
    int i;
    printf("[8.0] round constants\n");
    for (i = 0; i < 16; i++) ok_u64(dedalyan_rc((unsigned)i), RC_REF[i], "RC_i");
}

/* ---- раздел 8.1: лабиринт ---------------------------------------------- */

static void test_labyrinth(void)
{
    static const char *T0_ZERO = "a9dc013f46e85b27";
    static const char *T1_ZERO = "a1e4c03d76b9f825";
    static const char *T0_SEQ  = "3bed640f928c157a";
    static const char *T1_SEQ  = "e68359f1b4cd207a";
    uint8_t T[2][16];
    char buf[17];
    int i;

    printf("[8.1] labyrinth\n");

    dedalyan_build_labyrinth(UINT64_C(0), T);
    for (i = 0; i < 16; i++) buf[i] = "0123456789abcdef"[T[0][i]];
    buf[16] = 0; ok(strcmp(buf, T0_ZERO) == 0, "T0 for KL=0");
    for (i = 0; i < 16; i++) buf[i] = "0123456789abcdef"[T[1][i]];
    buf[16] = 0; ok(strcmp(buf, T1_ZERO) == 0, "T1 for KL=0");

    dedalyan_build_labyrinth(UINT64_C(0x0123456789ABCDEF), T);
    for (i = 0; i < 16; i++) buf[i] = "0123456789abcdef"[T[0][i]];
    buf[16] = 0; ok(strcmp(buf, T0_SEQ) == 0, "T0 for KL=0123456789ABCDEF");
    for (i = 0; i < 16; i++) buf[i] = "0123456789abcdef"[T[1][i]];
    buf[16] = 0; ok(strcmp(buf, T1_SEQ) == 0, "T1 for KL=0123456789ABCDEF");

    ok_u64(dedalyan_apply_labyrinth(UINT64_C(0x0123456789AB),
                                    (const uint8_t (*)[16])T),
           UINT64_C(0xE6ED640F92CD), "Lab(0x0123456789AB)");
}

/* ---- разделы 8.2 и 8.3: подключи --------------------------------------- */

static const uint64_t KS_ZERO[16] = {
    UINT64_C(0x9864a848b6d4), UINT64_C(0x66845d0326d1),
    UINT64_C(0x9ce6eff8cd60), UINT64_C(0xde534c0aeec3),
    UINT64_C(0x84ed264ac5bb), UINT64_C(0xaedd6a826c93),
    UINT64_C(0x2c4d8a772d04), UINT64_C(0xaba7eec66f0f),
    UINT64_C(0xff822a71a117), UINT64_C(0x13776bbc1fbf),
    UINT64_C(0x499da61debdf), UINT64_C(0xff1503bd8aac),
    UINT64_C(0xdc17510f5fae), UINT64_C(0x3a08b3dab4f4),
    UINT64_C(0x63bbb6a9252b), UINT64_C(0x30a6e63f94e6)
};

static const uint64_t KS_SEQ[16] = {
    UINT64_C(0x352b543e645d), UINT64_C(0x3bb3b319fa45),
    UINT64_C(0xba34ee3b5816), UINT64_C(0xf5015d474faa),
    UINT64_C(0x18454389852b), UINT64_C(0x545daa0a6112),
    UINT64_C(0x51f0a63d8e60), UINT64_C(0xb9bddda2e38c),
    UINT64_C(0x4a92ed2d2816), UINT64_C(0x47cdd4e8e543),
    UINT64_C(0xe10755f1fc74), UINT64_C(0xb7f0a3bd6e0c),
    UINT64_C(0x3d5d558b3b7f), UINT64_C(0xe04b6a7bd904),
    UINT64_C(0x558c5a714b1b), UINT64_C(0xf9958a46e7bf)
};

static void test_key_schedule(void)
{
    uint8_t key[32];
    uint64_t rk[16];
    int i;

    printf("[8.2] subkeys for K=0\n");
    memset(key, 0, 32);
    dedalyan_key_schedule(key, rk);
    for (i = 0; i < 16; i++) ok_u64(rk[i], KS_ZERO[i], "k_i (K=0)");

    printf("[8.3] subkeys for K=000102..1e1f\n");
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    dedalyan_key_schedule(key, rk);
    for (i = 0; i < 16; i++) ok_u64(rk[i], KS_SEQ[i], "k_i (K=0001..1f)");
}

/* ---- раздел 8.4: векторы шифрования ------------------------------------ */

struct tv { const char *name, *p, *k, *c; };

static const struct tv TVS[4] = {
    { "TV1", "000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "70a4ceaa4a6737fb294a0edf" },
    { "TV2", "000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "85a903c2a6b73b50f00e1405" },
    { "TV3", "0123456789abcdef01234567",
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "9b631fe623f15016cdba801e" },
    { "TV4", "ffffffffffffffffffffffff",
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "a936a309096319f869f6549d" }
};

static void test_vectors(void)
{
    int t, i;
    printf("[8.4] encryption vectors\n");
    for (t = 0; t < 4; t++) {
        uint8_t p[12], k[32], c[12], want[12], back[12];
        dedalyan_ctx ctx;
        hex2bytes(TVS[t].p, p, 12);
        hex2bytes(TVS[t].k, k, 32);
        hex2bytes(TVS[t].c, want, 12);
        dedalyan_key_setup(&ctx, k);
        dedalyan_encrypt_bytes(&ctx, p, c);
        checks++;
        if (memcmp(c, want, 12) != 0) {
            failures++;
            printf("  FAIL  %s ciphertext: got ", TVS[t].name);
            for (i = 0; i < 12; i++) printf("%02x", c[i]);
            printf(" want %s\n", TVS[t].c);
        }
        dedalyan_decrypt_bytes(&ctx, c, back);
        ok(memcmp(back, p, 12) == 0, "decrypt(encrypt(P)) == P");
    }
}

/* ---- раздел 8.5: пораундовые значения TV3 ------------------------------ */

static const uint64_t TV3_F[16] = {
    UINT64_C(0x229e7f0eb588), UINT64_C(0x94e01bc2aad8),
    UINT64_C(0xa9c66a1086e7), UINT64_C(0xfd9e1674955a),
    UINT64_C(0xa7c66b61b1b1), UINT64_C(0x82336d2325be),
    UINT64_C(0x05734be79f0d), UINT64_C(0x7e3febc6f8b6),
    UINT64_C(0x267030894057), UINT64_C(0xc572310f4b4c),
    UINT64_C(0x5f51ec67dd59), UINT64_C(0xbd7201f955d8),
    UINT64_C(0x60e553c6f23f), UINT64_C(0x1fb2103a188a),
    UINT64_C(0xaa69e031d8b8), UINT64_C(0x6f39670621ed)
};
static const uint64_t TV3_L[16] = {
    UINT64_C(0xcdef01234567), UINT64_C(0x23bd3a693c23),
    UINT64_C(0x590f1ae1efbf), UINT64_C(0x8a7b5079bac4),
    UINT64_C(0xa4910c957ae5), UINT64_C(0x2dbd3b180b75),
    UINT64_C(0x26a261b65f5b), UINT64_C(0x28ce70ff9478),
    UINT64_C(0x589d8a70a7ed), UINT64_C(0x0ebe4076d42f),
    UINT64_C(0x9defbb7feca1), UINT64_C(0x51efac110976),
    UINT64_C(0x209dba86b979), UINT64_C(0x310affd7fb49),
    UINT64_C(0x3f2faabca1f3), UINT64_C(0x9b631fe623f1)
};
static const uint64_t TV3_R[16] = {
    UINT64_C(0x23bd3a693c23), UINT64_C(0x590f1ae1efbf),
    UINT64_C(0x8a7b5079bac4), UINT64_C(0xa4910c957ae5),
    UINT64_C(0x2dbd3b180b75), UINT64_C(0x26a261b65f5b),
    UINT64_C(0x28ce70ff9478), UINT64_C(0x589d8a70a7ed),
    UINT64_C(0x0ebe4076d42f), UINT64_C(0x9defbb7feca1),
    UINT64_C(0x51efac110976), UINT64_C(0x209dba86b979),
    UINT64_C(0x310affd7fb49), UINT64_C(0x3f2faabca1f3),
    UINT64_C(0x9b631fe623f1), UINT64_C(0x5016cdba801e)
};

static void test_trace(void)
{
    uint8_t k[32];
    dedalyan_ctx ctx;
    dedalyan_block b;
    uint64_t tf[16], tl[16], tr[16];
    int i;

    printf("[8.5] per-round trace for TV3\n");
    hex2bytes(TVS[2].k, k, 32);
    dedalyan_key_setup(&ctx, k);
    b.l = UINT64_C(0x0123456789ab);
    b.r = UINT64_C(0xcdef01234567);
    dedalyan_encrypt_trace(&ctx, b, 16, tf, tl, tr);
    for (i = 0; i < 16; i++) {
        ok_u64(tf[i], TV3_F[i], "F_i");
        ok_u64(tl[i], TV3_L[i], "L_i");
        ok_u64(tr[i], TV3_R[i], "R_i");
    }
}

/* ---- раздел 10.4: точки, где вероятны ошибки --------------------------- */

static void test_pitfalls(void)
{
    dedalyan_ctx ctx;
    uint8_t key[32];
    uint64_t x;
    int i;

    printf("[10.4] pitfalls\n");

    /* 3. Сдвиг именно циклический, при s >= 48 берётся s mod 48. */
    x = UINT64_C(0x800000000001);
    ok_u64(dedalyan_rotl(x, 1), UINT64_C(0x000000000003), "rotl wraps (cyclic)");
    ok_u64(dedalyan_rotl(x, 48), x, "rotl by 48 == identity");
    ok_u64(dedalyan_rotl(x, 49), dedalyan_rotl(x, 1), "rotl s mod 48");
    ok_u64(dedalyan_rotr(dedalyan_rotl(x, 13), 13), x, "rotr undoes rotl");
    ok_u64(dedalyan_rotl(x, 0), x, "rotl by 0 == identity");

    /* 2. Маскирование после умножения: результат всегда 48-битный. */
    for (i = 0; i < 64; i++) {
        uint64_t v = dedalyan_f(UINT64_C(0xFFFFFFFFFFFF) - (uint64_t)i,
                                UINT64_C(0xFFFFFFFFFFFF), (unsigned)i & 15u);
        ok(v <= DEDALYAN_MASK, "F output fits in 48 bits");
    }

    /* 7. Расшифровка на урезанном числе раундов тоже обратима. */
    memset(key, 0x5a, 32);
    dedalyan_key_setup(&ctx, key);
    for (i = 1; i <= 16; i++) {
        dedalyan_block p, c, d;
        p.l = UINT64_C(0x0123456789ab);
        p.r = UINT64_C(0xcdef01234567);
        c = dedalyan_encrypt_r(&ctx, p, (unsigned)i);
        d = dedalyan_decrypt_r(&ctx, c, (unsigned)i);
        ok(d.l == p.l && d.r == p.r, "round-reduced roundtrip");
    }
}

/* ---- обратимость и CTR -------------------------------------------------- */

static void test_roundtrip_random(void)
{
    uint64_t st = UINT64_C(0xD1CE5EED);
    dedalyan_ctx ctx;
    size_t i;

    printf("[extra] random roundtrip, 200000 pairs\n");
    for (i = 0; i < 200000; i++) {
        uint8_t key[32];
        dedalyan_block p, c, d;
        int j;
        for (j = 0; j < 4; j++) {
            uint64_t v = ded_k_splitmix64(&st);
            int b;
            for (b = 0; b < 8; b++) key[j * 8 + b] = (uint8_t)(v >> (56 - 8 * b));
        }
        p.l = ded_k_splitmix64(&st) & DEDALYAN_MASK;
        p.r = ded_k_splitmix64(&st) & DEDALYAN_MASK;
        dedalyan_key_setup(&ctx, key);
        c = dedalyan_encrypt(&ctx, p);
        d = dedalyan_decrypt(&ctx, c);
        if (d.l != p.l || d.r != p.r) {
            failures++;
            printf("  FAIL  roundtrip at sample %llu\n", (unsigned long long)i);
            break;
        }
    }
    checks++;
}

static void test_ctr(void)
{
    dedalyan_ctx ctx;
    uint8_t key[32], counter[12], pt[100], ct[100], back[100];
    int i;

    printf("[extra] CTR mode\n");
    for (i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    memset(counter, 0, 12);
    counter[11] = 0xFD;          /* проверяем перенос через границу байта */
    for (i = 0; i < 100; i++) pt[i] = (uint8_t)i;

    dedalyan_key_setup(&ctx, key);
    dedalyan_ctr(&ctx, counter, pt, ct, sizeof(pt), 16);
    dedalyan_ctr(&ctx, counter, ct, back, sizeof(ct), 16);
    ok(memcmp(pt, back, sizeof(pt)) == 0, "CTR is self-inverse");
    ok(memcmp(pt, ct, sizeof(pt)) != 0, "CTR actually changes data");

    /* Счётчик = все единицы: инкремент должен завернуться в ноль. */
    memset(counter, 0xFF, 12);
    dedalyan_ctr(&ctx, counter, pt, ct, sizeof(pt), 16);
    dedalyan_ctr(&ctx, counter, ct, back, sizeof(ct), 16);
    ok(memcmp(pt, back, sizeof(pt)) == 0, "CTR wraps 2^96 correctly");
}

int main(void)
{
    printf("Dedalyan test vectors -- %s\n\n", dedalyan_version());

    test_round_constants();
    test_labyrinth();
    test_key_schedule();
    test_vectors();
    test_trace();
    test_pitfalls();
    test_roundtrip_random();
    test_ctr();

    printf("\n%d checks, %d failures\n", checks, failures);
    if (failures == 0) printf("ALL TESTS PASSED\n");
    return failures ? 1 : 0;
}
