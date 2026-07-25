/* dedalyan.h -- Dedalyan-96/256, блочный шифр. Спецификация 1.0.
 *
 * ВНИМАНИЕ: учебно-исследовательский шифр. Не для защиты реальных данных.
 *
 * Слово -- 48 бит, хранится в uint64_t, старшие 16 бит всегда нулевые.
 * Все функции без динамической аллокации; контекст ключа создаётся вызывающим.
 */
#ifndef DEDALYAN_H
#define DEDALYAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(DEDALYAN_BUILD_DLL)
#  define DEDALYAN_API __declspec(dllexport)
#elif defined(_WIN32) && defined(DEDALYAN_USE_DLL)
#  define DEDALYAN_API __declspec(dllimport)
#else
#  define DEDALYAN_API
#endif

#define DEDALYAN_W            48
#define DEDALYAN_MASK         UINT64_C(0xFFFFFFFFFFFF)
#define DEDALYAN_ROUNDS       16
#define DEDALYAN_WARMUP       4
#define DEDALYAN_BLOCK_BITS   96
#define DEDALYAN_BLOCK_BYTES  12
#define DEDALYAN_KEY_BITS     256
#define DEDALYAN_KEY_BYTES    32

/* Константы раздела 2 спецификации. */
#define DEDALYAN_GAMMA1    UINT64_C(0x46BD0CD0DCAD)  /* γ₁ */
#define DEDALYAN_DELTA     UINT64_C(0x128F8FB70F)    /* δ  */
#define DEDALYAN_GAMMA2    UINT64_C(0x46BB83114CCF)  /* γ₂ */
#define DEDALYAN_PHI       UINT64_C(0x9E3779B97F4A)  /* φ  */
#define DEDALYAN_LAB_DELTA UINT64_C(0x5A827999A2B1)  /* Δ  */

/* Половины блока: l -- старшие 48 бит, r -- младшие. */
typedef struct {
    uint64_t l;
    uint64_t r;
} dedalyan_block;

/* Контекст ключа: предвычисленные подключи и таблицы лабиринта. */
typedef struct {
    uint64_t rk[DEDALYAN_ROUNDS];
    uint8_t  T[2][16];
} dedalyan_ctx;

/* --- инициализация ключа ------------------------------------------------ */

/* key -- 32 байта big-endian (байт 0 содержит старшие биты K). */
DEDALYAN_API void dedalyan_key_setup(dedalyan_ctx *ctx,
                                     const uint8_t key[DEDALYAN_KEY_BYTES]);

/* Затирает контекст нулями. */
DEDALYAN_API void dedalyan_ctx_wipe(dedalyan_ctx *ctx);

/* --- примитивы (экспортируются ради тестов на соответствие Python) ------ */

DEDALYAN_API uint64_t dedalyan_rc(unsigned i);                 /* RC_i */
DEDALYAN_API uint64_t dedalyan_rotl(uint64_t x, unsigned s);
DEDALYAN_API uint64_t dedalyan_rotr(uint64_t x, unsigned s);
DEDALYAN_API uint64_t dedalyan_f(uint64_t r, uint64_t k, unsigned i);
DEDALYAN_API void     dedalyan_build_labyrinth(uint64_t kl, uint8_t T[2][16]);
DEDALYAN_API uint64_t dedalyan_apply_labyrinth(uint64_t x, const uint8_t T[2][16]);

/* Расписание ключей: 16 подключей по 48 бит. */
DEDALYAN_API void dedalyan_key_schedule(const uint8_t key[DEDALYAN_KEY_BYTES],
                                        uint64_t rk[DEDALYAN_ROUNDS]);

/* --- шифрование блока --------------------------------------------------- */

DEDALYAN_API dedalyan_block dedalyan_encrypt(const dedalyan_ctx *ctx,
                                             dedalyan_block b);
DEDALYAN_API dedalyan_block dedalyan_decrypt(const dedalyan_ctx *ctx,
                                             dedalyan_block b);

/* Урезанные версии: rounds ∈ 0..16, Dedalyan-96/256-r<rounds>. */
DEDALYAN_API dedalyan_block dedalyan_encrypt_r(const dedalyan_ctx *ctx,
                                               dedalyan_block b,
                                               unsigned rounds);
DEDALYAN_API dedalyan_block dedalyan_decrypt_r(const dedalyan_ctx *ctx,
                                               dedalyan_block b,
                                               unsigned rounds);

/* Байтовые обёртки, big-endian, 12 байт. in и out могут совпадать. */
DEDALYAN_API void dedalyan_encrypt_bytes(const dedalyan_ctx *ctx,
                                         const uint8_t in[DEDALYAN_BLOCK_BYTES],
                                         uint8_t out[DEDALYAN_BLOCK_BYTES]);
DEDALYAN_API void dedalyan_decrypt_bytes(const dedalyan_ctx *ctx,
                                         const uint8_t in[DEDALYAN_BLOCK_BYTES],
                                         uint8_t out[DEDALYAN_BLOCK_BYTES]);

/* --- пакетная обработка (дружественно к ctypes) ------------------------- */

/* io -- массив из 2*n элементов: пары (l, r). Обработка на месте. */
DEDALYAN_API void dedalyan_encrypt_blocks(const dedalyan_ctx *ctx,
                                          uint64_t *io, size_t n,
                                          unsigned rounds);
DEDALYAN_API void dedalyan_decrypt_blocks(const dedalyan_ctx *ctx,
                                          uint64_t *io, size_t n,
                                          unsigned rounds);

/* --- режим CTR ---------------------------------------------------------- */

/* Счётчик 96-битный, инкремент по модулю 2^96, big-endian.
 * in может быть NULL -- тогда out заполняется чистой гаммой. */
DEDALYAN_API void dedalyan_ctr(const dedalyan_ctx *ctx,
                               const uint8_t counter[DEDALYAN_BLOCK_BYTES],
                               const uint8_t *in, uint8_t *out, size_t len,
                               unsigned rounds);

/* --- служебное ---------------------------------------------------------- */

/* Пораундовая трассировка (формат раздела 8.5).
 * trace_f/trace_l/trace_r -- массивы на rounds элементов, любой может быть NULL. */
DEDALYAN_API void dedalyan_encrypt_trace(const dedalyan_ctx *ctx,
                                         dedalyan_block b, unsigned rounds,
                                         uint64_t *trace_f,
                                         uint64_t *trace_l,
                                         uint64_t *trace_r);

DEDALYAN_API const char *dedalyan_version(void);

#ifdef __cplusplus
}
#endif

#endif /* DEDALYAN_H */
