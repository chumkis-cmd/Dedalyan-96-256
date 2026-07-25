/* gcm.h -- Dedalyan-GCM-96: аутентифицированное шифрование.
 *
 * ЭТО НЕ NIST SP 800-38D. Настоящий GCM определён для 128-битного блока;
 * здесь та же схема адаптирована на GF(2^96), потому что блок Dedalyan --
 * 96 бит. Подробности и обоснование поля -- в dedalyan_gcm.py.
 *
 * Поле: GF(2^96) по модулю x^96 + x^10 + x^9 + x^6 + 1 (неприводимость
 * проверена вычислением). Соглашение о битах -- как в GCM: старший бит
 * блока есть коэффициент при x^0, поэтому умножение на x -- сдвиг вправо.
 */
#ifndef DEDALYAN_GCM_H
#define DEDALYAN_GCM_H

#include "dedalyan.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEDALYAN_GCM_NONCE_BYTES  8
#define DEDALYAN_GCM_TAG_BYTES    12
#define DEDALYAN_GCM_BLOCK_BYTES  DEDALYAN_BLOCK_BYTES   /* 12 */

/* Счётчик блоков 32-битный, значения 0 и 1 заняты под J0. */
#define DEDALYAN_GCM_MAX_MESSAGE  ((uint64_t)(0xFFFFFFFFu - 1u) * 12u)

/* Элемент GF(2^96): value = (hi << 32) | lo, hi -- биты 95..32. */
typedef struct {
    uint64_t hi;
    uint32_t lo;
} ded_gf96;

/* Контекст GCM: подключи шифра + таблицы для GHASH. */
typedef struct {
    dedalyan_ctx cipher;
    ded_gf96     M[16];    /* M[i] = i * H, ниббл в старшей позиции */
    ded_gf96     R4[16];   /* вклад редукции при сдвиге на 4 бита    */
    ded_gf96     H;        /* подключ хеша H = E_K(0^96)             */
} dedalyan_gcm_ctx;

/* --- инициализация ------------------------------------------------------ */

DEDALYAN_API void dedalyan_gcm_init(dedalyan_gcm_ctx *ctx,
                                    const uint8_t key[DEDALYAN_KEY_BYTES]);
DEDALYAN_API void dedalyan_gcm_wipe(dedalyan_gcm_ctx *ctx);

/* --- примитивы поля (экспортируются ради тестов на паритет с Python) ---- */

/* Побитовое умножение -- медленный эталон, по которому проверяется таблица. */
DEDALYAN_API void dedalyan_gcm_mul_ref(const uint8_t x[12], const uint8_t y[12],
                                       uint8_t out[12]);

/* Умножение на H через таблицы. */
DEDALYAN_API void dedalyan_gcm_mul_h(const dedalyan_gcm_ctx *ctx,
                                     const uint8_t x[12], uint8_t out[12]);

/* GHASH_H(data), длина обязана быть кратна 12. */
DEDALYAN_API void dedalyan_gcm_ghash(const dedalyan_gcm_ctx *ctx,
                                     const uint8_t *data, size_t len,
                                     uint8_t out[12]);

/* --- AEAD --------------------------------------------------------------- */

/* Шифрует len байт и пишет тег. in и out могут совпадать.
 * Возвращает 0 при успехе, -1 если сообщение длиннее допустимого. */
DEDALYAN_API int dedalyan_gcm_seal(const dedalyan_gcm_ctx *ctx,
                                   const uint8_t nonce[8],
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *in, uint8_t *out, size_t len,
                                   uint8_t tag[12]);

/* Проверяет тег и расшифровывает. Возвращает 0 при успехе, -1 если тег не
 * сошёлся. При отказе out не содержит осмысленных данных: расшифровка
 * выполняется только после проверки. */
DEDALYAN_API int dedalyan_gcm_open(const dedalyan_gcm_ctx *ctx,
                                   const uint8_t nonce[8],
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *in, uint8_t *out, size_t len,
                                   const uint8_t tag[12]);

#ifdef __cplusplus
}
#endif

#endif /* DEDALYAN_GCM_H */
