/* kernels.h -- горячие циклы для криптоаналитического набора.
 *
 * Все функции детерминированы: поток случайных чисел задаётся seed
 * (splitmix64), поэтому результат воспроизводим и Python может разбить
 * работу между процессами, просто раздав им разные seed.
 *
 * Нумерация бит блока: бит 0 -- младший бит R, бит 47 -- старший бит R,
 * бит 48 -- младший бит L, бит 95 -- старший бит L.
 */
#ifndef DEDALYAN_KERNELS_H
#define DEDALYAN_KERNELS_H

#include "dedalyan.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Генератор splitmix64 -- экспортируется, чтобы Python мог воспроизвести
 * ту же последовательность при отладке. */
DEDALYAN_API uint64_t ded_k_splitmix64(uint64_t *state);

/* --- дифференциальный криптоанализ -------------------------------------- */

/* Для n случайных P считает, сколько раз каждый выходной бит переворачивается
 * при входной разности (dl, dr). out -- 96 счётчиков. */
DEDALYAN_API void ded_k_diff_bitcount(const dedalyan_ctx *ctx, unsigned rounds,
                                      uint64_t dl, uint64_t dr,
                                      size_t n, uint64_t seed,
                                      uint64_t out[96]);

/* Усечённые разности: для каждого из 24 нибблов блока отмечает, какие из 16
 * значений разности встретились. seen -- 24*16 байт (0/1).
 * Ниббл 0 -- младший в R, ниббл 23 -- старший в L. */
DEDALYAN_API void ded_k_diff_nibble_seen(const dedalyan_ctx *ctx, unsigned rounds,
                                         uint64_t dl, uint64_t dr,
                                         size_t n, uint64_t seed,
                                         uint8_t seen[24 * 16]);

/* Число пар (P, P⊕Δin), дающих в точности выходную разность (ol, or_). */
DEDALYAN_API uint64_t ded_k_diff_exact(const dedalyan_ctx *ctx, unsigned rounds,
                                       uint64_t dl, uint64_t dr,
                                       uint64_t ol, uint64_t orr,
                                       size_t n, uint64_t seed);

/* --- диффузия ------------------------------------------------------------ */

/* Покрытие: out[2b], out[2b+1] -- ИЛИ всех выходных разностей (l, r),
 * полученных переворотом входного бита b. out -- 192 элемента. */
DEDALYAN_API void ded_k_diffusion_cover(const dedalyan_ctx *ctx, unsigned rounds,
                                        size_t n, uint64_t seed,
                                        uint64_t out[192]);

/* Полная матрица: out[b*96 + o] -- сколько раз выходной бит o перевернулся
 * при перевороте входного бита b. out -- 9216 элементов. */
DEDALYAN_API void ded_k_diffusion_count(const dedalyan_ctx *ctx, unsigned rounds,
                                        size_t n, uint64_t seed,
                                        uint32_t out[96 * 96]);

/* Лавина по открытому тексту: сумма и сумма квадратов расстояний Хэмминга
 * при перевороте одного случайного входного бита. */
DEDALYAN_API void ded_k_avalanche(const dedalyan_ctx *ctx, unsigned rounds,
                                  size_t n, uint64_t seed,
                                  uint64_t *sum_hd, uint64_t *sum_hd2);

/* --- линейный криптоанализ ---------------------------------------------- */

/* masks -- 4*npairs элементов: (in_l, in_r, out_l, out_r).
 * counts[i] -- число случаев, когда <α,P> ⊕ <β,C> == 0, на общих n текстах.
 * Смещение: |counts[i]/n − 1/2|, корреляция: 2·смещение. */
DEDALYAN_API void ded_k_linear_pairs(const dedalyan_ctx *ctx, unsigned rounds,
                                     const uint64_t *masks, size_t npairs,
                                     size_t n, uint64_t seed,
                                     uint64_t *counts);

/* --- бумеранг ------------------------------------------------------------ */

/* Возвращает число вернувшихся квартетов для (α = верхняя разность,
 * δ = нижняя разность). Случайно ожидается n·2^−96. */
DEDALYAN_API uint64_t ded_k_boomerang(const dedalyan_ctx *ctx, unsigned rounds,
                                      uint64_t al, uint64_t ar,
                                      uint64_t dl, uint64_t dr,
                                      size_t n, uint64_t seed);

/* --- интегральный криптоанализ и алгебраическая степень ------------------ */

/* XOR-сумма шифротекстов по аффинному подпространству: базовый блок
 * (base_l, base_r), активные биты перечислены в active_bits (индексы 0..95).
 * Это производная порядка nactive: ненулевая сумма означает степень ≥ nactive.
 * Перебирается 2^nactive блоков, поэтому nactive ≤ 32. */
DEDALYAN_API void ded_k_integral_sum(const dedalyan_ctx *ctx, unsigned rounds,
                                     uint64_t base_l, uint64_t base_r,
                                     const uint8_t *active_bits,
                                     unsigned nactive,
                                     uint64_t *sum_l, uint64_t *sum_r);

/* --- расписание ключей --------------------------------------------------- */

/* Лавина по мастер-ключу через весь шифр: n случайных пар (ключ, текст),
 * для каждого из 256 бит ключа считает переворот каждого из 96 бит выхода.
 * out -- 256*96 элементов. */
DEDALYAN_API void ded_k_key_avalanche(unsigned rounds, size_t n, uint64_t seed,
                                      uint32_t out[256 * 96]);

/* Лавина по мастер-ключу для каждого подключа: sum_hd/sum_hd2 -- по 16
 * элементов, накапливают расстояние Хэмминга между подключами при
 * перевороте одного случайного бита ключа. */
DEDALYAN_API void ded_k_subkey_avalanche(size_t n, uint64_t seed,
                                         uint64_t sum_hd[16],
                                         uint64_t sum_hd2[16]);

/* Связанные ключи: фиксированная разность ключей dk (32 байта),
 * out -- 96 счётчиков переворотов выходных бит. */
DEDALYAN_API void ded_k_relkey_bitcount(unsigned rounds, const uint8_t dk[32],
                                        size_t n, uint64_t seed,
                                        uint64_t out[96]);

/* Отпечатки ключей: для n псевдослучайных ключей шифрует блок (pl, pr).
 * out -- 2*n элементов (l, r). Поиск коллизий -- на стороне Python. */
DEDALYAN_API void ded_k_key_fingerprint(unsigned rounds, uint64_t pl, uint64_t pr,
                                        size_t n, uint64_t seed,
                                        uint64_t *out);

/* Подключи для n псевдослучайных ключей: out -- 16*n элементов. */
DEDALYAN_API void ded_k_subkey_dump(size_t n, uint64_t seed, uint64_t *out);

/* Число неподвижных точек лабиринта (T0 и T1 вместе, из 32 позиций)
 * для n псевдослучайных ключей. out -- n элементов. */
DEDALYAN_API void ded_k_labyrinth_fixpoints(size_t n, uint64_t seed,
                                            uint8_t *out);

/* --- ротационный криптоанализ -------------------------------------------- */

/* Число случаев E(P ⋘ rot) == E(P) ⋘ rot (обе половины вращаются отдельно).
 * Если key_rot != 0, ключ тоже вращается на rot (ротационные связанные ключи). */
DEDALYAN_API uint64_t ded_k_rotational(unsigned rounds, unsigned rot,
                                       int key_rot, size_t n, uint64_t seed);

/* --- потоки для статистики ----------------------------------------------- */

/* Гамма в режиме счётчика, len байт, начиная со счётчика (chi, clo96). */
DEDALYAN_API void ded_k_ctr_stream(const dedalyan_ctx *ctx, unsigned rounds,
                                   uint64_t ctr_hi, uint64_t ctr_lo,
                                   uint8_t *out, size_t len);

/* Шифрование n случайных блоков, out -- 2*n элементов (режим ECB, случайный
 * вход: проверка «шифр как случайная функция»). */
DEDALYAN_API void ded_k_random_ecb(const dedalyan_ctx *ctx, unsigned rounds,
                                   size_t n, uint64_t seed, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* DEDALYAN_KERNELS_H */
