"""Dedalyan-96/256 — эталонная реализация для генерации тестовых векторов."""
W = 48
M = (1 << W) - 1
N = 16
WARMUP = 4

G1 = 0x46BD0CD0DCAD
DL = 0x128F8FB70F
G2 = 0x46BB83114CCF
PHI = 0x9E3779B97F4A
DELTA = 0x5A827999A2B1

def rotl(x, s): s %= W; return ((x << s) | (x >> (W - s))) & M
def rotr(x, s): s %= W; return ((x >> s) | (x << (W - s))) & M
def RC(i): return ((i + 44) * PHI) & M

def F(R, k, i):
    rc = RC(i)
    Y  = ((R + k) & M) * G1 & M
    x0 = ((Y + rotr(Y, 7)) & M) ^ ((R * DL) & M)
    x1 = (x0 + rc) & M
    x2 = ((x1 + k) & M) ^ rotl(Y, 3)
    return ((x2 + rc) & M) * G2 & M

def build_lab(KL):
    U = (KL >> 16) & M
    V = ((KL & M) ^ DELTA) & M
    nu = []
    for t in range(3):
        V = F(V, U, t)
        nu += [(V >> (4 * j)) & 0xF for j in range(12)]
    T = [list(range(16)), list(range(16))]
    s = 0
    for t in (0, 1):
        for j in range(15, 0, -1):
            r = nu[s] % (j + 1); s += 1
            T[t][j], T[t][r] = T[t][r], T[t][j]
    return T

def Lab(x, T):
    y = 0
    for j in range(12):
        b = (x >> (4 * ((j + 6) % 12) + 2)) & 1
        y |= T[b][(x >> (4 * j)) & 0xF] << (4 * j)
    return y

def key_schedule(K):
    KL = (K >> 192) & 0xFFFFFFFFFFFFFFFF
    S  = [(K >> (W * j)) & M for j in range(4)]
    T  = build_lab(KL)
    ks = []
    for i in range(-WARMUP, N):
        S = [Lab(v, T) for v in S]
        for j in range(4):
            S[j] = (S[j] + S[(j + 1) % 4]) & M
        r = 2 * (i % 24) + 5
        S = [rotl(v, r) for v in S]
        S = [Lab(v, T) for v in S]
        if i >= 0:
            ks.append((S[i % 4] + RC(i)) & M)
    return ks

def encrypt_block(P, K):
    L, R = (P >> W) & M, P & M
    for i, k in enumerate(key_schedule(K)):
        L, R = R, L ^ F(R, k, i)
    return (L << W) | R

def decrypt_block(C, K):
    ks = key_schedule(K)
    L, R = (C >> W) & M, C & M
    for i in reversed(range(N)):
        R, L = L, R ^ F(L, ks[i], i)
    return (L << W) | R
