#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#include "jsmn.h" 
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <atomic>
#include <mutex>
#include <string.h>

#define CONST_MES_SIZE_8   8192 // 2^10

#define CONTINUE_POS       36

#define K_LEN              32

#define INIT_N_LEN         0x4000000
#define MAX_N_LEN          0x7FC9FF98
#define IncreaseStart      (600*1024)
#define IncreaseEnd        (4198400)
#define IncreasePeriodForN (50*1024)

#define MAX_SOLS 16

#define NONCES_PER_THREAD  1

#define MIN_FREE_MEMORY    2200000000
#define MIN_FREE_MEMORY_PREHASH 7300000000

#define NUM_SIZE_8         32

#define PK_SIZE_8          33

#define NONCE_SIZE_8       8

#define HEIGHT_SIZE       4

#define INDEX_SIZE_8       4

#define BUF_SIZE_8         128

#define qhi_s              "0xFFFFFFFF"
#define q4_s               "0xFFFFFFFE"
#define q3_s               "0xBAAEDCE6"
#define q2_s               "0xAF48A03B"
#define q1_s               "0xBFD25E8C"
#define q0_s               "0xD0364141"

#define Q3                 0xFFFFFFFFFFFFFFFF
#define Q2                 0xFFFFFFFFFFFFFFFE
#define Q1                 0xBAAEDCE6AF48A03B
#define Q0                 0xBFD25E8CD0364141

#define MAX_POST_RETRIES   5

#define MAX_URL_SIZE       1024

#define JSON_CAPACITY      256

#define MAX_JSON_CAPACITY  8192

#define REQ_LEN           11// 9

#define MES_POS            2

#define BOUND_POS          4

#define PK_POS             6

#define CONF_LEN           21

#define SEED_POS           2

#define NODE_POS           4

#define KEEP_POS           6

#define ERROR_STAT         "stat"
#define ERROR_ALLOC        "Host memory allocation"
#define ERROR_IO           "I/O"
#define ERROR_CURL         "Curl"
#define ERROR_OPENSSL      "OpenSSL"

#define NUM_SIZE_4         (NUM_SIZE_8 << 1)
#define NUM_SIZE_32        (NUM_SIZE_8 >> 2)
#define NUM_SIZE_64        (NUM_SIZE_8 >> 3)
#define NUM_SIZE_32_BLOCK  (1 + (NUM_SIZE_32 - 1) / BLOCK_DIM)
#define NUM_SIZE_8_BLOCK   (NUM_SIZE_32_BLOCK << 2)
#define ROUND_NUM_SIZE_32  (NUM_SIZE_32_BLOCK * BLOCK_DIM)

#define PK_SIZE_4          (PK_SIZE_8 << 1)
#define PK_SIZE_32_BLOCK   (1 + NUM_SIZE_32 / BLOCK_DIM)
#define PK_SIZE_8_BLOCK    (PK_SIZE_32_BLOCK << 2)
#define ROUND_PK_SIZE_32   (PK_SIZE_32_BLOCK * BLOCK_DIM)
#define COUPLED_PK_SIZE_32 (((PK_SIZE_8 << 1) + 3) >> 2)

#define NONCE_SIZE_4       (NONCE_SIZE_8 << 1)
#define NONCE_SIZE_32      (NONCE_SIZE_8 >> 2)

struct ctx_t;

#define DATA_SIZE_8                                                            \
(                                                                              \
    (1 + (2 * PK_SIZE_8 + 2 + 3 * NUM_SIZE_8 + sizeof(ctx_t) - 1) / BLOCK_DIM) \
    * BLOCK_DIM                                                                \
)

// necessary workspace size
#define WORKSPACE_SIZE_8                                                       \
(                                                                              \
    (                                                                          \
        (uint32_t)((N_LEN << 1) + 1) * INDEX_SIZE_8                            \
        > NONCES_PER_ITER * (NUM_SIZE_8  + (INDEX_SIZE_8 << 1)) + INDEX_SIZE_8 \
    )?                                                                         \
    (uint32_t)((N_LEN << 1) + 1) * INDEX_SIZE_8:                               \
    NONCES_PER_ITER * (NUM_SIZE_8  + (INDEX_SIZE_8 << 1)) + INDEX_SIZE_8       \
)

#define NP_SIZE_32_BLOCK   (1 + (NUM_SIZE_32 << 1) / BLOCK_DIM)
#define NP_SIZE_8_BLOCK    (NP_SIZE_32_BLOCK << 2)
#define ROUND_NP_SIZE_32   (NP_SIZE_32_BLOCK * BLOCK_DIM)

#define PNP_SIZE_32_BLOCK                                                      \
(1 + (COUPLED_PK_SIZE_32 + NUM_SIZE_32 - 1) / BLOCK_DIM)

#define PNP_SIZE_8_BLOCK   (PNP_SIZE_32_BLOCK << 2)
#define ROUND_PNP_SIZE_32  (PNP_SIZE_32_BLOCK * BLOCK_DIM)

#define NC_SIZE_32_BLOCK                                                       \
(1 + (NUM_SIZE_32 + sizeof(ctx_t) - 1) / BLOCK_DIM)

#define NC_SIZE_8_BLOCK    (NC_SIZE_32_BLOCK << 2)
#define ROUND_NC_SIZE_32   (NC_SIZE_32_BLOCK * BLOCK_DIM)

#define THREADS_PER_ITER   (NONCES_PER_ITER / NONCES_PER_THREAD)

typedef unsigned int uint_t;

typedef enum
{
    STATE_CONTINUE = 0,
    STATE_KEYGEN = 1,
    STATE_REHASH = 2,
    STATE_INTERRUPT = 3
}
state_t;

struct info_t
{
    std::mutex info_mutex;

    uint8_t AlgVer;
    uint8_t bound[NUM_SIZE_8];
    uint8_t mes[NUM_SIZE_8];
    uint8_t sk[NUM_SIZE_8];
    uint8_t pk[PK_SIZE_8];
    char skstr[NUM_SIZE_4];
    char pkstr[PK_SIZE_4 + 1];
    int keepPrehash;
    char to[MAX_URL_SIZE];
    char endJob[MAX_URL_SIZE];
    bool doJob;
    //pool additions
    char pool[MAX_URL_SIZE];
    uint8_t Hblock[HEIGHT_SIZE];

   	char    stratumMode;
	uint8_t extraNonceStart[NONCE_SIZE_8];
	uint8_t extraNonceEnd[NONCE_SIZE_8];

    std::atomic<uint_t> blockId; 
};

struct json_t
{
    size_t cap;
    size_t len;
    char * ptr;
    jsmntok_t * toks;

    json_t(const int strlen, const int toklen);
    json_t(const json_t & newjson);
    ~json_t(void);

    void Reset(void) { len = 0; return; }

    int GetTokenStartPos(const int pos) { return toks[pos].start; }
    int GetTokenEndPos(const int pos) { return toks[pos].end; }
    int GetTokenLen(const int pos) { return toks[pos].end - toks[pos].start; }

    char * GetTokenStart(const int pos) { return ptr + toks[pos].start; }
    char * GetTokenEnd(const int pos) { return ptr + toks[pos].end; }

    int jsoneq(const int pos, const char * str);
};

struct ctx_t
{
    uint8_t b[BUF_SIZE_8];
    uint64_t h[8];
    uint64_t t[2];
    uint32_t c;
};

struct uctx_t
{
    uint64_t h[8];
    uint64_t t[2];
};

#define CTX_SIZE sizeof(ctx_t)

#define B2B_IV(v)                                                              \
do                                                                             \
{                                                                              \
    ((uint64_t *)(v))[0] = 0x6A09E667F3BCC908;                                 \
    ((uint64_t *)(v))[1] = 0xBB67AE8584CAA73B;                                 \
    ((uint64_t *)(v))[2] = 0x3C6EF372FE94F82B;                                 \
    ((uint64_t *)(v))[3] = 0xA54FF53A5F1D36F1;                                 \
    ((uint64_t *)(v))[4] = 0x510E527FADE682D1;                                 \
    ((uint64_t *)(v))[5] = 0x9B05688C2B3E6C1F;                                 \
    ((uint64_t *)(v))[6] = 0x1F83D9ABFB41BD6B;                                 \
    ((uint64_t *)(v))[7] = 0x5BE0CD19137E2179;                                 \
}                                                                              \
while (0)

#define ROTR64(x, y) (((x) >> (y)) ^ ((x) << (64 - (y))))

#define B2B_G(v, a, b, c, d, x, y)                                             \
do                                                                             \
{                                                                              \
    ((uint64_t *)(v))[a] += ((uint64_t *)(v))[b] + x;                          \
    ((uint64_t *)(v))[d]                                                       \
        = ROTR64(((uint64_t *)(v))[d] ^ ((uint64_t *)(v))[a], 32);             \
    ((uint64_t *)(v))[c] += ((uint64_t *)(v))[d];                              \
    ((uint64_t *)(v))[b]                                                       \
        = ROTR64(((uint64_t *)(v))[b] ^ ((uint64_t *)(v))[c], 24);             \
    ((uint64_t *)(v))[a] += ((uint64_t *)(v))[b] + y;                          \
    ((uint64_t *)(v))[d]                                                       \
        = ROTR64(((uint64_t *)(v))[d] ^ ((uint64_t *)(v))[a], 16);             \
    ((uint64_t *)(v))[c] += ((uint64_t *)(v))[d];                              \
    ((uint64_t *)(v))[b]                                                       \
        = ROTR64(((uint64_t *)(v))[b] ^ ((uint64_t *)(v))[c], 63);             \
}                                                                              \
while (0)

#define B2B_MIX(v, m)                                                          \
do                                                                             \
{                                                                              \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 1]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 3]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 5]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 7]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 9]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[10], ((uint64_t *)(m))[11]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[12], ((uint64_t *)(m))[13]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[14], ((uint64_t *)(m))[15]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[14], ((uint64_t *)(m))[10]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 8]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[15]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 6]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[12]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 2]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 7]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 3]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 8]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 0]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 2]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[15], ((uint64_t *)(m))[13]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[10], ((uint64_t *)(m))[14]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[ 6]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 1]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[ 4]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 9]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[ 1]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[13], ((uint64_t *)(m))[12]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[11], ((uint64_t *)(m))[14]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 6]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[10]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 0]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[15], ((uint64_t *)(m))[ 8]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[ 0]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 7]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 4]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[10], ((uint64_t *)(m))[15]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[14], ((uint64_t *)(m))[ 1]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[11], ((uint64_t *)(m))[12]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 8]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[13]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[12]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[10]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[11]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 3]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[13]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 5]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[15], ((uint64_t *)(m))[14]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[ 9]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 5]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[15]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[14], ((uint64_t *)(m))[13]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[10]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 7]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 3]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[ 2]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[11]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[13], ((uint64_t *)(m))[11]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[14]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 1]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[ 9]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 0]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[15], ((uint64_t *)(m))[ 4]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 6]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[10]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[15]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[14], ((uint64_t *)(m))[ 9]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 3]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 8]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[12], ((uint64_t *)(m))[ 2]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 7]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[ 4]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[10], ((uint64_t *)(m))[ 5]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[10], ((uint64_t *)(m))[ 2]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 4]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 7], ((uint64_t *)(m))[ 6]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[ 5]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[15], ((uint64_t *)(m))[11]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[14]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[ 3], ((uint64_t *)(m))[12]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 0]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 1]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 2], ((uint64_t *)(m))[ 3]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 5]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[ 6], ((uint64_t *)(m))[ 7]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 8], ((uint64_t *)(m))[ 9]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[10], ((uint64_t *)(m))[11]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[12], ((uint64_t *)(m))[13]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[14], ((uint64_t *)(m))[15]);      \
                                                                               \
    B2B_G(v, 0, 4,  8, 12, ((uint64_t *)(m))[14], ((uint64_t *)(m))[10]);      \
    B2B_G(v, 1, 5,  9, 13, ((uint64_t *)(m))[ 4], ((uint64_t *)(m))[ 8]);      \
    B2B_G(v, 2, 6, 10, 14, ((uint64_t *)(m))[ 9], ((uint64_t *)(m))[15]);      \
    B2B_G(v, 3, 7, 11, 15, ((uint64_t *)(m))[13], ((uint64_t *)(m))[ 6]);      \
    B2B_G(v, 0, 5, 10, 15, ((uint64_t *)(m))[ 1], ((uint64_t *)(m))[12]);      \
    B2B_G(v, 1, 6, 11, 12, ((uint64_t *)(m))[ 0], ((uint64_t *)(m))[ 2]);      \
    B2B_G(v, 2, 7,  8, 13, ((uint64_t *)(m))[11], ((uint64_t *)(m))[ 7]);      \
    B2B_G(v, 3, 4,  9, 14, ((uint64_t *)(m))[ 5], ((uint64_t *)(m))[ 3]);      \
}                                                                              \
while (0)

#define B2B_INIT(ctx, aux)                                                     \
do                                                                             \
{                                                                              \
    ((uint64_t *)(aux))[0] = ((ctx_t *)(ctx))->h[0];                           \
    ((uint64_t *)(aux))[1] = ((ctx_t *)(ctx))->h[1];                           \
    ((uint64_t *)(aux))[2] = ((ctx_t *)(ctx))->h[2];                           \
    ((uint64_t *)(aux))[3] = ((ctx_t *)(ctx))->h[3];                           \
    ((uint64_t *)(aux))[4] = ((ctx_t *)(ctx))->h[4];                           \
    ((uint64_t *)(aux))[5] = ((ctx_t *)(ctx))->h[5];                           \
    ((uint64_t *)(aux))[6] = ((ctx_t *)(ctx))->h[6];                           \
    ((uint64_t *)(aux))[7] = ((ctx_t *)(ctx))->h[7];                           \
                                                                               \
    B2B_IV(aux + 8);                                                           \
                                                                               \
    ((uint64_t *)(aux))[12] ^= ((ctx_t *)(ctx))->t[0];                         \
    ((uint64_t *)(aux))[13] ^= ((ctx_t *)(ctx))->t[1];                         \
}                                                                              \
while (0)

#define CAST(x) (((union { __typeof__(x) a; uint64_t b; })x).b)

/*
/// // 2b mixing
/// #define B2B_FINAL(ctx, aux)                                                    \
/// do                                                                             \
/// {                                                                              \
///     ((uint64_t *)(aux))[16] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 0];         \
///     ((uint64_t *)(aux))[17] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 1];         \
///     ((uint64_t *)(aux))[18] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 2];         \
///     ((uint64_t *)(aux))[19] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 3];         \
///     ((uint64_t *)(aux))[20] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 4];         \
///     ((uint64_t *)(aux))[21] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 5];         \
///     ((uint64_t *)(aux))[22] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 6];         \
///     ((uint64_t *)(aux))[23] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 7];         \
///     ((uint64_t *)(aux))[24] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 8];         \
///     ((uint64_t *)(aux))[25] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 9];         \
///     ((uint64_t *)(aux))[26] = ((uint64_t *)(((ctx_t *)(ctx))->b))[10];         \
///     ((uint64_t *)(aux))[27] = ((uint64_t *)(((ctx_t *)(ctx))->b))[11];         \
///     ((uint64_t *)(aux))[28] = ((uint64_t *)(((ctx_t *)(ctx))->b))[12];         \
///     ((uint64_t *)(aux))[29] = ((uint64_t *)(((ctx_t *)(ctx))->b))[13];         \
///     ((uint64_t *)(aux))[30] = ((uint64_t *)(((ctx_t *)(ctx))->b))[14];         \
///     ((uint64_t *)(aux))[31] = ((uint64_t *)(((ctx_t *)(ctx))->b))[15];         \
///                                                                                \
///     B2B_MIX(aux, aux + 16);                                                    \
///                                                                                \
///     ((ctx_t *)(ctx))->h[0] ^= ((uint64_t *)(aux))[0] ^ ((uint64_t *)(aux))[ 8];\
///     ((ctx_t *)(ctx))->h[1] ^= ((uint64_t *)(aux))[1] ^ ((uint64_t *)(aux))[ 9];\
///     ((ctx_t *)(ctx))->h[2] ^= ((uint64_t *)(aux))[2] ^ ((uint64_t *)(aux))[10];\
///     ((ctx_t *)(ctx))->h[3] ^= ((uint64_t *)(aux))[3] ^ ((uint64_t *)(aux))[11];\
///     ((ctx_t *)(ctx))->h[4] ^= ((uint64_t *)(aux))[4] ^ ((uint64_t *)(aux))[12];\
///     ((ctx_t *)(ctx))->h[5] ^= ((uint64_t *)(aux))[5] ^ ((uint64_t *)(aux))[13];\
///     ((ctx_t *)(ctx))->h[6] ^= ((uint64_t *)(aux))[6] ^ ((uint64_t *)(aux))[14];\
///     ((ctx_t *)(ctx))->h[7] ^= ((uint64_t *)(aux))[7] ^ ((uint64_t *)(aux))[15];\
/// }                                                                              \
/// while (0)
*/

// 2b mixing
#define B2B_FINAL(ctx, aux)                                                    \
do                                                                             \
{                                                                              \
    ((uint64_t *)(aux))[16] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 0];         \
    ((uint64_t *)(aux))[17] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 1];         \
    ((uint64_t *)(aux))[18] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 2];         \
    ((uint64_t *)(aux))[19] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 3];         \
    ((uint64_t *)(aux))[20] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 4];         \
    ((uint64_t *)(aux))[21] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 5];         \
    ((uint64_t *)(aux))[22] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 6];         \
    ((uint64_t *)(aux))[23] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 7];         \
    ((uint64_t *)(aux))[24] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 8];         \
    ((uint64_t *)(aux))[25] = ((uint64_t *)(((ctx_t *)(ctx))->b))[ 9];         \
    ((uint64_t *)(aux))[26] = ((uint64_t *)(((ctx_t *)(ctx))->b))[10];         \
    ((uint64_t *)(aux))[27] = ((uint64_t *)(((ctx_t *)(ctx))->b))[11];         \
    ((uint64_t *)(aux))[28] = ((uint64_t *)(((ctx_t *)(ctx))->b))[12];         \
    ((uint64_t *)(aux))[29] = ((uint64_t *)(((ctx_t *)(ctx))->b))[13];         \
    ((uint64_t *)(aux))[30] = ((uint64_t *)(((ctx_t *)(ctx))->b))[14];         \
    ((uint64_t *)(aux))[31] = ((uint64_t *)(((ctx_t *)(ctx))->b))[15];         \
                                                                               \
    B2B_MIX(aux, aux + 16);                                                    \
                                                                               \
    ((ctx_t *)(ctx))->h[0] ^= ((uint64_t *)(aux))[0] ^ ((uint64_t *)(aux))[ 8];\
    ((ctx_t *)(ctx))->h[1] ^= ((uint64_t *)(aux))[1] ^ ((uint64_t *)(aux))[ 9];\
    ((ctx_t *)(ctx))->h[2] ^= ((uint64_t *)(aux))[2] ^ ((uint64_t *)(aux))[10];\
    ((ctx_t *)(ctx))->h[3] ^= ((uint64_t *)(aux))[3] ^ ((uint64_t *)(aux))[11];\
    ((ctx_t *)(ctx))->h[4] ^= ((uint64_t *)(aux))[4] ^ ((uint64_t *)(aux))[12];\
    ((ctx_t *)(ctx))->h[5] ^= ((uint64_t *)(aux))[5] ^ ((uint64_t *)(aux))[13];\
    ((ctx_t *)(ctx))->h[6] ^= ((uint64_t *)(aux))[6] ^ ((uint64_t *)(aux))[14];\
    ((ctx_t *)(ctx))->h[7] ^= ((uint64_t *)(aux))[7] ^ ((uint64_t *)(aux))[15];\
}                                                                              \
while (0)

#define HOST_B2B_H(ctx, aux)                                                   \
do                                                                             \
{                                                                              \
    ((ctx_t *)(ctx))->t[0] += BUF_SIZE_8;                                      \
    ((ctx_t *)(ctx))->t[1] += 1 - !(((ctx_t *)(ctx))->t[0] < BUF_SIZE_8);      \
                                                                               \
    B2B_INIT(ctx, aux);                                                        \
    B2B_FINAL(ctx, aux);                                                       \
                                                                               \
    ((ctx_t *)(ctx))->c = 0;                                                   \
}                                                                              \
while (0)

#define HOST_B2B_H_LAST(ctx, aux)                                              \
do                                                                             \
{                                                                              \
    ((ctx_t *)(ctx))->t[0] += ((ctx_t *)(ctx))->c;                             \
    ((ctx_t *)(ctx))->t[1]                                                     \
        += 1 - !(((ctx_t *)(ctx))->t[0] < ((ctx_t *)(ctx))->c);                \
                                                                               \
    while (((ctx_t *)(ctx))->c < BUF_SIZE_8)                                   \
    {                                                                          \
        ((ctx_t *)(ctx))->b[((ctx_t *)(ctx))->c++] = 0;                        \
    }                                                                          \
                                                                               \
    B2B_INIT(ctx, aux);                                                        \
                                                                               \
    ((uint64_t *)(aux))[14] = ~((uint64_t *)(aux))[14];                        \
                                                                               \
    B2B_FINAL(ctx, aux);                                                       \
}                                                                              \
while (0)

#define DEVICE_B2B_H(ctx, aux)                                                 \
do                                                                             \
{                                                                              \
    asm volatile (                                                             \
        "add.cc.u32 %0, %0, 128;": "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[0])  \
    );                                                                         \
    asm volatile (                                                             \
        "addc.cc.u32 %0, %0, 0;": "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[1])   \
    );                                                                         \
    asm volatile (                                                             \
        "addc.cc.u32 %0, %0, 0;": "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[2])   \
    );                                                                         \
    asm volatile (                                                             \
        "addc.u32 %0, %0, 0;": "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[3])      \
    );                                                                         \
                                                                               \
    B2B_INIT(ctx, aux);                                                        \
    B2B_FINAL(ctx, aux);                                                       \
                                                                               \
    ((ctx_t *)(ctx))->c = 0;                                                   \
}                                                                              \
while (0)

#define DEVICE_B2B_H_LAST(ctx, aux)                                            \
do                                                                             \
{                                                                              \
    asm volatile (                                                             \
        "add.cc.u32 %0, %0, %1;":                                              \
        "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[0]):                            \
        "r"(((ctx_t *)(ctx))->c)                                               \
    );                                                                         \
    asm volatile (                                                             \
        "addc.cc.u32 %0, %0, 0;":                                              \
        "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[1])                             \
    );                                                                         \
    asm volatile (                                                             \
        "addc.cc.u32 %0, %0, 0;":                                              \
        "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[2])                             \
    );                                                                         \
    asm volatile (                                                             \
        "addc.u32 %0, %0, 0;":                                                 \
        "+r"(((uint32_t *)((ctx_t *)(ctx))->t)[3])                             \
    );                                                                         \
                                                                               \
    while (((ctx_t *)(ctx))->c < BUF_SIZE_8)                                   \
    {                                                                          \
        ((ctx_t *)(ctx))->b[((ctx_t *)(ctx))->c++] = 0;                        \
    }                                                                          \
                                                                               \
    B2B_INIT(ctx, aux);                                                        \
                                                                               \
    ((uint64_t *)(aux))[14] = ~((uint64_t *)(aux))[14];                        \
                                                                               \
    B2B_FINAL(ctx, aux);                                                       \
}                                                                              \
while (0)

#define REVERSE_ENDIAN(p)                                                      \
    ((((uint64_t)((uint8_t *)(p))[0]) << 56) ^                                 \
    (((uint64_t)((uint8_t *)(p))[1]) << 48) ^                                  \
    (((uint64_t)((uint8_t *)(p))[2]) << 40) ^                                  \
    (((uint64_t)((uint8_t *)(p))[3]) << 32) ^                                  \
    (((uint64_t)((uint8_t *)(p))[4]) << 24) ^                                  \
    (((uint64_t)((uint8_t *)(p))[5]) << 16) ^                                  \
    (((uint64_t)((uint8_t *)(p))[6]) << 8) ^                                   \
    ((uint64_t)((uint8_t *)(p))[7]))

#define INPLACE_REVERSE_ENDIAN(p)                                              \
do                                                                             \
{                                                                              \
    *((uint64_t *)(p))                                                         \
    = ((((uint64_t)((uint8_t *)(p))[0]) << 56) ^                               \
    (((uint64_t)((uint8_t *)(p))[1]) << 48) ^                                  \
    (((uint64_t)((uint8_t *)(p))[2]) << 40) ^                                  \
    (((uint64_t)((uint8_t *)(p))[3]) << 32) ^                                  \
    (((uint64_t)((uint8_t *)(p))[4]) << 24) ^                                  \
    (((uint64_t)((uint8_t *)(p))[5]) << 16) ^                                  \
    (((uint64_t)((uint8_t *)(p))[6]) << 8) ^                                   \
    ((uint64_t)((uint8_t *)(p))[7]));                                          \
}                                                                              \
while (0)

#define FREE(x)                                                                \
do                                                                             \
{                                                                              \
    if (x)                                                                     \
    {                                                                          \
        free(x);                                                               \
        (x) = NULL;                                                            \
    }                                                                          \
}                                                                              \
while (0)

#define CUDA_CALL(x)                                                           \
do                                                                             \
{                                                                              \
    if ((x) != cudaSuccess)                                                    \
    {                                                                          \
        exit(EXIT_FAILURE);                                                    \
    }                                                                          \
}                                                                              \
while (0)

#define CALL(func, name)                                                       \
do                                                                             \
{                                                                              \
    if (!(func))                                                               \
    {                                                                          \
        exit(EXIT_FAILURE);                                                    \
    }                                                                          \
}                                                                              \
while (0)

#define FUNCTION_CALL(res, func, name)                                         \
do                                                                             \
{                                                                              \
    if (!((res) = (func)))                                                     \
    {                                                                          \
        exit(EXIT_FAILURE);                                                    \
    }                                                                          \
}                                                                              \
while (0)

#define CALL_STATUS(func, name, status)                                        \
do                                                                             \
{                                                                              \
    if ((func) != (status))                                                    \
    {                                                                          \
        exit(EXIT_FAILURE);                                                    \
    }                                                                          \
}                                                                              \
while (0)

#define FUNCTION_CALL_STATUS(res, func, name, status)                          \
do                                                                             \
{                                                                              \
    if ((res = func) != (status))                                              \
    {                                                                          \
        exit(EXIT_FAILURE);                                                    \
    }                                                                          \
}                                                                              \
while (0)

#define PERSISTENT_CALL(func)                                                  \
do {} while (!(func))

#define PERSISTENT_FUNCTION_CALL(res, func)                                    \
do {} while (!((res) = (func)))

#define PERSISTENT_CALL_STATUS(func, status)                                   \
do {} while ((func) != (status))

#define PERSISTENT_FUNCTION_CALL_STATUS(func, status)                          \
do {} while (((res) = (func)) != (status))

#endif // DEFINITIONS_H
