#ifndef REDUCTION_H
#define REDUCTION_H

#include "definitions.h"

uint32_t CeilToPower(uint32_t x);

template<uint32_t blockSize>
__global__ void BlockNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
);

template<uint32_t blockSize>
__global__ void BlockSum(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out
);

void ReduceNonZero(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
);

void ReduceSum(
    uint32_t * in,
    uint32_t inlen,
    uint32_t * out,
    uint32_t gridSize,
    uint32_t blockSize
);

uint32_t FindNonZero(
    uint32_t * data,
    uint32_t * aux,
    uint32_t inlen
);

uint32_t FindSum(
    uint32_t * data,
    uint32_t * aux,
    uint32_t inlen
);

#endif // REDUCTION_H
