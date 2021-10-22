#ifndef PREHASH_H
#define PREHASH_H

#include "definitions.h"

__global__ void InitPrehash(
    const uint32_t height,
    uint32_t *hashes);

int Prehash(
    uint32_t *hashes,
    uint32_t height);

#endif // PREHASH_H
