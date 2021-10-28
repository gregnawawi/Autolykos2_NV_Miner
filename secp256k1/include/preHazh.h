#ifndef PREHAZH_H
#define PREHAZH_H

#include "definitions.h"

__global__ void InitPrehazh(
    const uint32_t height,
    uint32_t *hashes);

int Prehazh(
    uint32_t *hashes,
    uint32_t height);

#endif // PREHAZH_H
