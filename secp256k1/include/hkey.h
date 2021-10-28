#ifndef HKEY_H
#define HKEY_H

#include "definitions.h"

__constant__ uint32_t bound_[8];

void cpyCtxSymbol(ctx_t *ctx);
void cpyBSymbol(uint8_t *bound);

void InitHkey(
	ctx_t *ctx,
	const uint32_t *mes,
	const uint32_t meslen);

__global__ void BlockHkeyStep1(
	const uint32_t *data,
	const uint64_t base,
	const uint32_t *hashes,
	uint32_t *BHashes
);
__global__ void BlockHkeyStep2(
	const uint32_t *data,
	const uint64_t base,
	const uint32_t height,
	const uint32_t *hashes,
	uint32_t *valid,
	uint32_t *count,
	uint32_t *BHashes);
#endif // HKEY_H
