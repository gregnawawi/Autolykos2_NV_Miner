    
#ifndef PROCESSING_H
#define PROCESSING_H

#include "definitions.h"

int ReadConfig(
    const char * fileName,
    char * from,
    char * to,
    char * endJob
);

int PrintPublicKey(const char * pkstr, char * str);

int PrintPublicKey(const uint8_t * pk, char * str);

int PrintPuzzleSolution(
    const uint8_t * nonce,
    const uint8_t * sol,
    char * str
);

#endif // PROCESSING_H
