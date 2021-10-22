// processing.cc

#include "../include/easylogging++.h"
#include "../include/conversion.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/jsmn.h"
#include <ctype.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fstream>
#include <string>

int ReadConfig(
    const char *fileName,
    char *from,
    char *to,
    char *endJob)
{
    std::ifstream file(
        fileName, std::ios::in | std::ios::binary | std::ios::ate);

    if (!file.is_open())
    {
        return EXIT_FAILURE;
    }

    file.seekg(0, std::ios::end);
    long int len = file.tellg();
    json_t config(len + 1, CONF_LEN);

    file.seekg(0, std::ios::beg);
    file.read(config.ptr, len);
    file.close();

    config.ptr[len] = '\0';

    jsmn_parser parser;
    jsmn_init(&parser);

    int numtoks = jsmn_parse(
        &parser, config.ptr, strlen(config.ptr), config.toks, CONF_LEN);

    if (numtoks < 0)
    {
        return EXIT_FAILURE;
    }

    uint8_t readNode = 0;

    for (int t = 1; t < numtoks; t += 2)
    {
        if (config.jsoneq(t, "node"))
        {
            from[0] = '\0';
            to[0] = '\0';
            endJob[0] = '\0';
            strncat(
                from, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1));

            strcat(from, "/mini/candidate");

            strncat(to, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1));
            strcat(to, "/mini/solution");

            strncat(endJob, config.GetTokenStart(t + 1), config.GetTokenLen(t + 1));
            strcat(endJob, "/mini/job/completed");

            readNode = 1;
        }
        else
        {
        }
    }

    if (readNode)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        return EXIT_FAILURE;
    }
}

int PrintPublicKey(const char *pkstr, char *str)
{
    sprintf(
        str, "   pkHex = %.2s%.16s%.16s%.16s%.16s",
        pkstr, pkstr + 2, pkstr + 18, pkstr + 34, pkstr + 50);

    return EXIT_SUCCESS;
}

int PrintPublicKey(const uint8_t *pk, char *str)
{
    sprintf(
        str, "   pkHex = 0x%02X%016lX%016lX%016lX%016lX",
        pk[0],
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(pk + 1) + 3));

    return EXIT_SUCCESS;
}

int PrintPuzzleSolution(
    const uint8_t *nonce,
    const uint8_t *sol,
    char *str)
{
    sprintf(
        str, "   nonce = 0x%016lX\n"
             "       d = 0x%016lX %016lX %016lX %016lX",
        *((uint64_t *)nonce),
        ((uint64_t *)sol)[3], ((uint64_t *)sol)[2],
        ((uint64_t *)sol)[1], ((uint64_t *)sol)[0]);

    return EXIT_SUCCESS;
}

// processing.cc
