#ifndef REQUEST_H
#define REQUEST_H

#include "definitions.h"
#include "jsmn.h"
#include <curl/curl.h>
#include <atomic>
#include <mutex>

size_t WriteFunc(
    void * ptr,
    size_t size,
    size_t nmemb,
    json_t * request
);

int ToUppercase(char * str);

void CurlLogError(CURLcode curl_status);

int ParseRequest(
    json_t * oldreq ,
    json_t * newreq, 
    info_t *info, 
    int checkPubKey,
	long http_code
);

int ParseRequestWithPBound(
    json_t * oldreq, 
    json_t * newreq, 
    info_t *info, 
    int checkPubKey
);

int GetLatestBlock(
    const char * from,
    json_t * oldreq,
    info_t * info,
    int checkPubKey
);

int JobCompleted(
	const char * to
	);

int PostPuzzleSolution(
    const char * to,
    const uint8_t * nonce
);

#endif // REQUEST_H
