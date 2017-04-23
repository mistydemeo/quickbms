#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "../libs/ppmz2/Coder.h"
#include "../libs/ppmz2/LocalOrderEstimation.h"



using namespace Ppmz2;



extern "C"
int ppmz2_encode(unsigned char *rawBuf, int rawLen, unsigned char *out, int outsz, unsigned char *conditionBuf, int conditionLen) {
    int             compLen = -1;
    unsigned char   *compBuf = NULL;

    Coder coder(NULL);
    if ( conditionBuf )
        compLen = coder.Encode(rawBuf, rawLen, &compBuf, conditionBuf, conditionLen, CodingOptions__Default);
    else
        compLen = coder.Encode(rawBuf, rawLen, &compBuf, CodingOptions__Default);

    if((compLen < 0) || !compBuf) return -1;
    if(compLen > outsz) {
        compLen = -1;
        goto quit;
    }
    memcpy(out, compBuf, compLen);
quit:
    delete compBuf;
    return compLen;
}



extern "C"
int ppmz2_decode(unsigned char *compBuf, int compLen, unsigned char *out, int outsz, unsigned char *conditionBuf, int conditionLen) {
    int             ok = 0;
    int             rawLen = outsz;
    unsigned char   *decBuf = NULL;

    if(!memcmp(compBuf, "ppz2", 4)) {
        compBuf += 12;
        compLen -= 12;
    }
    Coder coder(NULL);
    if ( conditionBuf )
        ok = coder.Decode(&decBuf, rawLen, compBuf, conditionBuf, conditionLen, CodingOptions__Default);
    else
        ok = coder.Decode(&decBuf, rawLen, compBuf, CodingOptions__Default);

    if(!ok) return -1;
    if((rawLen < 0) || !decBuf) return -1;
    if(rawLen > outsz) {
        rawLen = -1;
        goto quit;
    }
    memcpy(out, decBuf, rawLen);
quit:
    delete decBuf;
    return rawLen;
}

