/*
by Luigi Auriemma
*/



// Compress uses the enum value while Decompress uses the raw value stored in the header of the compressed file
// the algorithm number is NOT the same of the enum, that's why we need this
typedef struct {
    char    *name;
    int     algo_compress;
    int     algo_raw;       // 0x8c followed by this byte
} Oodle_algorithms_raw_t;

Oodle_algorithms_raw_t    Oodle_algorithms_raw[] = {
    { "LZH",            0,  7 },
    { "LZHLW",          1,  0 },
    { "LZNIB",          2,  1 },
    { "None",           3,  7 },    // 0x8c->0xcc
    { "LZB16",          4,  2 },
    { "LZBLW",          5,  3 },
    { "LZA",            6,  4 },
    { "LZNA",           7,  5 },
    { "Kraken",         8,  6 },
    { "Mermaid",        9, 10 },
    { "BitKnit",       10, 11 },
    { "Selkie",        11, 10 },
    { "Akkorokamui",   12,  6 },
    //
    { "LZQ1",           8,  6 },    // old name of Kraken
    { "LZNIB2",         9, 10 },    // old name of Mermaid
    //
    { NULL, -1, -1 }
};



#ifdef WIN32
#include <stdio.h>
#include <stdlib.h>
#include "oodle_dll.h"

int __stdcall (*OodleLZ_Compress)(int algo, unsigned char *in, int insz, unsigned char *out, int max, void *a, void *b, void *c) = NULL;
int __stdcall (*OodleLZ_Decompress)(unsigned char *in, int insz, unsigned char *out, int outsz, int a, int b, int c, void *d, void *e, void *f, void *g, void *h, void *i, int j) = NULL;   // Oodle 2.3.0
void* __stdcall (*OodlePlugins_SetAssertion)(void *func) = NULL;
int __stdcall oodle_noassert(const char * a,const int b,const char * c,const char * d) { return 0; }
#endif



int oodle_get_algo(char *name, int raw) {
    int     i;
    if(name) {
        for(i = 0; Oodle_algorithms_raw[i].name; i++) {
            if(!stricmp(name, Oodle_algorithms_raw[i].name)) {
                if(raw) return Oodle_algorithms_raw[i].algo_raw;
                else    return Oodle_algorithms_raw[i].algo_compress;
            }
        }
    }
    return -1;
}



int oodle_init(void) {
#ifdef WIN32
    static HMODULE hlib = NULL;
    if(!hlib) {
        hlib = (void *)MemoryLoadLibrary((void *)oodle_dll, sizeof(oodle_dll));
        if(hlib) {
            if(!OodleLZ_Compress)   OodleLZ_Compress   = (void *)MemoryGetProcAddress(hlib, "OodleLZ_Compress");
            if(!OodleLZ_Compress)   OodleLZ_Compress   = (void *)MemoryGetProcAddress(hlib, "_OodleLZ_Compress@32");
            if(!OodleLZ_Decompress) OodleLZ_Decompress = (void *)MemoryGetProcAddress(hlib, "OodleLZ_Decompress");
            if(!OodleLZ_Decompress) OodleLZ_Decompress = (void *)MemoryGetProcAddress(hlib, "_OodleLZ_Decompress@56");
        }
        if(!hlib || !OodleLZ_Compress || !OodleLZ_Decompress) {
            fprintf(stderr, "\nError: unable to load the Oodle DLL and functions\n");
            myexit(QUICKBMS_ERROR_DLL);
        }

        // better to leave the asserts enabled for debug information
        //if(!OodlePlugins_SetAssertion) OodlePlugins_SetAssertion = (void *)MemoryGetProcAddress(hlib, "OodlePlugins_SetAssertion");
        //if(!OodlePlugins_SetAssertion) OodlePlugins_SetAssertion = (void *)MemoryGetProcAddress(hlib, "_OodlePlugins_SetAssertion@4");
        //if(OodlePlugins_SetAssertion) OodlePlugins_SetAssertion(oodle_noassert);
    }
    return 0;
#else
    return -1;
#endif
}



int oodle_compress(unsigned char *in, int insz, unsigned char *out) {
#ifdef WIN32
    // algo is not supported, intentionally! Only public information are used here
    if(!OodleLZ_Compress) return -1;
    return OodleLZ_Compress(
        oodle_get_algo("bitknit", 0),
        in, insz,
        out,
        7,  // Max
        NULL, NULL, NULL);
#else
    return -1;
#endif
}



int oodle_decompress(unsigned char *in, int insz, unsigned char *out, int outsz, char *algo_name) {
#ifdef WIN32
    unsigned char   *p = NULL;

    int     algo = oodle_get_algo(algo_name, 1);

    if(!OodleLZ_Decompress) return -1;
    if(algo >= 0) {
        p = malloc(2 + insz);
        memcpy(p + 2, in, insz);
        p[0] = 0x8c;
        p[1] = algo;
        insz += 2;
    }
    outsz = OodleLZ_Decompress(in, insz, out, outsz, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, 3);
    FREE(p);    // automatically check "if(p)"
    return outsz;
#else
    return -1;
#endif
}


