/*
    Copyright 2009-2017 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

// custom encryption algorithms



//#include "encryption/leverage_ssc.c"
void ssc_decrypt(unsigned char *key, int keylen, unsigned char *data, int datalen);
void ssc_encrypt(unsigned char *key, int keylen, unsigned char *data, int datalen);
unsigned int ascii_calculate_hash(unsigned char *data, int datalen);
unsigned int ascii_calculate_key_hash(unsigned char *key, int keylen, unsigned char *data, int datalen);
u8 *mystrdup_simple(u8 *str);
u8 *mystrchrs(u8 *str, u8 *chrs);
QUICKBMS_int readbase(u8 *data, QUICKBMS_int size, QUICKBMS_int *readn);
int unhex(u8 *in, int insz, u8 *out, int outsz);
QUICKBMS_int getxx(u8 *tmp, QUICKBMS_int bytes);
QUICKBMS_int putxx(u8 *data, QUICKBMS_u_int num, QUICKBMS_int bytes);
QUICKBMS_int math_operations(QUICKBMS_int cmd, QUICKBMS_int var1i, QUICKBMS_int op, QUICKBMS_int var2i, QUICKBMS_int sign);
QUICKBMS_int set_math_operator(u8 *data, QUICKBMS_int *ret_sign, u8 **ret_next);
QUICKBMS_int calcc(QUICKBMS_int cmd, char *command, u64 input);
QUICKBMS_int getvarnum(u8 *name, QUICKBMS_int namesz);



int ctx_set_size(int num, u8 *str) {
    int     size;
    u8      *p;

    if(num < 0) num = 8;
    size = num;
    if(str && str[0]) {
        p = str;
        while(*p && (*p <= ' ')) p++;
        if(*p > ' ') size = getvarnum(p, -1); //readbase(p, 10, NULL);
    }
    switch(size) {
        case 1:  size = 8;  break;
        case 2:  size = 16; break;
        case 4:  size = 32; break;
        default:            break;
    }
    size /= 8;
    if(size <= 0) size = 0;
    if(size >  8) size = 8;
    return size;
}




// random
typedef struct {
    int     type;
    int     size;
    u64     key;
    u64     multiplier;
    u64     incrementer;
    u64     modulus;
    u32     mt[4096];
    int     mt_size;
    int     idx;
    u64     c;
    u8      op;
    u64     retmask;
} random_context;

QUICKBMS_int get_var_from_name(u8 *name, QUICKBMS_int namelen);
QUICKBMS_int get_var32(QUICKBMS_int idx);

void random_setkey(random_context *ctx, u8 *key, u8 *ivec) {
    int     i,
            var;
    u8      *p,
            *l;

    p = key;
    while(*p && (*p <= ' ')) p++;
    if(strchr("+-^*/%|&", *p)) ctx->op = *p++;
    ctx->type = getvarnum(p, -1); //readbase(p, 10, NULL);
    while(*p && (*p > ' ')) p++;
    while(*p && (*p <= ' ')) p++;

    l = p;
    while(*l && (*l > ' ')) l++;
    ctx->key = getvarnum(p, l - p);
    p = l;
    while(*p && (*p <= ' ')) p++;
    ctx->retmask = getvarnum(p, -1);
    
    ctx->size = ctx_set_size(8, ivec);

    /*
        TODO
        http://www.boost.org/doc/libs/release/libs/random/index.html
        http://www.boost.org/doc/libs/1_39_0/libs/random/index.html
    */

    switch(ctx->type) {
        // http://en.wikipedia.org/wiki/Linear%5Fcongruential%5Fgenerator#Parameters_in_common_use
        case 0: /* Numerical Recipes 	232 */	ctx->multiplier = 1664525; ctx->incrementer = 1013904223; break;
        case 1: /* Borland C/C++ 	232 */	ctx->multiplier = 22695477; ctx->incrementer = 1; break;
        case 2: /* glibc (used by GCC)[5] 	231 */	ctx->multiplier = 1103515245; ctx->incrementer = 12345; break;
        case 3: /* ANSI C: Watcom, Digital Mars, CodeWarrior, IBM VisualAge C/C++ [6] 	231 */	ctx->multiplier = 1103515245; ctx->incrementer = 12345; break;
        case 4: /* Borland Delphi, Virtual Pascal 	232 */	ctx->multiplier = 134775813; ctx->incrementer = 1; break;
        case 5: /* Microsoft Visual/Quick C/C++ 	232 */	ctx->multiplier = 214013; ctx->incrementer = 2531011; break;
        case 6: /* Microsoft Visual Basic (6 and earlier)[7] 	224 */	ctx->multiplier = 1140671485; ctx->incrementer = 12820163; break;
        case 7: /* RtlUniform from Native API[8] 	231 - 1 */	ctx->multiplier = 2147483629; ctx->incrementer = 2147483587; break;
        case 8: /* Apple CarbonLib 	231 - 1 */	ctx->multiplier = 16807; ctx->incrementer = 0; break;
        case 9: /* MMIX by Donald Knuth 	264 */	ctx->multiplier = 6364136223846793005LL; ctx->incrementer = 1442695040888963407LL; break;
        case 10: /* Newlib 	264 */	ctx->multiplier = 6364136223846793005LL; ctx->incrementer = 1; break;
        case 11: /* VAX's MTH$RANDOM,[9] old versions of glibc 	232 */	ctx->multiplier = 69069; ctx->incrementer = 1; break;
        case 12: /* Java's java.util.Random 	248 */	ctx->multiplier = 25214903917LL; ctx->incrementer = 11; break;
        case 13: /* LC53[10] in Forth 	232 - 5 */	ctx->multiplier = /*232*/ - 333333333LL; ctx->incrementer = 0; break;
        case 14: /* RANDU [4] 	231 	 */ ctx->multiplier = 65539; ctx->incrementer = 0; break;
        // http://en.wikipedia.org/wiki/Complementary-multiply-with-carry
        case 15:
            ctx->c = 362436;
            ctx->mt_size = 4096;
            ctx->mt[0] = ctx->key;
            ctx->mt[1] = ctx->key + 0x9e3779b9;
            ctx->mt[2] = ctx->key + 0x9e3779b9 + 0x9e3779b9;
            for (i = 3; i < ctx->mt_size; i++)
                    ctx->mt[i] = ctx->mt[i - 3] ^ ctx->mt[i - 2] ^ 0x9e3779b9 ^ i;
            ctx->idx = ctx->mt_size - 1;
            break;
        case 16: ctx->multiplier = 279470273UL; ctx->modulus = 4294967291UL; break;
        // I tried to implement mersenne but both the two implementations I found didn't work
        default: break;
    }
}

void random_crypt(random_context *ctx, u8 *data, int datalen) {
    u64     n,
            ret_key,
            t,
            x;
    int     i;

    if(ctx->size <= 0) return;
    datalen /= ctx->size;
    for(i = 0; i < datalen; i++) {
        n = getxx(data, ctx->size);

        switch(ctx->type) {
            case 15:
                ctx->idx = (ctx->idx + 1) % ctx->mt_size;
                t = 18782LL * ctx->mt[ctx->idx] + ctx->c;
                ctx->c = (t >> 32);
                x = t + ctx->c;
                if (x < ctx->c) {
                    x++;
                    ctx->c++;
                }
                ctx->key = (ctx->mt[ctx->idx] = 0xfffffffe - x);
                break;

            default:
                ctx->key = (ctx->key * ctx->multiplier) + ctx->incrementer;
                break;
        }

        ret_key = ctx->key;
        if(ctx->retmask) {
            t = ctx->retmask;
            while(!(t & 1)) {
                t       >>= 1;
                ret_key >>= 1;
            }
            ret_key &= t;
        }
        switch(ctx->op) {
            case '+':   n += ret_key;   break;
            case '-':   n -= ret_key;   break;
            case '*':   n *= ret_key;   break;
            case '/':   n /= ret_key;   break;
            case '%':   n %= ret_key;   break;
            case '|':   n |= ret_key;   break;
            case '&':   n &= ret_key;   break;
            case '^':
            default:    n ^= ret_key;   break;
        }
        if(ctx->modulus) n %= ctx->modulus;

        putxx(data, n, ctx->size);
        data += ctx->size;
    }
}



// xmath
typedef struct {
    u8      *op;
    int     size;
    int     exact;
} xmath_context;

void xmath_setkey(xmath_context *ctx, u8 *key, u8 *ivec) {
    ctx->op   = mystrdup_simple(key);
    ctx->size = ctx_set_size(8, ivec);
}

void xmath_crypt(xmath_context *ctx, u8 *data, int datalen) {
    int     i;

    if(ctx->size <= 0) return;
    datalen /= ctx->size;
    for(i = 0; i < datalen; i++) {
        if(ctx->exact) {
            #define xmath_crypt_bytes(X) { \
                putxx(data, calcc(-1, ctx->op, getxx(data, X)), X); \
            }
            switch(ctx->size) {
                case 1: xmath_crypt_bytes(1) break;
                case 2: xmath_crypt_bytes(2) break;
                case 4: xmath_crypt_bytes(4) break;
                case 8: xmath_crypt_bytes(8) break;
                default: break;
            }
        } else {
            xmath_crypt_bytes(ctx->size)
        }
        data += ctx->size;
    }
}



// math
typedef struct {
    int     op;
    int     var2;
    int     var2_is_var1;
    int     sign;
    int     size;
    int     exact;
} math_context;

void math_setkey(math_context *ctx, u8 *key, u8 *ivec) {
    QUICKBMS_int    t;
    u8      *p,
            *s;

    p = key;
    while(*p && (*p <= ' ')) p++;   // spaces
    t = ctx->sign;
    ctx->op = set_math_operator(p, &t, &p);
    ctx->sign = t;
    while(*p && (*p <= ' ')) p++;   // spaces
    ctx->var2 = getvarnum(p, -1); //readbase(p, 10, NULL);
    s = p;
    while(*p && (*p > ' ')) p++;    // var2 to skip
    if(!strnicmp(s, "#INPUT#", p - s)) ctx->var2_is_var1 = 1;
    while(*p && (*p <= ' ')) p++;   // spaces
    if(*p) ctx->exact = getvarnum(p, -1); //readbase(p, 10, NULL);

    ctx->size = ctx_set_size(8, ivec);
}

void math_crypt(math_context *ctx, u8 *data, int datalen) {

    #define math_crypt_bytes(X) { \
        v##X = getxx(data, X); \
        if(ctx->var2_is_var1) ctx->var2 = v##X; \
        v##X = math_operations(-1, v##X, ctx->op, ctx->var2 ? ctx->var2 : v##X, ctx->sign); \
        putxx(data, v##X, X); \
    }

    int     vsz,
            sz,
            i;
    u64     v8;
    u32     v4;
    u16     v2;
    u8      v1;

    sz = ctx->size;
    if(sz <= 0) return;
    datalen /= sz;
    for(i = 0; i < datalen; i++) {
        if(ctx->exact) {
            switch(sz) {
                case 1: math_crypt_bytes(1) break;
                case 2: math_crypt_bytes(2) break;
                case 4: math_crypt_bytes(4) break;
                case 8: math_crypt_bytes(8) break;
                default: break;
            }
        } else {
            math_crypt_bytes(sz)
        }
        data += sz;
    }
}



// swap
typedef struct {
    int     size;
} swap_context;

void swap_setkey(swap_context *ctx, int num, u8 *ivec) {
    ctx->size = ctx_set_size(num, ivec);
}

void swap_crypt(swap_context *ctx, u8 *data, int datalen) {
    int     i,
            j;
    u8      tmp[32],    // 256bit
            *p;

    if(ctx->size <= 1) return;
    if(ctx->size > sizeof(tmp)) ctx->size = sizeof(tmp);
    datalen /= ctx->size;
    for(i = 0; i < datalen; i++) {
        p = tmp + ctx->size;
        for(j = 0; j < ctx->size; j++) {
            p--;
            *p = data[j];
        }
        for(j = 0; j < ctx->size; j++) {
            data[j] = p[j];
        }
        data += ctx->size;
    }
}



// xor
typedef struct {
    u8      *key;
    int     keysz;
    int     keypos;
} xor_context;

int xor_setkey(xor_context *ctx, u8 *key, int keysz) {
    ctx->key    = malloc(keysz);    // "ctx->key = key" was good too
    if(!ctx->key) return -1;
    memcpy(ctx->key, key, keysz);
    ctx->keysz  = keysz;
    ctx->keypos = 0;
    return 0;
}

void xor_crypt(xor_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        if(ctx->keypos >= ctx->keysz) ctx->keypos = 0;
        data[i] ^= ctx->key[ctx->keypos];
        ctx->keypos++;
    }
}



// rot
typedef struct {
    u8      *key;
    int     keysz;
    int     keypos;
} rot_context;

int rot_setkey(rot_context *ctx, u8 *key, int keysz) {
    ctx->key    = malloc(keysz);    // "ctx->key = key" was good too
    if(!ctx->key) return -1;
    memcpy(ctx->key, key, keysz);
    ctx->keysz  = keysz;
    ctx->keypos = 0;
    return 0;
}

void rot_decrypt(rot_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        if(ctx->keypos >= ctx->keysz) ctx->keypos = 0;
        data[i] += ctx->key[ctx->keypos];
        ctx->keypos++;
    }
}

void rot_encrypt(rot_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        if(ctx->keypos >= ctx->keysz) ctx->keypos = 0;
        data[i] -= ctx->key[ctx->keypos];
        ctx->keypos++;
    }
}



// rotate
typedef struct {
    int     num;
    int     size;
} rotate_context;

void rotate_setkey(rotate_context *ctx, u8 *key, u8 *ivec) {
    ctx->num  = getvarnum(key, -1); //readbase(key, 10, NULL);
    ctx->size = ctx_set_size(8, ivec);
}

void rotate_crypt(rotate_context *ctx, u8 *data, int datalen, int decenc) {
    int     i,
            num;
    u64     v8;
    u32     v4;
    u16     v2;
    u8      v1;

    if(ctx->size <= 0) return;

    num = ctx->num;
    if(decenc) num = (ctx->size << 3) - num;

    datalen /= ctx->size;
    for(i = 0; i < datalen; i++) {
        #define rotate_crypt_bytes(X) { \
            v##X = getxx(data, X); \
            v##X = (v##X  >> (num)) | (v##X  << ((X << 3) - num)); \
            putxx(data, v##X, X); \
        }
        switch(ctx->size) {
            case 1: rotate_crypt_bytes(1)   break;
            case 2: rotate_crypt_bytes(2)   break;
            case 4: rotate_crypt_bytes(4)   break;
            case 8: rotate_crypt_bytes(8)   break;
            default: break;
        }
        data += ctx->size;
    }
}



// revert
typedef struct {
    int     bytes;
} reverse_context;

void reverse_setkey(reverse_context *ctx, u8 *key) {
    ctx->bytes = 1;
    if(key && key[0]) {
        ctx->bytes = getvarnum(key, -1);
    }
    if(ctx->bytes <= 0) ctx->bytes = 1;
}

void reverse_crypt(reverse_context *ctx, u8 *data, int datalen) {
    int     i;
    u8      c,
            *p,
            *l;

    p = data;
    l = data + datalen - ctx->bytes;
    while(p < l) {
        for(i = 0; i < ctx->bytes; i++) {
            c  = *p;
            *p = *l;
            *l = c;
            p++;
            l--;
        }
    }
}



// incremental xor/rot
typedef struct {
    int     xor_rot;
    u32     byte;
    int     bytesz;
    int     inc;
} inc_context;

void inc_setkey(inc_context *ctx, int xor_rot, u32 byte, int inc) {
    ctx->xor_rot    = xor_rot;
    ctx->byte       = byte;
    if(byte > 0xffff) {
        ctx->bytesz = 4;
    } else if(byte > 0xff) {
        ctx->bytesz = 2;
    } else {
        ctx->bytesz = 1;
    }
    if(!inc) inc = 1;   // inc can be both positive and negative
    ctx->inc        = inc;
}

void inc_crypt(inc_context *ctx, u8 *data, int datalen, int decenc) {
    u32     var1;
    int     i;

    datalen /= ctx->bytesz;
    for(i = 0; i < datalen; i++) {
        var1 = getxx(data, ctx->bytesz);
        if(!ctx->xor_rot) { // XOR
            var1 ^= ctx->byte;
        } else {            // ROT
            if(!decenc) {
                var1 += ctx->byte;
            } else {
                var1 -= ctx->byte;
            }
        }
        putxx(data, var1, ctx->bytesz);
        ctx->byte += ctx->inc;
        data += ctx->bytesz;
    }
}



// charset

static const u8 ebcdic_charset[256] =
"\x00\x01\x02\x03\x1a\x09\x1a\x7f\x1a\x1a\x1a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x1a\x0a\x08\x1a\x18\x19\x1a\x1a\x1c\x1d\x1e\x1f"
"\x1a\x1a\x1c\x1a\x1a\x0a\x17\x1b\x1a\x1a\x1a\x1a\x1a\x05\x06\x07"
"\x1a\x1a\x16\x1a\x1a\x1e\x1a\x04\x1a\x1a\x1a\x1a\x14\x15\x1a\x1a"
"\x20\xa6\xe1\x80\xeb\x90\x9f\xe2\xab\x8b\x9b\x2e\x3c\x28\x2b\x7c"
"\x26\xa9\xaa\x9c\xdb\xa5\x99\xe3\xa8\x9e\x21\x24\x2a\x29\x3b\x5e"
"\x2d\x2f\xdf\xdc\x9a\xdd\xde\x98\x9d\xac\xba\x2c\x25\x5f\x3e\x3f"
"\xd7\x88\x94\xb0\xb1\xb2\xfc\xd6\xfb\x60\x3a\x23\x40\x27\x3d\x22"
"\xf8\x61\x62\x63\x64\x65\x66\x67\x68\x69\x96\xa4\xf3\xaf\xae\xc5"
"\x8c\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x97\x87\xce\x93\xf1\xfe"
"\xc8\x7e\x73\x74\x75\x76\x77\x78\x79\x7a\xef\xc0\xda\x5b\xf2\xf9"
"\xb5\xb6\xfd\xb7\xb8\xb9\xe6\xbb\xbc\xbd\x8d\xd9\xbf\x5d\xd8\xc4"
"\x7b\x41\x42\x43\x44\x45\x46\x47\x48\x49\xcb\xca\xbe\xe8\xec\xed"
"\x7d\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\xa1\xad\xf5\xf4\xa3\x8f"
"\x5c\xe7\x53\x54\x55\x56\x57\x58\x59\x5a\xa0\x85\x8e\xe9\xe4\xd1"
"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\xb3\xf7\xf0\xfa\xa7\xff";

typedef struct {
    u8      key[256];
} charset_context;

void charset_setkey(charset_context *ctx, u8 *key, int keysz) {
    memset(ctx->key, 0, 256);
    if(keysz <= 0) return;
    if(keysz > 256) keysz = 256;
    memcpy(ctx->key, key, keysz);
}

void charset_decrypt(charset_context *ctx, u8 *data, int datalen) {
    int     i;

    for(i = 0; i < datalen; i++) {
        data[i] = ctx->key[data[i]];
    }
}

void charset_encrypt(charset_context *ctx, u8 *data, int datalen) {
    int     i,
            j,
            c;

    for(i = 0; i < datalen; i++) {
        c = data[i];
        for(j = 0; j < 256; j++) {
            if(ctx->key[j] == c) {
                c = j;
                break;
            }
        }
        data[i] = c;
    }
}



// ssc
typedef struct {
    u8      *key;
    int     keysz;
} ssc_context;

int ssc_setkey(ssc_context *ctx, u8 *key, int keysz) {
    ctx->key    = malloc(keysz);    // "ctx->key = key" was good too
    if(!ctx->key) return -1;
    memcpy(ctx->key, key, keysz);
    ctx->keysz  = keysz;
    return 0;
}



// wincrypt
#ifdef WIN32
#include <wincrypt.h>

typedef struct {
    DWORD   num;
    char    *str;
} wincrypt_types;
wincrypt_types wincrypt_mspn1[] = { // blah
    { (DWORD)MS_DEF_DH_SCHANNEL_PROV,  "MS_DEF_DH_SCHANNEL_PROV" },
    { (DWORD)MS_DEF_DSS_DH_PROV,       "MS_DEF_DSS_DH_PROV" },
    { (DWORD)MS_DEF_DSS_PROV,          "MS_DEF_DSS_PROV" },
    { (DWORD)MS_DEF_PROV,              "MS_DEF_PROV" },
    { (DWORD)MS_DEF_RSA_SCHANNEL_PROV, "MS_DEF_RSA_SCHANNEL_PROV" },
    { (DWORD)MS_DEF_RSA_SIG_PROV,      "MS_DEF_RSA_SIG_PROV" },
    { (DWORD)MS_ENH_DSS_DH_PROV,       "MS_ENH_DSS_DH_PROV" },
#ifdef MS_ENH_RSA_AES_PROV
    { (DWORD)MS_ENH_RSA_AES_PROV,      "MS_ENH_RSA_AES_PROV" },
#endif
    { (DWORD)MS_ENHANCED_PROV,         "MS_ENHANCED_PROV" },
    { (DWORD)MS_SCARD_PROV,            "MS_SCARD_PROV" },
    { (DWORD)MS_STRONG_PROV,           "MS_STRONG_PROV" },
    { (DWORD)NULL,                     NULL }
};
wincrypt_types wincrypt_mspn2[] = { // blah
    { (DWORD)MS_DEF_DH_SCHANNEL_PROV,  MS_DEF_DH_SCHANNEL_PROV },
    { (DWORD)MS_DEF_DSS_DH_PROV,       MS_DEF_DSS_DH_PROV },
    { (DWORD)MS_DEF_DSS_PROV,          MS_DEF_DSS_PROV },
    { (DWORD)MS_DEF_PROV,              MS_DEF_PROV },
    { (DWORD)MS_DEF_RSA_SCHANNEL_PROV, MS_DEF_RSA_SCHANNEL_PROV },
    { (DWORD)MS_DEF_RSA_SIG_PROV,      MS_DEF_RSA_SIG_PROV },
    { (DWORD)MS_ENH_DSS_DH_PROV,       MS_ENH_DSS_DH_PROV },
#ifdef MS_ENH_RSA_AES_PROV
    { (DWORD)MS_ENH_RSA_AES_PROV,      MS_ENH_RSA_AES_PROV },
#endif
    { (DWORD)MS_ENHANCED_PROV,         MS_ENHANCED_PROV },
    { (DWORD)MS_SCARD_PROV,            MS_SCARD_PROV },
    { (DWORD)MS_STRONG_PROV,           MS_STRONG_PROV },
    { (DWORD)NULL,                     NULL }
};
wincrypt_types wincrypt_prov[] = {
    { 1,  "PROV_RSA_FULL" },
    { 2,  "PROV_RSA_SIG" },
    { 3,  "PROV_DSS" },
    { 4,  "PROV_FORTEZZA" },
    { 5,  "PROV_MS_EXCHANGE" },
    { 5,  "PROV_MS_MAIL" },
    { 6,  "PROV_SSL" },
    { 7,  "PROV_STT_MER" },
    { 8,  "PROV_STT_ACQ" },
    { 9,  "PROV_STT_BRND" },
    { 10, "PROV_STT_ROOT" },
    { 11, "PROV_STT_ISS" },
    { 12, "PROV_RSA_SCHANNEL" },
    { 13, "PROV_DSS_DH" },
    { 14, "PROV_EC_ECDSA_SIG" },
    { 15, "PROV_EC_ECNRA_SIG" },
    { 16, "PROV_EC_ECDSA_FULL" },
    { 17, "PROV_EC_ECNRA_FULL" },
    { 18, "PROV_DH_SCHANNEL" },
    { 20, "PROV_SPYRUS_LYNKS" },
    { 21, "PROV_RNG" },
    { 22, "PROV_INTEL_SEC" },
    { 24, "PROV_RSA_AES" },
    { 0,  NULL }
};
wincrypt_types wincrypt_calg[] = {
    { 0x00006603, "CALG_3DES" },
    { 0x00006609, "CALG_3DES_112" },
    { 0x00006611, "CALG_AES" },
    { 0x00006611, "CALG_AES" },
    { 0x0000660e, "CALG_AES_128" },
    { 0x0000660e, "CALG_AES_128" },
    { 0x0000660f, "CALG_AES_192" },
    { 0x0000660f, "CALG_AES_192" },
    { 0x00006610, "CALG_AES_256" },
    { 0x00006610, "CALG_AES_256" },
    { 0x0000aa03, "CALG_AGREEDKEY_ANY" },
    { 0x0000660c, "CALG_CYLINK_MEK" },
    { 0x00006601, "CALG_DES" },
    { 0x00006604, "CALG_DESX" },
    { 0x0000aa02, "CALG_DH_EPHEM" },
    { 0x0000aa01, "CALG_DH_SF" },
    { 0x00002200, "CALG_DSS_SIGN" },
    { 0x0000aa05, "CALG_ECDH" },
    { 0x0000aa05, "CALG_ECDH" },
    { 0x00002203, "CALG_ECDSA" },
    { 0x00002203, "CALG_ECDSA" },
    { 0x0000a001, "CALG_ECMQV" },
    { 0x0000800b, "CALG_HASH_REPLACE_OWF" },
    { 0x0000800b, "CALG_HASH_REPLACE_OWF" },
    { 0x0000a003, "CALG_HUGHES_MD5" },
    { 0x00008009, "CALG_HMAC" },
    { 0x0000aa04, "CALG_KEA_KEYX" },
    { 0x00008005, "CALG_MAC" },
    { 0x00008001, "CALG_MD2" },
    { 0x00008002, "CALG_MD4" },
    { 0x00008003, "CALG_MD5" },
    { 0x00002000, "CALG_NO_SIGN" },
    { 0xffffffff, "CALG_OID_INFO_CNG_ONLY" },
    { 0xfffffffe, "CALG_OID_INFO_PARAMETERS" },
    { 0x00004c04, "CALG_PCT1_MASTER" },
    { 0x00006602, "CALG_RC2" },
    { 0x00006801, "CALG_RC4" },
    { 0x0000660d, "CALG_RC5" },
    { 0x0000a400, "CALG_RSA_KEYX" },
    { 0x00002400, "CALG_RSA_SIGN" },
    { 0x00004c07, "CALG_SCHANNEL_ENC_KEY" },
    { 0x00004c03, "CALG_SCHANNEL_MAC_KEY" },
    { 0x00004c02, "CALG_SCHANNEL_MASTER_HASH" },
    { 0x00006802, "CALG_SEAL" },
    { 0x00008004, "CALG_SHA" },
    { 0x00008004, "CALG_SHA1" },
    { 0x0000800c, "CALG_SHA_256" },
    { 0x0000800c, "CALG_SHA_256" },
    { 0x0000800d, "CALG_SHA_384" },
    { 0x0000800d, "CALG_SHA_384" },
    { 0x0000800e, "CALG_SHA_512" },
    { 0x0000800e, "CALG_SHA_512" },
    { 0x0000660a, "CALG_SKIPJACK" },
    { 0x00004c05, "CALG_SSL2_MASTER" },
    { 0x00004c01, "CALG_SSL3_MASTER" },
    { 0x00008008, "CALG_SSL3_SHAMD5" },
    { 0x0000660b, "CALG_TEK" },
    { 0x00004c06, "CALG_TLS1_MASTER" },
    { 0x0000800a, "CALG_TLS1PRF" },
    { 0,          NULL }
};
wincrypt_types wincrypt_flags[] = {
    { 1,          "CRYPT_EXPORTABLE" },
    { 2,          "CRYPT_USER_PROTECTED" },
    { 4,          "CRYPT_CREATE_SALT" },
    { 8,          "CRYPT_UPDATE_KEY" },
    { 0x00000400, "CRYPT_SERVER" },
    { 0,          NULL }
};
wincrypt_types wincrypt_flags2[] = {
    { 0x00000040, "CRYPT_OAEP" },
    { 0x00000020, "CRYPT_DECRYPT_RSA_NO_PADDING_CHECK" },
    { 0,          NULL }
};

typedef struct {
    HCRYPTPROV  hProv;
    HCRYPTHASH  hHash;
    HCRYPTKEY   hKey;
    u8          *mspn;
    DWORD       prov;
    DWORD       hash;
    DWORD       algo;
    DWORD       flags;
    DWORD       flags2;
} wincrypt_context;

u8 *wincrypt_parameters(u8 *parameters, wincrypt_types *types, DWORD *ret) {
    DWORD   tmp;
    int     i,
            len,
            quote = 0;
    u8      *p,
            *pquote = NULL,
            *pret;

    if(!parameters) return NULL;
    if(!parameters[0]) return NULL;
    p = parameters;
    if((*p == '\"') || (*p == '\'')) {
        quote = 1;
        for(++p; *p; p++) {
            if((*p == '\"') || (*p == '\'')) {
                pquote = p;
                break;
            }
        }
    }
    p = mystrchrs(p, " \t,;");
    if(!p) p = parameters + strlen(parameters);
    pret = p;

    if(quote) {
        parameters++;
        p = pquote;
    }
    len = p - parameters;
    if(len <= 0) return NULL;

    tmp = getvarnum(parameters, -1); //readbase(parameters, 10, NULL);
    for(i = 0; types[i].str; i++) {
        if(
            (!strnicmp(types[i].str, parameters, len) && !types[i].str[len])
         || (tmp == types[i].num)) {
            *ret = (DWORD)types[i].num;
            if(!pret[0]) return NULL;
            return(pret + 1);
        }
    }
    return(parameters);
}

int wincrypt_setkey(wincrypt_context *ctx, u8 *key, int keysz, u8 *parameters) {
    static const int    flags[] = {
                0,
                CRYPT_NEWKEYSET,
                CRYPT_MACHINE_KEYSET,
                CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET,
                CRYPT_VERIFYCONTEXT,
                CRYPT_DELETEKEYSET,
                CRYPT_SILENT,
                -1
            };
    int     i;
    u8      *p;

    ctx->mspn = MS_DEF_PROV;
    ctx->prov = PROV_RSA_FULL;
    ctx->hash = CALG_MD5;
    ctx->algo = CALG_RC4;

    if(parameters) {
        p = parameters;
        p = wincrypt_parameters(p, wincrypt_calg,   &ctx->hash);
        p = wincrypt_parameters(p, wincrypt_calg,   &ctx->algo);
        p = wincrypt_parameters(p, wincrypt_prov,   &ctx->prov);
        p = wincrypt_parameters(p, wincrypt_mspn1,  (DWORD *)&ctx->mspn);
        p = wincrypt_parameters(p, wincrypt_mspn2,  (DWORD *)&ctx->mspn);
        p = wincrypt_parameters(p, wincrypt_flags,  &ctx->flags);
        p = wincrypt_parameters(p, wincrypt_flags2, &ctx->flags2);
    }

    for(i = 0; flags[i] >= 0; i++) {
        if(CryptAcquireContext(
            &ctx->hProv,
            NULL,
            ctx->mspn,
            ctx->prov,
            flags[i])) break;
    }
    if(flags[i] < 0) return -1;

    if(!CryptCreateHash(
        ctx->hProv,
        ctx->hash,
        0,  //ctx->hashkey,
        0,
        &ctx->hHash)) return -1;

    if(!CryptHashData(
        ctx->hHash,
        key,
        keysz,
        0)) return -1;
    return 0;
}

int wincrypt_decrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    DWORD   len;

    if(datalen <= 0) return 0;
    len = datalen;

    if(!CryptDeriveKey(
        ctx->hProv,
        ctx->algo,
        ctx->hHash,
        ctx->flags,
        &ctx->hKey)) return -1;

    if(!CryptDecrypt(
        ctx->hKey,
        0,
        TRUE,
        ctx->flags2,
        data,
        &len)) return -1;
    return(len);
}

int wincrypt_encrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    DWORD   len;

    if(datalen <= 0) return 0;
    len = datalen;

    if(!CryptDeriveKey(
        ctx->hProv,
        ctx->algo,
        ctx->hHash,
        ctx->flags,
        &ctx->hKey)) return -1;

    if(!CryptEncrypt(
        ctx->hKey,
        0,
        TRUE,
        ctx->flags2,
        data,
        &len,
        datalen)) return -1;
    return(len);
}
#else
typedef struct {
} wincrypt_context;
int wincrypt_setkey(wincrypt_context *ctx, u8 *key, int keysz, u8 *parameters) {
    return -1;
}
int wincrypt_decrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    return -1;
}
int wincrypt_encrypt(wincrypt_context *ctx, u8 *data, int datalen) {
    return -1;
}
#endif



// CryptUnprotect (mainly for thoroughness, not for real usage)
#ifdef WIN32
#include <windows.h>
typedef struct {
    u8      *entropy;
    int     entropy_size;
} cunprot_context;
int cunprot_setkey(cunprot_context *ctx, u8 *key, int keysz) {
    if(keysz > 0) {
        ctx->entropy      = key;
        ctx->entropy_size = keysz;
    } else {
        ctx->entropy      = NULL;
        ctx->entropy_size = 0;
    }
    return 0;
}
int cunprot_decrypt(cunprot_context *ctx, u8 *data, int datalen) {
    DATA_BLOB   DataIn,
                DataEntropy,
                DataOut;
    int         ret;

    DataIn.pbData = data;
    DataIn.cbData = datalen;
    if(ctx->entropy) {
        DataEntropy.pbData = ctx->entropy;
        DataEntropy.cbData = ctx->entropy_size;
    }

    if(!CryptUnprotectData(
      &DataIn,
      NULL,
      ctx->entropy ? &DataEntropy : NULL,
      NULL,
      NULL,
      0,
      &DataOut)) {
        DataIn.pbData = malloc(datalen + 1);
        if(!DataIn.pbData) return -1;
        DataIn.cbData = unhex(data, datalen, DataIn.pbData, datalen);
        ret = CryptUnprotectData(
          &DataIn,
          NULL,
          ctx->entropy ? &DataEntropy : NULL,
          NULL,
          NULL,
          0,
          &DataOut);
        free(DataIn.pbData);    // free it in any case
        if(!ret) return -1;
    }

    if(datalen > DataOut.cbData) datalen = DataOut.cbData;
    memcpy(data, DataOut.pbData, datalen);
    if(DataOut.pbData) LocalFree(DataOut.pbData);
    return(datalen);
}
int cunprot_encrypt(cunprot_context *ctx, u8 *data, int datalen) {
    DATA_BLOB   DataIn,
                DataEntropy,
                DataOut;
    int         ret;

    DataIn.pbData = data;
    DataIn.cbData = datalen;
    if(ctx->entropy) {
        DataEntropy.pbData = ctx->entropy;
        DataEntropy.cbData = ctx->entropy_size;
    }

    if(!CryptProtectData(
      &DataIn,
      L"description",
      ctx->entropy ? &DataEntropy : NULL,
      NULL,
      NULL,
      0,
      &DataOut)) {
        DataIn.pbData = malloc(datalen + 1);
        if(!DataIn.pbData) return -1;
        DataIn.cbData = unhex(data, datalen, DataIn.pbData, datalen);
        ret = CryptProtectData(
          &DataIn,
          L"description",
          ctx->entropy ? &DataEntropy : NULL,
          NULL,
          NULL,
          0,
          &DataOut);
        free(DataIn.pbData);
        if(!ret) return -1;
    }

    if(datalen > DataOut.cbData) datalen = DataOut.cbData;
    memcpy(data, DataOut.pbData, datalen);
    if(DataOut.pbData) LocalFree(DataOut.pbData);
    return(datalen);
}
#else
typedef struct {
} cunprot_context;
int cunprot_setkey(cunprot_context *ctx, u8 *key, int keysz) {
    return -1;
}
int cunprot_decrypt(cunprot_context *ctx, u8 *data, int datalen) {
    return -1;
}
int cunprot_encrypt(cunprot_context *ctx, u8 *data, int datalen) {
    return -1;
}
#endif



// crc
#include "crc.c"



typedef struct {
    int     direction;
    int     operation;
    int     last_value;
} xor_prev_next_context;
int xor_prev_next_setkey(xor_prev_next_context *ctx, u8 *key, int direction) {
    memset(ctx, 0, sizeof(xor_prev_next_context));
    ctx->direction = direction;
    if(key && key[0]) {
        if(isalnum(key[0])) {   // "0xff"
            ctx->last_value = getvarnum(key, -1); //readbase(key, 10, NULL);
        } else {                // "+ 0xff"
            ctx->operation = key[0];
            ctx->last_value = getvarnum(key + 1, -1); //readbase(key + 1, 10, NULL);
        }
    }
    return 0;
}
int xor_prev_next(xor_prev_next_context *ctx, u8 *data, int datalen, int encrypt) {
    #define xor_prev_next_do(X) \
        if((i < 0) || (i >= datalen)) continue; \
        pos = i X 1; \
        if((pos < 0) || (pos >= datalen)) { \
            c = ctx->last_value; \
        } else { \
            c = data[pos]; \
        } \
        switch(ctx->operation) { \
            case '+': data[i] += c; break; \
            case '-': data[i] -= c; break; \
            default:  data[i] ^= c; break; \
        }

    xor_prev_next_context   bck_ctx;
    int     i,
            c,
            pos;

    if(encrypt) {
        memcpy(&bck_ctx, ctx, sizeof(xor_prev_next_context));
        switch(ctx->operation) {
            case '+': ctx->operation = '-'; break;
            case '-': ctx->operation = '+'; break;
            default: break;
        }
        switch(ctx->direction) {
            case -1: ctx->direction =  1;   break;
            case -2: ctx->direction =  2;   break;
            case  1: ctx->direction = -1;   break;
            case  2: ctx->direction = -2;   break;
            default: break;
        }
    }

    switch(ctx->direction) {
        case -1:
            for(i = datalen - 1; i >= 0; i--) {
                xor_prev_next_do(-)
            }
            break;
        case -2:
            for(i = datalen - 1; i >= 0; i--) {
                xor_prev_next_do(+)
            }
            break;
        case 1:
            for(i = 0; i < datalen; i++) {
                xor_prev_next_do(-)
            }
            break;
        case 2:
            for(i = 0; i < datalen; i++) {
                xor_prev_next_do(+)
            }
            break;
        default: break;
    }

    if(encrypt) {
        memcpy(ctx, &bck_ctx, sizeof(xor_prev_next_context));
    }
    return datalen;
}
