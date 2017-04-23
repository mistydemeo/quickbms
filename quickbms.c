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

#define _WIN32_WINNT    0x0601
#define _WIN32_WINDOWS  0x0601
#define WINVER          0x0601

//#define NOLFS
#ifndef NOLFS   // 64 bit file support not really needed since the tool uses signed 32 bits at the moment, anyway I leave it enabled
    #define _LARGE_FILES        // if it's not supported the tool will work
    #define __USE_LARGEFILE64   // without support for large files
    #define __USE_FILE_OFFSET64
    #define _LARGEFILE_SOURCE
    #define _LARGEFILE64_SOURCE
    #define _FILE_OFFSET_BITS   64
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <math.h>
#include <inttypes.h>
#include <locale.h>
#include <fcntl.h>
#include "stristr.c"

#include "extra/xalloc.h"
#include "extra/uthash_real_alloc.h"
#include "extra/utlist.h"

// this is the old method used by quickbms to handle short strings.
// currently it has been disabled and will rely entirely on allocated memory instead of static buffers.
// I'm still testing the effects on the performances, QUICKBMS_VAR_STATIC is stable and has ever worked,
// while the other method is slower (frostbite.bms is sloooooow) but doesn't use work-arounds.
// so... do NOT touch it!
#define QUICKBMS_VAR_STATIC

// disabled by default because there are some things that don't convince me
// for example during the disassembling of shellcode_Alpha2.txt
#ifdef ENABLE_BEAENGINE
    #define BEA_ENGINE_STATIC
    #define BEA_USE_STDCALL
    #include <BeaEngine.h>
#endif

//typedef int8_t      i8;
typedef uint8_t     u8;
//typedef int16_t     i16;
typedef uint16_t    u16;
typedef int32_t     i32;
typedef uint32_t    u32;
//typedef int64_t     i64;
typedef uint64_t    u64;

typedef int8_t      int8;
typedef uint8_t     uint8;
typedef int16_t     int16;
typedef uint16_t    uint16;
typedef int32_t     int32;
typedef uint32_t    uint32;
typedef int64_t     int64;
typedef uint64_t    uint64;
typedef unsigned char   byte;   // for sflcomp
typedef unsigned short  word;   // for sflcomp

#define QUICKBMS
// in case you want to make QuickBMS 64bit compatible
// start
#ifdef QUICKBMS64
    #define INTSZ           64
    #define QUICKBMS_int    int64_t     // trick for forcing the usage of signed 32 bit numbers on any system without modifying the code
    #define QUICKBMS_u_int  uint64_t    // used only in some rare occasions
    #define PRId            PRId64
    #define PRIu            PRIu64
    #define PRIx            "016"PRIx64
#else
    #define INTSZ           32
    #define QUICKBMS_int    int32_t     // trick for forcing the usage of signed 32 bit numbers on any system without modifying the code
    #define QUICKBMS_u_int  uint32_t    // used only in some rare occasions
    #define PRId            PRId32
    #define PRIu            PRIu32
    #define PRIx            "08"PRIx32
#endif
// end
#define PATH_DELIMITERS     "\\/"

#ifdef WIN32
#else
    #define stricmp     strcasecmp
    #define strnicmp    strncasecmp
    //#define stristr     strcasestr
    typedef uint32_t    DWORD;
#endif
int (*real_strcmp) ( const char * str1, const char * str2 ) = strcmp;
int (*real_stricmp) ( const char * str1, const char * str2 ) = stricmp;
int (*real_strncmp) ( const char * str1, const char * str2, size_t num ) = strncmp;
int (*real_strnicmp) ( const char * str1, const char * str2, size_t num ) = strnicmp;
i32 mystrcmp(const char *a, const char *b);
i32 mystricmp(const char *a, const char *b);
i32 mystrncmp(const char *a, const char *b, i32 n);
i32 mystrnicmp(const char *a, const char *b, i32 n);
#define strcmp      mystrcmp
#undef stricmp
#define stricmp     mystricmp
#define strncmp     mystrncmp
#undef strnicmp
#define strnicmp    mystrnicmp

// yeah it's cdecl by default
int /*__cdecl*/ fake_printf(const char *__format, ...) {
    return 0;
}
int /*__cdecl*/ (*backup_real_printf) (const char *__format, ...) = printf;
int /*__cdecl*/ (*real_printf) (const char *__format, ...) = printf;
int /*__cdecl*/ fake_fprintf(FILE *__stream, const char *__format, ...) {
    if((__stream == stdout) || (__stream == stderr)) return 0;
  register int __retval;
  __builtin_va_list __local_argv; __builtin_va_start( __local_argv, __format );
  __retval = /*__mingw_*/vfprintf( __stream, __format, __local_argv );
  __builtin_va_end( __local_argv );
  return __retval;
}
int /*__cdecl*/ (*backup_real_fprintf) (FILE *__stream, const char *__format, ...) = fprintf;
int /*__cdecl*/ (*real_fprintf) (FILE *__stream, const char *__format, ...) = fprintf;
#define printf      real_printf
#define fprintf     real_fprintf

#include "quickiso.c"
#include "quickzip.c"
#include <zlib.h>
#include <bzlib.h>
#ifndef DISABLE_UCL     // add -DDISABLE_UCL at compiling if you don't have UCL
    #include <ucl/ucl.h>
#endif
#ifndef DISABLE_LZO     // add -DDISABLE_LZO at compiling if you don't have LZO
    #include <lzo/lzo1.h>
    #include <lzo/lzo1a.h>
    #include <lzo/lzo1b.h>
    #include <lzo/lzo1c.h>
    #include <lzo/lzo1f.h>
    #include <lzo/lzo1x.h>
    #include <lzo/lzo1y.h>
    #include <lzo/lzo1z.h>
    #include <lzo/lzo2a.h>
#else
    #include "libs/minilzo/minilzo.h"
#endif
#include "compression/blast.h"
#include "compression/sflcomp.h"
#include "libs/lzma/LzmaDec.h"
#include "libs/lzma/Lzma2Dec.h"
#include "libs/lzma/Bra.h"
#include "libs/lzma/LzmaEnc.h"
#include "libs/lzma/Lzma2Enc.h"

// or use -DDISABLE_SSL
#ifndef DISABLE_SSL
    // it's useless to enable the following
    //#define OPENSSL_DOING_MAKEDEPEND
    //#define OPENSSL_NO_KRB5
    #include <openssl/ossl_typ.h>
    #include <openssl/evp.h>
    #include <openssl/aes.h>
    #include <openssl/blowfish.h>
    #include <openssl/hmac.h>
#endif
#include "encryption/tea.h"
#include "encryption/xtea.h"
#include "encryption/xxtea.h"
#include "myenc.c"
#include "encryption/twofish.h"
#include "encryption/seed.h"
#include "encryption/serpent.h"
#include "encryption/ice.h"
#include "encryption/rotor.c"
//#include "encryption/libkirk/kirk_engine.h"
#include "encryption/sph.h"
int kirk_CMD0(u8* outbuff, u8* inbuff, int size, int generate_trash);
int kirk_CMD1(u8* outbuff, u8* inbuff, int size, int do_check);
int kirk_CMD4(u8* outbuff, u8* inbuff, int size);
int kirk_CMD7(u8* outbuff, u8* inbuff, int size);
int kirk_CMD10(u8* inbuff, int insize);
int kirk_CMD11(u8* outbuff, u8* inbuff, int size);
int kirk_CMD14(u8* outbuff, int size);
int kirk_init(); //CMD 0xF?
void xtea_crypt_ecb( xtea_context *ctx, int mode, u8 input[8], u8 output[8] );
#ifndef DISABLE_MCRYPT
    #include <mcrypt.h>
#endif
//#define DISABLE_TOMCRYPT    // useless at the moment
#ifndef DISABLE_TOMCRYPT
    #define USE_LTM
    #define LTC_MECC
    #define LTM_DESC
    #define LTC_SOURCE
    #define LTC_MRSA
    #define LTC_MKAT
    #define LTC_MDH
    #define LTC_MDSA
    #define LTC_DER
    #include <tomcrypt.h>
#endif
void zipcrypto_init_keys(const char* passwd,uint32_t* pkeys,const uint32_t* pcrc_32_tab);
void zipcrypto_decrypt(uint32_t* pkeys,const uint32_t* pcrc_32_tab, unsigned char *data, int datalen);
void zipcrypto_encrypt(uint32_t* pkeys,const uint32_t* pcrc_32_tab, unsigned char *data, int datalen);
int threeway_setkey(unsigned *key, unsigned char *data, int datalen);
void threeway_encrypt(unsigned *key, unsigned char *data, int datalen);
void threeway_decrypt(unsigned *key, unsigned char *data, int datalen);
void skipjack_makeKey(byte key[10], byte tab[10][256]);
void skipjack_encrypt(byte tab[10][256], byte in[8], byte out[8]);
void skipjack_decrypt(byte tab[10][256], byte in[8], byte out[8]);
#include "encryption/anubis.h"
typedef struct { Byte rk[16*17]; int Nr; } aria_ctx_t;
int ARIA_DecKeySetup(const Byte *mk, Byte *rk, int keyBits);
int ARIA_EncKeySetup(const Byte *mk, Byte *rk, int keyBits);
void ARIA_Crypt(const Byte *i, int Nr, const Byte *rk, Byte *o);
u_int *crypton_set_key(const u_int in_key[], const u_int key_len, u_int l_key[104]);
u_int crypton_encrypt(const u_int in_blk[4], u_int out_blk[4], u_int l_key[104]);
u_int crypton_decrypt(const u_int in_blk[4], u_int out_blk[4], u_int l_key[104]);
u_int *frog_set_key(const u_int in_key[], const u_int key_len);
void frog_encrypt(const u_int in_blk[4], u_int out_blk[4]);
void frog_decrypt(const u_int in_blk[4], u_int out_blk[4]);
typedef struct { u_int iv[2]; u_int key[8]; int type; } gost_ctx_t;
void gost_kboxinit(void);
void gostcrypt(u_int const in[2], u_int out[2], u_int const key[8]);
void gostdecrypt(u_int const in[2], u_int out[2], u_int const key[8]);
void gostofb(u_int const *in, u_int *out, int len, u_int const iv[2], u_int const key[8]);
void gostcfbencrypt(u_int const *in, u_int *out, int len, u_int iv[2], u_int const key[8]);
void gostcfbdecrypt(u_int const *in, u_int *out, int len, u_int iv[2], u_int const key[8]);
void lucifer(unsigned char *);
void lucifer_loadkey(unsigned char *, int);
u_int *mars_set_key(u_int key_blk[], u_int key_len);
void mars_encrypt(u_int in_blk[], u_int out_blk[]);
void mars_decrypt(u_int in_blk[], u_int out_blk[]);
void misty1_keyinit(u_int  *ek, u_int  *k);
void misty1_decrypt_block(u_int  *ek,u_int  c[2], u_int  p[2]);
void misty1_encrypt_block(u_int  *ek, u_int  p[2], u_int  c[2]);
typedef struct { u_int k[4]; } NOEKEONstruct;
void NOEKEONkeysetup(const unsigned char * const key, 
                    NOEKEONstruct * const structpointer);
void NOEKEONencrypt(const NOEKEONstruct * const structpointer, 
                   const unsigned char * const plaintext,
                   unsigned char * const ciphertext);
void NOEKEONdecrypt(const NOEKEONstruct * const structpointer,
                   const unsigned char * const ciphertext,
                   unsigned char * const plaintext);
#include "encryption/seal.h"
#include "encryption/safer.h"
int pc1_128(unsigned char *cle, unsigned char *data, int size, int decenc);
int pc1_256(unsigned char *cle, unsigned char *data, int size, int decenc);
uint32_t *rc6_set_key(uint32_t *l_key, const uint32_t in_key[], const uint32_t key_len);
void rc6_encrypt(uint32_t *l_key, const uint32_t in_blk[4], uint32_t out_blk[4]);
void rc6_decrypt(uint32_t *l_key, const uint32_t in_blk[4], uint32_t out_blk[4]);
#include "encryption/isaac.h"
void isaacx_crypt(unsigned char *key, int keylen, unsigned char *data, int datasz, int do_encrypt);
void hsel_crypt(unsigned char *key, unsigned char *data, int size, int do_encrypt, char *options);

#ifdef __DJGPP__
    #define NOLFS
    char **__crt0_glob_function (char *arg) { return 0; }
    void   __crt0_load_environment_file (char *progname) { }
#endif

#define DISABLE_BACKTRACE   // it makes the executable bigger and breaks compatibility with Win98 (_fstat64)

#ifdef WIN32
    #include <windows.h>
    //#include <psapi.h>
    //#include <shlobj.h>
    //#include <tlhelp32.h>
    #include <wincrypt.h>
    #include <direct.h>
    //#include <ddk/ntifs.h>    // I want compatibility even with Win9x
    #include "extra/MemoryModule.h"
    #ifndef DISABLE_BACKTRACE
    #include "extra/backtrace.c"
    #endif

    #define PATHSLASH   '\\'
    #define LOADDLL(X)  LoadLibrary(X)
    #define GETFUNC(X)  (void *)GetProcAddress(hlib, X)
    #define CLOSEDLL    FreeLibrary(hlib)

    char *get_file(char *title, i32 bms, i32 multi);
    char *get_folder(char *title);
#else
    #include <unistd.h>
    #include <dirent.h>
    #include <dlfcn.h>      // -ldl
    #include <sys/mman.h>
    #include <netinet/in.h>

    #define LOADDLL(X)  dlopen(X, RTLD_LAZY)
    #define GETFUNC(X)  (void *)dlsym(hlib, X)
    #define CLOSEDLL    dlclose(hlib)
    #define HMODULE     void *
    #define GetCurrentProcessId getpid
    #define PATHSLASH   '/'
    #ifdef __APPLE__
        // don't use iconv
    #else
        #define USE_LIBICONV    // -liconv
    #endif
#endif

#if defined(_LARGE_FILES)
    #if defined(__APPLE__)
        #define fseek   fseeko
        #define ftell   ftello
    #elif defined(__FreeBSD__)
    #elif !defined(NOLFS)       // use -DNOLFS if this tool can't be compiled on your OS!
        #define off_t   off64_t
        #define fopen   fopen64
        #define fseek   fseeko64
        #define ftell   ftello64
        #ifndef fstat
            #ifdef WIN32
                #define fstat   _fstati64
                #define stat    _stati64
            #else
                #define fstat   fstat64
                #define stat    stat64
            #endif
        #endif
    #endif
#endif

# ifndef __cdecl 
#  define __cdecl  __attribute__ ((__cdecl__))
# endif
# ifndef __stdcall
#  define __stdcall __attribute__ ((__stdcall__))
# endif
void __cxa_pure_virtual() { while(1); }

#include "threads.h"



static u8   VER[64]     = "";       // kept for compatibility with some functions
#define BUFFSZ          8192
#define MAX_IFS         16          // fixed but exagerated
#define MAX_ARGS        32          // fixed but exagerated
#define MAX_VARS        1024        // fixed but exagerated (name/value_static gives problems with allocated variables)
#define MAX_FILES       1024        // fixed but exagerated
#define MAX_CMDS        4096        // fixed but exagerated
#define MAX_ARRAYS      1024        // fixed but exagerated

#define STRINGSZ        273         // more than MAX_PATH, aligned with +1, 273*15+1 = 4096
#define VAR_VALUE_DELIMITERS    3   // unicode and so on, originally it was just 1
#define NUMBERSZ        24          // ready for 64 bits, includes also space for the NULL delimiter
#define PATHSZ          1024        // 257 was enough, theoretically the system could support 32kb but 1024 is really a lot
#define MULTI_PATHSZ    32768       // 32k limit ansi, no limit unicode
#define ENABLE_DIRECT_COPY

#ifdef QUICKBMS_VAR_STATIC
#define VAR_NAMESZ      STRINGSZ    // 31          // +1 for alignment, 31 for a variable name is perfect
#define VAR_VALUESZ     STRINGSZ    // more than 256 and big enough to contain filenames
#if VAR_NAMESZ < NUMBERSZ
ERROR VAR_NAMESZ < NUMBERSZ
#endif
#endif

#define MYLITTLE_ENDIAN 0
#define MYBIG_ENDIAN    1

#define int             QUICKBMS_int
#define u_int           QUICKBMS_u_int

#define QUICKBMS_DUMMY  "QUICKBMS_DUMMY_TEMP"
#define CMD             g_command[cmd]
#define ARG             argument
#define NUM(X)          CMD.num[X]
#define STR(X)          CMD.str[X]
#define VARISNUM(X)     var_is_a_number(CMD.var[X]) //g_variable[CMD.var[X]].isnum
#define VARNAME(X)      get_varname(CMD.var[X])
#define VAR(X)          get_var(CMD.var[X])
#define VAR32(X)        get_var32(CMD.var[X])
#ifdef QUICKBMS_VAR_STATIC
#define VARSZ(X)        g_variable[CMD.var[X]].size   // due to the memory enhancement done on this tool, VARSZ returns ever STRINGSZ for sizes lower than this value... so do NOT trust this value!
#else
#define VARSZ(X)        get_var_fullsz(CMD.var[X])    // causes LOT of problems with static variables, check what happened with quickbms 0.7.2a
#endif
//#define FILEZ(X)        ((NUM(X) < 0) ? NULL : g_filenumber[NUM(X)].fd)  // automatic support for MEMORY_FILE
#define DIRECT_ADDVAR(X,Y,Z) \
                        g_variable[CMD.var[X]].value   = Y; \
                        g_variable[CMD.var[X]].value32 = 0; \
                        g_variable[CMD.var[X]].isnum   = 0; \
                        g_variable[CMD.var[X]].size    = Z;
#define FILEZ(X)        NUM(X)
#define MEMORY_FNAME    "MEMORY_FILE"
#define MEMORY_FNAMESZ  (sizeof(MEMORY_FNAME) - 1)
#define TEMPORARY_FILE  "TEMPORARY_FILE"
#define ALLOC_ERR       alloc_err(__FILE__, __LINE__, __FUNCTION__)
#define STD_ERR(ERR)    std_err(__FILE__, __LINE__, __FUNCTION__, ERR)

static void FCLOSEX(FILE *X) { if(X && (X != stdout) && (X != stderr) && (X != stdin)) fclose(X); }
#define FCLOSE(X)   { FCLOSEX(X); X = NULL; }   // NULL is very important!
// use FREE instead of free
#define FREE(X)         if(X) { \
                            free(X); \
                            X = NULL; \
                        }
#define FREEX(X,Y)      if(X) { \
                            Y; \
                            FREE(X) \
                        }
// the first 2 checks on fdnum are not necessary
#define CHECK_FILENUM   if( \
                            (fdnum < 0) ||  \
                            (fdnum > MAX_FILES) || \
                            ( \
                                !g_filenumber[fdnum].fd && \
                                !g_filenumber[fdnum].sd && \
                                !g_filenumber[fdnum].pd && \
                                !g_filenumber[fdnum].ad && \
                                !g_filenumber[fdnum].vd && \
                                !g_filenumber[fdnum].md \
                            ) \
                        ) { \
                            fprintf(stderr, "\nError: the specified file number (%d) has not been opened yet (line %d)\n", (i32)fdnum, (i32)__LINE__); \
                            myexit(QUICKBMS_ERROR_BMS); \
                        }
#define myatoi(X)       readbase(X, 10, NULL)
#define CSTRING(X,Y)    { \
                        mystrdup(&CMD.str[X], Y); \
                        CMD.num[X] = cstring(CMD.str[X], CMD.str[X], -1, NULL); \
                        }
#define QUICK_GETi32(X,Y)   ((X[Y])   | (X[Y+1] << 8) | (X[Y+2] << 16) | (X[Y+3] << 24))
#define QUICK_GETb32(X,Y)   ((X[Y+3]) | (X[Y+2] << 8) | (X[Y+1] << 16) | (X[Y]   << 24))
#define QUICK_GETi16(X,Y)   ((X[Y])   | (X[Y+1] << 8))
#define QUICK_GETb16(X,Y)   ((X[Y+1]) | (X[Y]   << 8))
#define SCAN_INPUT_FILE_PATH(OUT_BUFF, IN_NAME) \
            switch(i) { \
                case 0:  mypath = g_bms_folder;     break; \
                case 1:  mypath = g_exe_folder;     break; \
                case 2:  mypath = g_file_folder;    break; \
                case 3:  mypath = g_current_folder; break; \
                case 4:  mypath = g_output_folder;  break; \
                case 5:  mypath = ".";              break; \
                default: mypath = NULL;             break; \
            } \
            if(!mypath) break; \
            spr(&OUT_BUFF, "%s%c%s", mypath, PATHSLASH, IN_NAME);

// numbers_to_bytes returns a static buffer so do NOT free it
// NUMS2BYTES(input, input_size, output, output_size)
#define NUMS2BYTES(A,B,C,D,E) { \
                        tmp = numbers_to_bytes(A, &B, 0, E); \
                        myalloc(&C, B, &D); \
                        memcpy(C, tmp, B); \
                        }
#define NUMS2BYTES_HEX(A,B,C,D,E) { \
                        tmp = numbers_to_bytes(A, &B, 1, E); \
                        myalloc(&C, B, &D); \
                        memcpy(C, tmp, B); \
                        }

#define MULTISTATIC     256 // this number is simply the amount of static buffers to use so that
                            // we can use the same function MULTISTATIC times without overlapped results!
#define strdup_dontuse  "Error: do NOT use strdup, use re_strdup or mystrdup!"
#define strdup          strdup_dontuse
#define far
//#define PRINTF64(X)     (i32)(((X) >> 32) & 0xffffffff), (i32)((X) & 0xffffffff)



#include "defs.h"



u8 *myitoa(QUICKBMS_int num);
files_t *add_files(u8 *fname, QUICKBMS_int fsize, QUICKBMS_int *ret_files);
int debug_privileges(void);
int verbose_options(u8 *arg);
u8 *mystrdup_simple(u8 *str);
u8 *mystrdup(u8 **old_buff, u8 *str);
u8 *show_dump(int left, u8 *data, int len, FILE *stream);
int get_parameter_numbers_int(u8 *str, ...);
int get_parameter_numbers_i32(u8 *str, ...);
QUICKBMS_int readbase(u8 *data, QUICKBMS_int size, QUICKBMS_int *readn);
void g_mex_default_init(int file_only);
int start_bms(int startcmd, int nop, int this_is_a_cycle, int *invoked_if, int *invoked_break, int *invoked_continue, u8 **invoked_label);
int check_wildcard(u8 *fname, u8 *wildcard);
int check_wildcards(u8 *fname, u8 **list);
u8 *create_dir(u8 *fname, int mdir, int cdir, int is_path, int filter_bad);
int check_overwrite(u8 *fname, int check_if_present_only);
u8 *myalloc(u8 **data, QUICKBMS_int wantsize, QUICKBMS_int *currsize);
void std_err(const char *fname, i32 line, const char *func, signed char error);
void winerr(DWORD error, char *msg);
void myexit(int ret);



// boring 64bit compatibility
#undef int
#undef u_int
#if QUICKBMS_int != 32
    u8 *myalloc32(u8 **data, int wantsize, int *currsize) {
        QUICKBMS_int    lame;
        if(!currsize) {
            myalloc(data, wantsize, NULL);
        } else {
            lame = *currsize;
            myalloc(data, wantsize, &lame);
            *currsize = lame;
        }
        return(*data);
    }
    #define myalloc myalloc32
#endif
#define get_parameter_numbers get_parameter_numbers_i32

// int -> 32
#include "calling_conventions.h"
#include "sign_ext.c"
#include "unz.c"
#include "extra/wcx.c"
#include "extra/window.c"
#include "extra/libtcc.h"
#include "io/sockets.c"
#include "io/process.c"
#include "io/audio.c"
#include "io/video.c"
#include "io/winmsg.c"
#undef myalloc
#define MAINPROG
#include "disasm/disasm.h"
typedef struct t_asmmodel {            // Model to search for assembler command
  uchar          code[MAXCMDSIZE];     // Binary code
  uchar          mask[MAXCMDSIZE];     // Mask for binary code (0: bit ignored)
  int            length;               // Length of code, bytes (0: empty)
  int            jmpsize;              // Offset size if relative jump
  int            jmpoffset;            // Offset relative to IP
  int            jmppos;               // Position of jump offset in command
} t_asmmodel;
int    Assemble(uchar *cmd,ulong ip,t_asmmodel *model,int attempt,
         int constsize,uchar *errtext);
// restore int and u_int after main()



// int -> 32 or 64
#define int             QUICKBMS_int
#define u_int           QUICKBMS_u_int

#undef  get_parameter_numbers
#define get_parameter_numbers get_parameter_numbers_int



int     g_quickbms_exception_test   = -1,
        g_insensitive               = 1;
i32     g_quickbms_argc             = 0;
char    **g_quickbms_argv           = NULL;
char    g_quickbms_arg0[PATHSZ + 1] = "";



#include "utils_unicode.c"
#include "utils.c"
#include "var.c"
#include "perform.c"
#include "hexhtml.c"
#include "file.c"
#include "cmd.c"
#include "bms.c"
#include "update.c"
#include "help.c"



int set_console_title(u8 *options_db, u8 *bms, u8 *fname) {
#ifdef WIN32
    static  u8  title[1024] = "";
    u8      options[256 + 1];
    int     i,
            len;

    len = 0;
    for(i = 0; i < 256; i++) {
        if(options_db[i]) options[len++] = i;
    }
    options[len] = 0;

    len = snprintf(
        title,
        sizeof(title),
        "%s -%s: %s . %s",
        VER,
        options,
        bms,
        fname);

    if((len < 0) || (len > sizeof(title))) {
        title[sizeof(title) - 1] = 0;
    }

    SetConsoleTitle(title);
#endif
    return 0;
}



#ifdef WIN32
// the goal of these functions is avoiding the error dialog box and terminating the process immediately
u8 *show_exception_code(int code) {
    u8      *msg = NULL;
    switch(code) {
        case STATUS_SEGMENT_NOTIFICATION: msg = "segment notification"; break;
        case STATUS_GUARD_PAGE_VIOLATION: msg = "guard page violation"; break;
        case STATUS_DATATYPE_MISALIGNMENT: msg = "datatype misalignment"; break;
        case STATUS_BREAKPOINT: msg = "breakpoint"; break;
        case STATUS_SINGLE_STEP: msg = "single step"; break;
        case STATUS_ACCESS_VIOLATION: msg = "access violation"; break;
        case STATUS_IN_PAGE_ERROR: msg = "in page error"; break;
        case STATUS_INVALID_HANDLE: msg = "invalid handle"; break;
        case STATUS_NO_MEMORY: msg = "no memory"; break;
        case STATUS_ILLEGAL_INSTRUCTION: msg = "illegal instruction"; break;
        case STATUS_NONCONTINUABLE_EXCEPTION: msg = "non continuable exception"; break;
        case STATUS_INVALID_DISPOSITION: msg = "invalid disposition"; break;
        case STATUS_ARRAY_BOUNDS_EXCEEDED: msg = "array bounds exceeded"; break;
        case STATUS_FLOAT_DENORMAL_OPERAND: msg = "float denormal operand"; break;
        case STATUS_FLOAT_DIVIDE_BY_ZERO: msg = "float divide by zero"; break;
        case STATUS_FLOAT_INEXACT_RESULT: msg = "float inexact result"; break;
        case STATUS_FLOAT_INVALID_OPERATION: msg = "float invalid operation"; break;
        case STATUS_FLOAT_OVERFLOW: msg = "float overflow"; break;
        case STATUS_FLOAT_STACK_CHECK: msg = "float stack check"; break;
        case STATUS_FLOAT_UNDERFLOW: msg = "float underflow"; break;
        case STATUS_INTEGER_DIVIDE_BY_ZERO: msg = "divide by zero"; break;
        case STATUS_INTEGER_OVERFLOW: msg = "integer overflow"; break;
        case STATUS_PRIVILEGED_INSTRUCTION: msg = "privileged instruction"; break;
        case STATUS_STACK_OVERFLOW: msg = "stack overflow"; break;
        case STATUS_CONTROL_C_EXIT: msg = "CTRL+C exit"; break;
        case STATUS_DLL_INIT_FAILED: msg = "DLL init failed"; break;
        #ifdef STATUS_DLL_INIT_FAILED_LOGOFF
        case STATUS_DLL_INIT_FAILED_LOGOFF: msg = "DLL init failed logoff"; break;
        #endif
        default: msg = ""; break;
    }
    return msg;
}
int show_exceptionrecord(EXCEPTION_RECORD *ExceptionRecord, i32 level) {
    static void *  old_addr = NULL - 1;
    static int  called = 0;
    int     i;
    if(!ExceptionRecord) return -1;
    if((old_addr == ExceptionRecord->ExceptionAddress) || (called >= 10)) {
        // corrupted handler, it happened one time with compression 148
        // yeah I know that it's not a perfect solution
        TerminateProcess(GetCurrentProcess(), 9);
        Sleep(-1);  // it will be killed automatically
    }
    old_addr = ExceptionRecord->ExceptionAddress;
    called++;

    fprintf(stderr, "%.*s*EH* ExceptionCode      %08x %s\n", level * 4, "", (i32)ExceptionRecord->ExceptionCode, show_exception_code(ExceptionRecord->ExceptionCode));
    fprintf(stderr, "%.*s*EH* ExceptionFlags     %08x\n", level * 4, "", (i32)ExceptionRecord->ExceptionFlags);
    fprintf(stderr, "%.*s*EH* ExceptionAddress   %08x\n", level * 4, "", (i32)ExceptionRecord->ExceptionAddress);
    module_t *module;   // placed here in case of crashes
    module = scan_modules(NULL, GetCurrentProcessId(), NULL, NULL);
    if(module) {
        for(i = 0; module[i].addr; i++) {
            if((ExceptionRecord->ExceptionAddress >= module[i].addr) && (ExceptionRecord->ExceptionAddress < (module[i].addr + module[i].size))) {
                fprintf(stderr, "%.*s                        %p + %08x %s\n", level * 4, "", module[i].addr, (i32)(ExceptionRecord->ExceptionAddress - module[i].addr), module[i].szModule);
            }
        }
    }
    fprintf(stderr, "%.*s*EH* NumberParameters   %08x\n", level * 4, "", (i32)ExceptionRecord->NumberParameters);
    for(i = 0; i < ExceptionRecord->NumberParameters; i++) {
        fprintf(stderr, "%.*s*EH*                    %08x\n", level * 4, "", (i32)ExceptionRecord->ExceptionInformation[i]);
    }
    show_exceptionrecord(ExceptionRecord->ExceptionRecord, level + 1);
    return 0;
}
void exception_handler(EXCEPTION_POINTERS *ExceptionInfo) {
    if(ExceptionInfo && ExceptionInfo->ExceptionRecord && (ExceptionInfo->ExceptionRecord->ExceptionCode <= 0x7fffffff)) {
        return;
    }
    fprintf(stderr,
        "\n"
        "-------------------\n"
        "*EXCEPTION HANDLER*\n"
        "-------------------\n"
        "An error or crash occurred:\n"
        "\n"
    );
    if(ExceptionInfo) {
        show_exceptionrecord(ExceptionInfo->ExceptionRecord, 0);
        /* this hex dump is useless
        u8      *p;
        if(ExceptionInfo->ContextRecord) {
            // alpha, mips, x86, x86_64... show_dump is easier
            // skip the last zeroes to avoid too much data
            for(p = (u8 *)ExceptionInfo->ContextRecord + sizeof(CONTEXT) - sizeof(u32); p >= (u8 *)ExceptionInfo->ContextRecord; p -= sizeof(u32)) {
                if(((u32 *)p)[0]) break;
            }
            show_dump(2, (u8 *)ExceptionInfo->ContextRecord, (p + sizeof(u32)) - (u8 *)ExceptionInfo->ContextRecord /|*sizeof(CONTEXT)*|/, stderr);
        }
        */
        if(ExceptionInfo->ExceptionRecord && (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) && GetModuleHandle("HsSrv")) {
            fprintf(stderr,
                "\n"
                "Probably the crash has been caused by your Asus Xonar/Unixonar drivers.\n"
                "More information and details are available in quickbms.txt\n"
                "Some ways to fix the bug:\n"
                "- disable the GX mode (emulated EAX) of the Asus driver\n"
                "- disable the Asus HookSupport Manager application (HsMgr.exe)\n"
                "- start QuickBMS with the -9 option (create a link)\n"
                "- contact Asus! :)\n"
                "\n");
        }


        // backtrace part
        #ifndef DISABLE_BACKTRACE
        struct output_buffer ob;
        output_init(&ob, g_backtrace_output, BACKTRACE_BUFFER_MAX);

        if (!SymInitialize(GetCurrentProcess(), 0, TRUE)) {
            output_print(&ob,"Failed to init symbol context\n");
        }
        else {
            bfd_init();
            struct bfd_set *set = calloc(1,sizeof(*set));
            _backtrace(&ob , set , 128 , ExceptionInfo->ContextRecord);
            release_set(set);

            SymCleanup(GetCurrentProcess());
        }

        fputs("\n*EH* Stack Trace:\n", stderr);
        fputs(g_backtrace_output , stderr);
        #endif
    }

    if(!g_quickbms_exception_test && XDBG_ALLOC_ACTIVE && g_is_gui) {

        // the problem is caused by some programs that read the memory of the other processes
        // when GetOpenFileName is called but they are so dumb to read the data before the
        // allocated memory or the blocks tagged as PAGE_NOACCESS or PAGE_GUARD.

        printf(
            "\n"
            "\n"
            "It seems you have some program running on your system that doesn't allow\n"
            "QuickBMS to run because it reads invalid zones of the memory of this process.\n"
            "This is usually caused by Xonar drivers or some Nvidia software with special\n"
            "options enabled and maybe also some antivirus software.\n"
            "\n"
            "You can bypass the problem by launching QuickBMS with the -9 option by\n"
            "creating a link to quickbms.exe or simply by answering to the following\n"
            "question:\n"
            "\n"
            "- Do you want to launch QuickBMS with the -9 option? (y/N)\n"
            "  ");
        if(get_yesno(NULL) == 'y') {
            // spawnv note: do not enable this (don't know why but doesn't work if you specify the folder): copycut_folder(NULL, g_quickbms_arg0);
            char    *myargv[g_quickbms_argc + 2 + 1]; // 2 = -9 -G
            int32   i, arg, do_9=1, do_G=1;
            i = 0;
            for(arg = 0; arg < g_quickbms_argc; arg++) {
                if(!strcmp(g_quickbms_argv[arg], "-9")) do_9 = 0;
                if(!strcmp(g_quickbms_argv[arg], "-G")) do_G = 0;
            }
            for(arg = 0; arg < g_quickbms_argc; arg++) {
                myargv[i++] = g_quickbms_argv[arg];
                if(!arg) {
                    if(do_9) myargv[i++] = "-9";
                    if(do_G) if(g_is_gui == 2) myargv[i++] = "-G";   // auto enabled gui mode, we need to consider that the user used -G in his command-line
                }
            }
            myargv[i]   = NULL;
            printf("\n\n\n");
            spawnv(P_NOWAITO, g_quickbms_arg0, (void *)myargv);
            exit(QUICKBMS_ERROR_UNKNOWN);   // yeah, no myexit() because we don't need to wait
        }
    }

    myexit(QUICKBMS_ERROR_UNKNOWN);
}
LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS *ExceptionInfo) {
    exception_handler(ExceptionInfo);
    return EXCEPTION_CONTINUE_SEARCH;
}
LONG WINAPI UnhandledException(EXCEPTION_POINTERS *ExceptionInfo) {
    exception_handler(ExceptionInfo);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif



i32 main(i32 argc, char *argv[]) {
    static u8   filedir[PATHSZ + 1] = ".",  // don't waste the stack
                bckdir[PATHSZ + 1]  = ".";
    files_t *files          = NULL;
    FILE    *fds,
            *pre_fd;
    time_t  benchmark       = 0;
    int     i,
            t,
            argi,
            cmd,
            curr_file       = 0,
            wcx_plugin      = 0,
            update          = 0,
            quickbms_outname = 0,
            fname_multi_select = 0,
            embed_mode      = 0;
    u8      options_db[256],
            *newdir,
            *bms,
            *fname,
            *fdir           = ".",
            *p,
            *tmp,
            *pre_script     = NULL,
            *listfile       = NULL,
            *filter_files_tmp = NULL,
            *filter_in_files_tmp = NULL;
    int     quickbms_args   = 0;
    u8      **quickbms_arg  = NULL;

    #include "quickbms_ver.h"
    sprintf(VER, "%d.%d.%d%c", QUICKBMS_VER);

#ifdef WIN32
    // useful moreover in future
    g_osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&g_osver);

    if(!winapi_missing()) {
        // disabled because it may cause problems with Win8.1
        //SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

        //don't enable: if(_AddVectoredContinueHandler) _AddVectoredContinueHandler(1, VectoredHandler);

        // my original solution
        #ifndef DISABLE_BACKTRACE
        g_backtrace_output = calloc(BACKTRACE_BUFFER_MAX, 1);
        #endif
        //if(_AddVectoredExceptionHandler) _AddVectoredExceptionHandler(1, VectoredHandler);
        SetUnhandledExceptionFilter(UnhandledException);
    }
#endif

    //setbuf(stdout, NULL); // disabled because it's too slow with many files
    //setbuf(stderr, NULL); // disabled because it's slow with may Print commands

    fflush(stdin);  // useless?
    #ifdef O_BINARY
    setmode(fileno(stdin), O_BINARY);
    //setmode(fileno(stdout), O_BINARY);
    #endif

    srand(time(NULL));

    set_codepage();

    //xdbg_alloc_extreme();

    fprintf(stderr,
        "\n"
        "QuickBMS generic files extractor and reimporter %s"
#ifdef QUICKBMS64
        " (64bit test)"
#endif
        "\n"
        "by Luigi Auriemma\n"
        "e-mail: me@aluigi.org\n"
        "web:    aluigi.org\n"
        "        (" __DATE__ " - " __TIME__ ")\n"
        "\n"
        "                   quickbms.aluigi.org  Homepage\n"
        "                            zenhax.com  ZenHAX Forum\n"
        "                               @zenhax  Twitter & Scripts\n"
        //"                       @luigi_auriemma  aluigi Twitter\n"
        "\n",
        VER);

#ifdef WIN32
    DWORD   r;
    r = GetModuleFileName(NULL, g_quickbms_arg0, PATHSZ);
    if(!r || (r >= PATHSZ))
#endif
        mystrcpy(g_quickbms_arg0, argv[0], PATHSZ);
    g_quickbms_argc = argc;
    g_quickbms_argv = argv;

#ifdef WIN32
    int check_if_running_from_doubleclick(void) {
        // -1 = error
        // 0  = console
        // 1  = gui/double-click

        if(g_osver.dwMajorVersion > 4) {
            // this method is very easy and works well, tested on XP/2003/win7/win8
            // doesn't work with win98
            #ifndef GWL_WNDPROC
                #define GWL_WNDPROC -4
            #endif
            if(GetWindowLong(GetForegroundWindow(), GWL_WNDPROC)) {
                return 1;
            }
            return 0;
        }

        // for Win98 only
        int     ret = -1;
        DWORD pid = GetCurrentProcessId();
        if(pid) {
            HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if(h != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32  pe, pp;
                pe.dwSize = sizeof(PROCESSENTRY32);
                if(Process32First(h, &pe)) { do {
                    if(pe.th32ProcessID == pid) {
                        pp.dwSize = sizeof(PROCESSENTRY32);
                        if(Process32First(h, &pp)) { do {
                            if(pp.th32ProcessID == pe.th32ParentProcessID) {
                                     if(!stricmp(get_filename(pp.szExeFile), "winoa386.mod")) ret = 0;
                                else if(!stricmp(get_filename(pp.szExeFile), "cmd.exe"))      ret = 0;
                                else ret = 1;    // found but no command.com, so it's probably explorer.exe
                                break;
                            }
                        } while(Process32Next(h, &pp)); }
                        break;
                    }
                } while(Process32Next(h, &pe)); }
                CloseHandle(h);
            }
        }
        return ret;
    }

    // necessary to handle the GUI and the secure memory
    // before the execption handler that may be used
    // in some situations on Win8.1 and bugged software

    for(i = 1; i < argc; i++) {
        if(verbose_options(argv[i]) < 0) break;
        switch(argv[i][1]) {
            case 'f': i++;  break;
            case 'F': i++;  break;
            case 'L': i++;  break;
            case 'a': i++;  break;
            case 's': i++;  break;
            case 'S': i++;  break;
            case 'O': i++;  break;
            case 'M': i++;  break;
            case 'P': i++;  break;
            //
            case 'G': g_is_gui = !g_is_gui; break;
            case '9': XDBG_ALLOC_ACTIVE = !XDBG_ALLOC_ACTIVE; break;
            default: break;
        }
    }
    argi = i;

    if(check_if_running_from_doubleclick() == 1) g_is_gui = 2;

    if(g_is_gui) {

        g_quickbms_exception_test = 0;

        i = argi;
        if(i > argc) i = argc;
        i = 3 - (argc - i);
        if(i > 0) {
            fprintf(stderr,
                "- GUI mode activated, remember that the tool works also from command-line\n"
                "  where are available various options like folder scanning, filters and so on\n"
                "\n");
            p = calloc(argc + i + 1, sizeof(char *));
            if(!p) STD_ERR(QUICKBMS_ERROR_MEMORY);
            memcpy(p, argv, sizeof(char *) * argc);
            argv = (void *)p;
            argc -= (3 - i);

            static const char embedded_script_check[] = "SET THIS BYTE X TO 0x00 FOR EMBEDDING YOUR SCRIPT INTO QUICKBMS.EXE";
            // stristr embedded_script_check is needed to avoid compiler optimizations
            if(
                !stristr(embedded_script_check, "embed")    // this is the only choice to avoid false positives
            // || !stristr(get_basename(g_quickbms_arg0, "quickbms")) // commented out because some modders may rename quickbms but are not aware of this feature
            ) {  
                argv[argc] = mystrdup_simple(g_quickbms_arg0);
                i--;
                embed_mode = 1;
                printf(
                    "\n"
                    "    ### EMBEDDED SCRIPT MODE ACTIVATED ###\n"
                    "    This copy of QuickBMS is distributed with an embedded script.\n"
                    "\n");
            }

            if(i >= 3)   argv[argc]     = get_file("select the BMS script to use", 1, 0);
            if(i >= 2) { argv[argc + 1] = get_file("select the input archives/files to extract, type * or \"\" for whole folder and subfolders", 0, fname_multi_select = 1); }
            if(i >= 1)   argv[argc + 2] = get_folder("select the output folder where extracting the files");
            argc += 3;
        }
    }
#endif

    g_quickbms_exception_test = 1;

    if(argc < 3) {
        if((argc >= 2) && (argv[1][1] == 'c')) {
            quick_bms_list();

        } else if((argc >= 2) && (argv[1][1] == 'u')) {
            quickbms_update();

        } else if((argc >= 2) && !stricmp(argv[1], "--version")) {
            printf(
                "%s"
#ifdef QUICKBMS64
                " (64bit test)"
#endif
                "\n", VER);

        } else {
            myhelp(g_quickbms_arg0);
        }
        myexit(QUICKBMS_ERROR_ARGUMENTS);
    }

    memset(options_db, 0, sizeof(options_db));
    for(i = 1; i < argc; i++) {
        if(verbose_options(argv[i]) < 0) {
            if((i + 3) >= argc) break;
            fprintf(stderr, "\nError: wrong command-line argument (%s)\n", argv[i]);
            myexit(QUICKBMS_ERROR_ARGUMENTS);
        }
        options_db[(u8)argv[i][1]]++;
        switch(argv[i][1]) {
            case '-':
            case '?':
            case 'h': myhelp(g_quickbms_arg0);  myexit(QUICKBMS_ERROR_ARGUMENTS);   break;
            case 'c': quick_bms_list(); myexit(QUICKBMS_ERROR_ARGUMENTS);       break;
            case 'l': g_list_only               = 1;                            break;
            case 'f': append_list(&filter_files_tmp,    argv[++i]);             break;
            case 'F': append_list(&filter_in_files_tmp, argv[++i]);             break;
            case 'o': g_force_overwrite         = 1;                            break;
            case 'k': g_force_overwrite         = -1;                           break;
            case 'K': g_force_rename            = -1;                           break;
            case 'v': g_verbose                 = 1; dump_cmdline(argc, argv);  break;
            case 'V': g_verbose                 = -1;                           break;
            case 'L': listfile                  = mystrdup_simple(argv[++i]);   break;
            case 'R': g_quick_gui_exit          = 1;                            break;  // internal usage for external programs
            case 'x': g_decimal_notation        = 0;                            break;
            case 'w': g_write_mode              = 1;                            break;
            case 'a':
                quickbms_arg = realloc(quickbms_arg, (quickbms_args + 1) * sizeof(char *));
                if(!quickbms_arg) myexit(QUICKBMS_ERROR_MEMORY);
                quickbms_arg[quickbms_args] = mystrdup_simple(argv[++i]);
                quickbms_args++;
                break;
            case 'd': quickbms_outname          = 1;                            break;
            case 'D': quickbms_outname          = -1;                           break;
            case 'E': g_endian_killer           = 1;                            break;
            case '0': g_void_dump               = 1;                            break;
            case 'r': g_reimport                = 1;                            break;
            case 'n': enable_sockets            = 1;                            break;
            case 'p': enable_process            = 1;                            break;
            case 'A': enable_audio              = 1;                            break;
            case 'g': enable_video              = 1;                            break;
            case 'm': enable_winmsg             = 1;                            break;
            case 'C': enable_calldll            = 1;                            break;
            case 'H': g_enable_hexhtml          = -1;                           break;
            case 'X': g_enable_hexhtml = -1; hexhtml_output = HEXHTML_CONSOLE;  break;
            case 's': pre_script                = mystrdup_simple(argv[++i]);   break;
            case 'u': update                    = 1;                            break;
            case '.': g_continue_anyway         = 1;                            break;
            case '9': break;    // already handled! XDBG_ALLOC_ACTIVE     = !XDBG_ALLOC_ACTIVE;           break;  // xdbg_toggle() is not ready yet
            case '8': XDBG_ALLOC_INDEX          = !XDBG_ALLOC_INDEX;            break;
            case '7': XDBG_ALLOC_VERBOSE        = !XDBG_ALLOC_VERBOSE;          break;
            case '6': XDBG_HEAPVALIDATE         = !XDBG_HEAPVALIDATE;           break;
            case 'S': g_quickbms_execute_file   = mystrdup_simple(argv[++i]);   break;
            case 'Y': g_yes                     = 1;                            break;
            case '3': g_int3                    = 1;                            break;
            case 'O':
                g_force_output = mystrdup_simple(argv[++i]);
                if(!strcmp(g_force_output, "-")) {
                    fclose(stdout); // avoid mix of stdout
                }
                break;
            case 'G': break;    // already handled! g_is_gui              = !g_is_gui;                    break;
            case 'I': g_insensitive             = !g_insensitive;               break;
            case 'M': g_compare_folder          = mystrdup_simple(argv[++i]);   break;
            case 'q': g_quiet                   = 1;                            break;
            case 'Q':
                g_quiet         = -1;
                real_printf     = fake_printf;
                real_fprintf    = fake_fprintf;
                break;
            case 'i': g_quickiso                = calloc(1, sizeof(quickiso_ctx_t)); break;
            case 'z': g_quickzip                = calloc(1, sizeof(quickzip_ctx_t)); break;
            case 'Z': g_reimport_zero           = !g_reimport_zero;             break;
            case 'P':
                i++;
                set_g_codepage(argv[i], atoi(argv[i]));
                g_codepage_default = g_codepage;
                break;
            case 'T': g_keep_temporary_file     = !g_keep_temporary_file;       break;
            // remember to add the options with arguments to the list above
            default: {
                fprintf(stderr, "\nError: wrong command-line argument (%s)\n", argv[i]);
                myexit(QUICKBMS_ERROR_ARGUMENTS);
            }
        }
    }

    if(update) quickbms_update();

    if(g_reimport) {
        fprintf(stderr, "- REIMPORT mode enabled!\n");
        fprintf(stderr, "  - remember to select the SAME script, file and folder you selected during\n"
                        "    the previous extraction\n");
        fprintf(stderr, "  - it's highly suggested to leave only the edited files in the folder, it's\n"
                        "    faster and less prone to errors with compressed files\n");
    }

    bms   = argv[i++];
    fname = argv[i++];
    if(i < argc) fdir = argv[i++];

    if(!bms || !fname || !fdir) {
        fprintf(stderr, "\n"
            "Error: you missed one or more arguments:\n"
            "       - bms:   %s\n"
            "       - fname: %s\n"
            "       - fdir:  %s\n"
            "\n",
            bms, fname, fdir);
        myexit(QUICKBMS_ERROR_ARGUMENTS);
    }

    if(bms)   bms   = mystrdup_simple(bms);
    if(fname) {
        if(fname_multi_select) {
            fname = malloc_copy(NULL, fname, MULTI_PATHSZ);
        } else {
            fname = mystrdup_simple(fname);
        }
    }
    if(fdir) fdir = mystrdup_simple(fdir);

    // useful for get_file on Windows7 where it's used '*' to work
    p = strrchr(fname, '*');
    if(!p) p = strristr(fname, "{}");
    if(p) {
        p = mystrrchrs(fname, PATH_DELIMITERS);
        if(p) p++;
        else  p = fname;
        append_list(&filter_in_files_tmp, p);
        while(*p) *p++ = 0; // necessary
    }
    for(p = fname + strlen(fname) - 1; p >= (fname + 1) /* leave / or \ on fname[0] */; p--) {
        if(!strchr(PATH_DELIMITERS "* ", *p)) break;
        *p = 0;
    }
    if((p >= fname) && (*p == ':')) {
        p[1] = '\\';
        p[2] = 0;
    }

    // fix and build filters

    g_filter_files    = build_filter(filter_files_tmp);
    FREE(filter_files_tmp)

    g_filter_in_files = build_filter(filter_in_files_tmp);
    FREE(filter_in_files_tmp)

    g_temp_folder[0] = 0;
#ifdef WIN32
    GetTempPath(sizeof(g_temp_folder), g_temp_folder);
#endif
    if(!g_temp_folder[0]) {
        p = getenv ("TMP");
        if(!p) p = getenv ("TEMP");
        if(!p) p = getenv ("TMPDIR");
#ifdef WIN32
        if(!p) p = "c:\\windows\\temp";
#else
        if(!p) p = "/tmp";
#endif
        mystrcpy(g_temp_folder, p, PATHSZ);
    }

    if(!xgetcwd(g_current_folder, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);

    if(g_compare_folder) {
        if(xchdir(g_compare_folder) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
        g_compare_folder = calloc(PATHSZ + 1, 1);
        if(!g_compare_folder) STD_ERR(QUICKBMS_ERROR_MEMORY);
        if(!xgetcwd(g_compare_folder, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
        if(xchdir(g_current_folder) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }

    g_output_folder = fdir;
    if(!xchdir(g_output_folder)) { // ???
        g_output_folder = calloc(PATHSZ + 1, 1);
        if(!g_output_folder) STD_ERR(QUICKBMS_ERROR_MEMORY);
        if(!xgetcwd(g_output_folder, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
        if(xchdir(g_current_folder) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }

    if(g_compare_folder && !stricmp(g_compare_folder, g_output_folder)) {
        fprintf(stderr,
            "\n"
            "Error: the compare/merge folder specified with -M is the same of the output folder\n"
            "       %s\n", g_compare_folder);
        myexit(QUICKBMS_ERROR_FOLDER);
    }

    copycut_folder(fname, g_file_folder); // this is ok also with windows multifile
    if(!g_file_folder[0]) {
        if(!xgetcwd(g_file_folder, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }

    /* problems with multifile, do NOT USE the following!
    if(!xchdir(g_file_folder)) {   // ???
        if(!xgetcwd(g_file_folder, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
        if(xchdir(g_current_folder) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
        p = get_filename(fname);
        fname = malloc(strlen(g_file_folder) + 1 + strlen(p) + 1);
        if(!fname) STD_ERR(QUICKBMS_ERROR_MEMORY);
        sprintf(fname, "%s%c%s", g_file_folder, PATHSLASH, p);
    }
    */

    bms_init(0);

    get_main_path(NULL, g_quickbms_arg0, g_exe_folder);
    if(!g_exe_folder[0]) {
        if(!xgetcwd(g_exe_folder, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }

    // the following is used only for calldll so it's not much important
    if(strchr(bms, ':') || (bms[0] == '/') || (bms[0] == '\\')) {   // almost absolute path
        g_bms_folder[0] = 0;
    } else {
        mystrcpy(g_bms_folder, g_current_folder, PATHSZ);
    }
    mystrcpy(g_bms_folder + strlen(g_bms_folder), bms, PATHSZ - strlen(g_bms_folder));
    mystrcpy(g_bms_script, g_bms_folder, PATHSZ);
    copycut_folder(NULL, g_bms_folder);

    newdir = NULL;
#ifdef WIN32
    if(g_is_gui && fname[strlen(fname) + 1]) { // check if there are files after the folder
        newdir = fname;
        if(!xgetcwd(bckdir, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
        if(xchdir(newdir) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
        for(p = fname;;) {
            p += strlen(p) + 1;
            if(!*p) break;
            add_files(p, 0, NULL);
        }
    } else
#endif

    if(check_is_dir(fname)) {
        mystrcpy(g_file_folder, fname, PATHSZ);
        newdir = fname;
        fprintf(stderr, "- start the scanning of the input folder: %s\n", newdir);
        if(!xgetcwd(bckdir, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
        if(xchdir(newdir) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
        strcpy(filedir, ".");
        recursive_dir(filedir, PATHSZ);
    }
    // if one of the above was done finish the job
    if(newdir) {
        files = add_files(NULL, 0, &g_input_total_files);
        curr_file = 0;
        if(g_input_total_files <= 0) {
            fprintf(stderr,
                "\n"
                "Error: the input folder is empty\n"
                "       %s\n", newdir);
            myexit(QUICKBMS_ERROR_FOLDER);
        }
        if(xchdir(bckdir) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }

    p = strchr(g_current_folder, ':');  if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(g_bms_folder, ':');      if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(g_exe_folder, ':');      if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(g_file_folder, ':');     if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(g_output_folder, ':');   if(p && !p[1]) strcpy(p + 1, "\\");

    // boring stuff for having a full g_file_folder, maybe this one is the good time
    tmp = calloc(PATHSZ + 1, 1);
    if(!tmp) STD_ERR(QUICKBMS_ERROR_MEMORY);
    if(!xgetcwd(tmp, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
    if(xchdir(g_current_folder) >= 0) {
        if(xchdir(g_file_folder) >= 0) {
            if(!xgetcwd(g_file_folder, PATHSZ)) STD_ERR(QUICKBMS_ERROR_FOLDER);
        }
        if(xchdir(tmp) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }
    FREE(tmp);

    if(g_verbose) {
        fprintf(stderr, "- current_folder: %s\n", g_current_folder);
        fprintf(stderr, "- bms_folder:     %s\n", g_bms_folder);
        fprintf(stderr, "- exe_folder:     %s\n", g_exe_folder);
        fprintf(stderr, "- file_folder:    %s\n", g_file_folder);
        fprintf(stderr, "- output_folder:  %s\n", g_output_folder);
        fprintf(stderr, "- temp_folder:    %s\n", g_temp_folder);
    }

    for(i = 0; i < quickbms_args; i++) {
        set_quickbms_arg(quickbms_arg[i]);
    }

    if(check_extension(bms, "wcx")) wcx_plugin = 1;

redo:
    benchmark = time(NULL);
    if(files) {
        fname = files[curr_file].name;
        curr_file++;
        if(xchdir(bckdir) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
        if(xchdir(newdir) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }
    if(wcx_plugin) {
        if(wcx(NULL, fname) < 0) STD_ERR(QUICKBMS_ERROR_EXTRA);
    } else {
        fdnum_open(fname, 0, 1);
    }
    if(files) {
        if(xchdir(bckdir) < 0) STD_ERR(QUICKBMS_ERROR_FOLDER);
    }

    if(wcx_plugin) {
        fprintf(stderr, "- open WCX plugin %s\n", bms);
        if(wcx(bms, fname) < 0) STD_ERR(QUICKBMS_ERROR_EXTRA);
    } else {
        fprintf(stderr, "- open script %s\n", bms);
        if(!bms[0]) {
            fds = NULL;
        } else if(!strcmp(bms, "-")) {
            fds = stdin;
        } else {
            fds = xfopen(bms, "rb");
            if(!fds) STD_ERR(QUICKBMS_ERROR_FILE_READ);
            if(embed_mode) {
                fseek(fds, -1, SEEK_END);
                for(;;) {
                    t = fgetc(fds);
                    if(t < 0) break;    // error
                    if(!t) break;
                    if(fseek(fds, -2, SEEK_CUR) < 0) break;
                }
                printf("- embedded script found at offset %08x\n", (i32)ftell(fds));
            }
        }
        cmd = 0;
        if(pre_script) {
            p = quickbms_path_open(pre_script);
            pre_fd = xfopen(p, "rb");
            FREE(p);
            if(pre_fd) {
                cmd = parse_bms(pre_fd, NULL, cmd, 0);
                FCLOSE(pre_fd);
            } else {
                cmd = parse_bms(NULL, pre_script, cmd, 1);
            }
        }
        if(fds) {
            cmd = parse_bms(fds, NULL, cmd, 0);
            /*if(fds != stdin)*/ FCLOSE(fds);
        }
    }

    if(listfile && !g_listfd) {
        g_listfd = xfopen(listfile, "wb");
        if(!g_listfd) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);
    }

    if(g_list_only) {
    //} else if(g_void_dump) {
    } else {
        if(/*!g_list_only &&*/ fdir && fdir[0] /* && strcmp(fdir, ".")*/) {
            fprintf(stderr, "- set output folder %s\n", fdir);
            if(xchdir(fdir) < 0) {
                fprintf(stderr, "- the folder doesn't exist, do you want to create it (y/N)?:\n  ");
                if(get_yesno(NULL) != 'y') STD_ERR(QUICKBMS_ERROR_USER);
                fdir = create_dir(fdir, 1, 1, 1, 0);   // fdir must remain modified
                if(!fdir) STD_ERR(QUICKBMS_ERROR_FOLDER);
            }
            if(quickbms_outname) {
                p = fname;
                if(!files || (g_input_total_files <= 1)) {
                    p = get_filename(p);    // take only the name of the file instead of the whole path
                }
                tmp = mystrdup_simple(p);   // don't change fname

                fix_my_d_option(tmp, NULL); // compare file path and output path

                if(!create_dir(tmp, 1, 1, (quickbms_outname > 0) ? 1 : 0, 1)) STD_ERR(QUICKBMS_ERROR_FOLDER);
                FREE(tmp)
            }
        }
    }

    if(!g_list_only && !g_void_dump) {
        // reimport mode doesn't work with the alternative outputs like ISO
        if(g_reimport) {
            FREE(g_quickiso);
            FREE(g_quickzip);
        }
        // open the outputs here
        u8      iso_fname[260 + 1];
        if(g_quickiso && g_quickzip) {
            fprintf(stderr, "\nError: you can't specify the -i and -z options together\n");
            STD_ERR(QUICKBMS_ERROR_USER);
        }
        quickbms_archive_output_open(iso)
        quickbms_archive_output_open(zip)
    }

    set_console_title(options_db, bms, fname);

    fprintf(stderr, "\n"
        "  %-*s filesize   filename\n"
        "--------------------------------------\n",
        sizeof(int) * 2, "offset");

    if(wcx_plugin) {
        wcx(NULL, NULL);
    } else {
        start_bms(-1, 0, 0, NULL, NULL, NULL, NULL);
    }

    benchmark = time(NULL) - benchmark;
    if(g_reimport) {
        fprintf(stderr, "\n- %"PRId" files reimported in %d seconds\n", g_reimported_files, (i32)benchmark);
    } else {
        fprintf(stderr, "\n- %"PRId" files found in %d seconds\n", g_extracted_files, (i32)benchmark);
    }

    if(files && (curr_file < g_input_total_files)) {
        bms_init(1);
        goto redo;
    }

    bms_finish();
    /*if(g_listfd)*/ FCLOSE(g_listfd);
    myexit(QUICKBMS_OK);
    return(QUICKBMS_OK);
}

