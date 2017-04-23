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
// QuickBMS enum, defines, global variables and so on

enum {
    QUICKBMS_OK                 = 0,    // success
    QUICKBMS_ERROR_UNKNOWN      = 1,    // any error
    QUICKBMS_ERROR_MEMORY       = 2,    // unable to allocate memory, memory errors
    QUICKBMS_ERROR_FILE_READ    = 3,    // impossible to read/seek input file
    QUICKBMS_ERROR_FILE_WRITE   = 4,    // impossible to write output file
    QUICKBMS_ERROR_COMPRESSION  = 5,    // errors related to file compression
    QUICKBMS_ERROR_ENCRYPTION   = 6,    // errors related to file encryption
    QUICKBMS_ERROR_DLL          = 7,    // any external dll or executable
    QUICKBMS_ERROR_BMS          = 8,    // anything related the BMS script and language
    QUICKBMS_ERROR_ARGUMENTS    = 9,    // quickbms arguments (argc, argv)
    QUICKBMS_ERROR_FOLDER       = 10,   // problems with the input/output folders
    QUICKBMS_ERROR_USER         = 11,   // termination caused by the user
    QUICKBMS_ERROR_EXTRA        = 12,   // extra IO input/output
    QUICKBMS_ERROR_UPDATE       = 13,   // update feature
    //
    QUICKBMS_ERROR_DUMMY
};



enum {
    CMD_NONE = 0,
    CMD_CLog,
    CMD_Do,
    CMD_FindLoc,
    CMD_For,
    CMD_ForTo,  // for an easy handling of For
    CMD_Get,
    CMD_GetDString,
    CMD_GoTo,
    CMD_IDString,
    CMD_ImpType,
    CMD_Log,
    CMD_Math,
    CMD_Next,
    CMD_Open,
    CMD_SavePos,
    CMD_Set,
    CMD_While,
    CMD_String,
    CMD_CleanExit,
    CMD_If,
    CMD_Else,
    CMD_Elif,   // added by me
    CMD_EndIf,
    CMD_GetCT,
    CMD_ComType,
    CMD_ReverseLong,
        // added by me
    CMD_Endian,
    CMD_FileXOR,        // similar job done also by Encryption
    CMD_FileRot13,      // similar job done also by Encryption
    CMD_FileCrypt,      // experimental and useless
    CMD_Break,
    CMD_Strlen,         // not necessary (implemented in Set)
    CMD_GetVarChr,
    CMD_PutVarChr,
    CMD_Debug,          // only for debugging like -v, so not necessary
    CMD_Padding,        // useful but not necessary, can be done with GoTo
    CMD_Append,
    CMD_Encryption,
    CMD_Print,
    CMD_GetArray,
    CMD_PutArray,
    CMD_SortArray,
    CMD_StartFunction,
    CMD_CallFunction,
    CMD_EndFunction,
    CMD_ScanDir,        // not needed for the extraction jobs
    CMD_CallDLL,
    CMD_Put,            // not needed for the extraction jobs
    CMD_PutDString,     // not needed for the extraction jobs
    CMD_PutCT,          // not needed for the extraction jobs
    CMD_GetBits,        // rarely useful
    CMD_PutBits,        // rarely useful
    CMD_ReverseShort,   // rarely useful
    CMD_ReverseLongLong,// rarely useful
    CMD_Prev,           // like i--
    CMD_XMath,          // one line math
    CMD_NameCRC,        // name hashing
    CMD_Codepage,
    CMD_SLog,
    CMD_Continue,
    CMD_Label,
    CMD_If_Return,      // internal usage
    CMD_NOP
};



#define ISNUMTYPE(X)    ((X > 0) || (X == BMS_TYPE_ASIZE))
enum {  // the value is referred to their size which makes the job faster, numbers are positive and the others are negative!
    BMS_TYPE_NONE               = 0,
    BMS_TYPE_BYTE               = 1,
    BMS_TYPE_SHORT              = 2,
    BMS_TYPE_THREEBYTE          = 3,
    BMS_TYPE_LONG               = 4,
    BMS_TYPE_LONGLONG           = 8,
    BMS_TYPE_STRING             = -1,
    BMS_TYPE_ASIZE              = -2,
    BMS_TYPE_PURETEXT           = -3,
    BMS_TYPE_PURENUMBER         = -4,
    BMS_TYPE_TEXTORNUMBER       = -5,
    BMS_TYPE_FILENUMBER         = -6,
        // added by me
    BMS_TYPE_FILENAME           = -1000,
    BMS_TYPE_BASENAME           = -1001,
    BMS_TYPE_EXTENSION          = -1002,
    BMS_TYPE_UNICODE            = -1003,
    BMS_TYPE_BINARY             = -1004,
    BMS_TYPE_LINE               = -1005,
    BMS_TYPE_FULLNAME           = -1006,
    BMS_TYPE_CURRENT_FOLDER     = -1007,
    BMS_TYPE_FILE_FOLDER        = -1008,
    BMS_TYPE_INOUT_FOLDER       = -1009,
    BMS_TYPE_BMS_FOLDER         = -1010,
    BMS_TYPE_ALLOC              = -1011,
    BMS_TYPE_COMPRESSED         = -1012,
    BMS_TYPE_FLOAT              = -1013,
    BMS_TYPE_DOUBLE             = -1014,
    BMS_TYPE_LONGDOUBLE         = -1015,
    BMS_TYPE_VARIABLE           = -1016,    // c & 0x80
    BMS_TYPE_VARIABLE2          = -1017,    // unreal index numbers
    BMS_TYPE_VARIANT            = -1018,
    BMS_TYPE_BITS               = -1019,
    BMS_TYPE_TIME               = -1020,
    BMS_TYPE_TIME64             = -1021,
    BMS_TYPE_CLSID              = -1022,
    BMS_TYPE_IPV4               = -1023,
    BMS_TYPE_IPV6               = -1024,
    BMS_TYPE_ASM                = -1025,
    BMS_TYPE_VARIABLE3          = -1026,
    BMS_TYPE_SIGNED_BYTE        = -1027,
    BMS_TYPE_SIGNED_SHORT       = -1028,
    BMS_TYPE_SIGNED_THREEBYTE   = -1029,
    BMS_TYPE_SIGNED_LONG        = -1030,
    BMS_TYPE_VARIABLE4          = -1031,
    BMS_TYPE_VARIABLE5          = -1032,
    BMS_TYPE_FILEPATH           = -1033,
    BMS_TYPE_FULLBASENAME       = -1034,
    BMS_TYPE_TO_UNICODE         = -1035,
    BMS_TYPE_TCC                = -1036,
        //
    BMS_TYPE_UNKNOWN            = -2000,
        // nop
    BMS_TYPE_NOP
};



enum {
    APPEND_MODE_NONE = 0,
    APPEND_MODE_APPEND = 1,
    APPEND_MODE_OVERWRITE = 2,
    APPEND_MODE_BEFORE = -1
};












/*
if you add a new compression algorithm remember to modify the following files:
- defs.h
- cmd.c     -> CMD_ComType_func
- perform.c -> perform_compression
? file.c    -> reimport
*/

enum {  // note that the order must be not change due to the introduction of the scan feature
    COMP_NONE = 0,      // scan 0
    COMP_ZLIB,      /* RFC 1950 */
    COMP_DEFLATE,   /* RFC 1951 */
    COMP_LZO1,
    COMP_LZO1A,
    COMP_LZO1B,         // scan 5
    COMP_LZO1C,
    COMP_LZO1F,
    COMP_LZO1X,
    COMP_LZO1Y,
    COMP_LZO1Z,         // scan 10
    COMP_LZO2A,
    COMP_LZSS,
    COMP_LZX,
    COMP_GZIP,
    COMP_EXPLODE,       // scan 15
    COMP_LZMA,
    COMP_LZMA_86HEAD,
    COMP_LZMA_86DEC,
    COMP_LZMA_86DECHEAD,
    COMP_LZMA_EFS,      // scan 20
    COMP_BZIP2,
    COMP_XMEMLZX,
    COMP_HEX,
    COMP_BASE64,
    COMP_UUENCODE,      // scan 25
    COMP_ASCII85,
    COMP_YENC,
    COMP_UNLZW,
    COMP_UNLZWX,
    COMP_LZXCAB,        // scan 30
    COMP_LZXCHM,
    COMP_RLEW,
    COMP_LZJB,
    COMP_SFL_BLOCK,
    COMP_SFL_RLE,       // scan 35
    COMP_SFL_NULLS,
    COMP_SFL_BITS,
    COMP_LZMA2,
    COMP_LZMA2_86HEAD,
    COMP_LZMA2_86DEC,   // scan 40
    COMP_LZMA2_86DECHEAD,
    COMP_NRV2b,
    COMP_NRV2d,
    COMP_NRV2e,
    COMP_HUFFBOH,       // scan 45
    COMP_UNCOMPRESS,
    COMP_DMC,
    COMP_LZH,
    COMP_LZARI,
    COMP_TONY,          // scan 50
    COMP_RLE7,
    COMP_RLE0,
    COMP_RLE,
    COMP_RLEA,
    COMP_BPE,           // scan 55
    COMP_QUICKLZ,
    COMP_Q3HUFF,
    COMP_UNMENG,
    COMP_LZ2K,
    COMP_DARKSECTOR,    // scan 60
    COMP_MSZH,
    COMP_UN49G,
    COMP_UNTHANDOR,
    COMP_DOOMHUFF,
    COMP_APLIB,         // scan 65
    COMP_TZAR_LZSS,
    COMP_LZF,
    COMP_CLZ77,
    COMP_LZRW1,
    COMP_DHUFF,         // scan 70
    COMP_FIN,
    COMP_LZAH,
    COMP_LZH12,
    COMP_LZH13,
    COMP_GRZIP,         // scan 75
    COMP_CKRLE,
    COMP_QUAD,
    COMP_BALZ,
    COMP_DEFLATE64,
    COMP_SHRINK,        // scan 80
    COMP_PPMDI,
    COMP_MULTIBASE,
    COMP_BRIEFLZ,
    COMP_PAQ6,
    COMP_SHCODEC,       // scan 85
    COMP_HSTEST1,
    COMP_HSTEST2,
    COMP_SIXPACK,
    COMP_ASHFORD,
    COMP_JCALG,         // scan 90
    COMP_JAM,
    COMP_LZHLIB,
    COMP_SRANK,
    COMP_ZZIP,
    COMP_SCPACK,        // scan 95
    COMP_RLE3,
    COMP_BPE2,
    COMP_BCL_HUF,
    COMP_BCL_LZ,
    COMP_BCL_RICE,      // scan 100
    COMP_BCL_RLE,
    COMP_BCL_SF,
    COMP_SCZ,
    COMP_SZIP,
    COMP_PPMDI_RAW,     // scan 105
    COMP_PPMDG,
    COMP_PPMDG_RAW,
    COMP_PPMDJ,
    COMP_PPMDJ_RAW,
    COMP_SR3C,          // scan 110
    COMP_HUFFMANLIB,
    COMP_SFASTPACKER,
    COMP_SFASTPACKER2,
    COMP_DK2,
    COMP_LZ77WII,       // scan 115
    COMP_LZ77WII_RAW10,
    COMP_DARKSTONE,
    COMP_SFL_BLOCK_CHUNKED,
    COMP_YUKE_BPE,
    COMP_STALKER_LZA,   // scan 120
    COMP_PRS_8ING,
    COMP_PUYO_CNX,
    COMP_PUYO_CXLZ,
    COMP_PUYO_LZ00,
    COMP_PUYO_LZ01,     // scan 125
    COMP_PUYO_LZSS,
    COMP_PUYO_ONZ,
    COMP_PUYO_PRS,
    COMP_FALCOM,
    COMP_CPK,           // scan 130
    COMP_BZIP2_FILE,
    COMP_LZ77WII_RAW11,
    COMP_LZ77WII_RAW30,
    COMP_LZ77WII_RAW20,
    COMP_PGLZ,          // scan 135
    COMP_SLZ,
    COMP_SLZ_01,
    COMP_SLZ_02,
    COMP_LZHL,
    COMP_D3101,         // scan 140
    COMP_SQUEEZE,
    COMP_LZRW3,
    COMP_TDCB_ahuff,
    COMP_TDCB_arith,
    COMP_TDCB_arith1,   // scan 145
    COMP_TDCB_arith1e,
    COMP_TDCB_arithn,
    COMP_TDCB_compand,
    COMP_TDCB_huff,
    COMP_TDCB_lzss,     // scan 150
    COMP_TDCB_lzw12,
    COMP_TDCB_lzw15v,
    COMP_TDCB_silence,
    COMP_RDC,
    COMP_ILZR,          // scan 155
    COMP_DMC2,
    COMP_diffcomp,
    COMP_LZR,
    COMP_LZS,
    COMP_LZS_BIG,       // scan 160
    COMP_COPY,
    COMP_MOHLZSS,
    COMP_MOHRLE,
    COMP_YAZ0,
    COMP_BYTE2HEX,      // scan 165
    COMP_UN434A,
    COMP_UNZIP_DYNAMIC,
    COMP_XXENCODE,
    COMP_GZPACK,
    COMP_ZLIB_NOERROR,  // scan 170
    COMP_DEFLATE_NOERROR,
    COMP_PPMDH,
    COMP_PPMDH_RAW,
    COMP_RNC,
    COMP_RNC_RAW,       // scan 175
    COMP_FITD,
    COMP_KENS_Nemesis,
    COMP_KENS_Kosinski,
    COMP_KENS_Kosinski_moduled,
    COMP_KENS_Enigma,   // scan 180
    COMP_KENS_Saxman,
    COMP_DRAGONBALLZ,
    COMP_NITROSDK,
    COMP_ZDAEMON,
    COMP_SKULLTAG,      // scan 185
    COMP_MSF,
    COMP_STARGUNNER,
    COMP_NTCOMPRESS,
    COMP_CRLE,
    COMP_CTW,           // scan 190
    COMP_DACT_DELTA,
    COMP_DACT_MZLIB2,
    COMP_DACT_MZLIB,
    COMP_DACT_RLE,
    COMP_DACT_SNIBBLE,  // scan 195
    COMP_DACT_TEXT,
    COMP_DACT_TEXTRLE,
    COMP_EXECUTE,
    COMP_LZ77_0,
    COMP_LZBSS,         // scan 200
    COMP_BPAQ0,
    COMP_LZPX,
    COMP_MAR_RLE,
    COMP_GDCM_RLE,
    COMP_LZMAT,         // scan 205
    COMP_DICT,
    COMP_REP,
    COMP_LZP,
    COMP_ELIAS_DELTA,
    COMP_ELIAS_GAMMA,   // scan 210
    COMP_ELIAS_OMEGA,
    COMP_PACKBITS,
    COMP_DARKSECTOR_NOCHUNKS,
    COMP_ENET,
    COMP_EDUKE32,       // scan 215
    COMP_XU4_RLE,
    COMP_RVL,
    COMP_LZFU,
    COMP_LZFU_RAW,
    COMP_XU4_LZW,       // scan 220
    COMP_HE3,
    COMP_IRIS,
    COMP_IRIS_HUFFMAN,
    COMP_IRIS_UO_HUFFMAN,
    COMP_NTFS,          // scan 225
    COMP_PDB,
    COMP_COMPRLIB_SPREAD,
    COMP_COMPRLIB_RLE1,
    COMP_COMPRLIB_RLE2,
    COMP_COMPRLIB_RLE3, // scan 230
    COMP_COMPRLIB_RLE4,
    COMP_COMPRLIB_ARITH,
    COMP_COMPRLIB_SPLAY,
    COMP_CABEXTRACT,
    COMP_MRCI,          // scan 235
    COMP_HD2_01,
    COMP_HD2_08,
    COMP_HD2_01raw,
    COMP_RTL_LZNT1,
    COMP_RTL_XPRESS,    // scan 240
    COMP_RTL_XPRESS_HUFF,
    COMP_PRS,
    COMP_SEGA_LZ77,
    COMP_SAINT_SEYA,
    COMP_NTCOMPRESS30,  // scan 245
    COMP_NTCOMPRESS40,
    COMP_SLZ_03,
    COMP_YAKUZA,
    COMP_LZ4,
    COMP_SNAPPY,        // scan 250
    COMP_LUNAR_LZ1,
    COMP_LUNAR_LZ2,
    COMP_LUNAR_LZ3,
    COMP_LUNAR_LZ4,
    COMP_LUNAR_LZ5,     // scan 255
    COMP_LUNAR_LZ6,
    COMP_LUNAR_LZ7,
    COMP_LUNAR_LZ8,
    COMP_LUNAR_LZ9,
    COMP_LUNAR_LZ10,    // scan 260
    COMP_LUNAR_LZ11,
    COMP_LUNAR_LZ12,
    COMP_LUNAR_LZ13,
    COMP_LUNAR_LZ14,
    COMP_LUNAR_LZ15,    // scan 265
    COMP_LUNAR_LZ16,
    COMP_LUNAR_RLE1,
    COMP_LUNAR_RLE2,
    COMP_LUNAR_RLE3,
    COMP_LUNAR_RLE4,    // scan 270
    COMP_GOLDENSUN,
    COMP_LUMINOUSARC,
    COMP_LZV1,
    COMP_FASTLZAH,
    COMP_ZAX,           // scan 275
    COMP_SHRINKER,
    COMP_MMINI_HUFFMAN,
    COMP_MMINI_LZ1,
    COMP_MMINI,
    COMP_CLZW,          // scan 280
    COMP_LZHAM,
    COMP_LPAQ8,
    COMP_SEGA_LZS2,
    COMP_CALLDLL,
    COMP_WOLF,          // scan 285
    COMP_COREONLINE,
    COMP_MSZIP,
    COMP_QTM,
    COMP_MSLZSS,
    COMP_MSLZSS1,       // scan 290
    COMP_MSLZSS2,
    COMP_KWAJ,
    COMP_LZLIB,
    COMP_DFLT,
    COMP_LZMA_DYNAMIC,  // scan 295
    COMP_LZMA2_DYNAMIC,
    COMP_LZMA2_EFS,
    COMP_LZXCAB_DELTA,
    COMP_LZXCHM_DELTA,
    COMP_FFCE,          // scan 300
    COMP_SCUMMVM4,
    COMP_SCUMMVM5,
    COMP_SCUMMVM6,
    COMP_SCUMMVM7,
    COMP_SCUMMVM8,      // scan 305
    COMP_SCUMMVM9,
    COMP_SCUMMVM10,
    COMP_SCUMMVM11,
    COMP_SCUMMVM12,
    COMP_SCUMMVM13,     // scan 310
    COMP_SCUMMVM14,
    COMP_SCUMMVM15,
    COMP_SCUMMVM16,
    COMP_SCUMMVM17,
    COMP_SCUMMVM18,     // scan 315
    COMP_SCUMMVM19,
    COMP_SCUMMVM20,
    COMP_SCUMMVM21,
    COMP_SCUMMVM22,
    COMP_SCUMMVM23,     // scan 320
    COMP_SCUMMVM24,
    COMP_SCUMMVM25,
    COMP_SCUMMVM26,
    COMP_SCUMMVM27,
    COMP_SCUMMVM28,     // scan 325
    COMP_SCUMMVM29,
    COMP_SCUMMVM30,
    COMP_SCUMMVM31,
    COMP_SCUMMVM32,
    COMP_SCUMMVM33,     // scan 330
    COMP_SCUMMVM34,
    COMP_SCUMMVM35,
    COMP_SCUMMVM36,
    COMP_SCUMMVM37,
    COMP_SCUMMVM38,     // scan 335
    COMP_SCUMMVM39,
    COMP_SCUMMVM40,
    COMP_SCUMMVM41,
    COMP_SCUMMVM42,
    COMP_SCUMMVM43,     // scan 340
    COMP_SCUMMVM44,
    COMP_SCUMMVM45,
    COMP_SCUMMVM46,
    COMP_SCUMMVM47,
    COMP_SCUMMVM48,     // scan 345
    COMP_SCUMMVM49,
    COMP_SCUMMVM50,
    COMP_SCUMMVM51,
    COMP_SCUMMVM52,
    COMP_SCUMMVM53,     // scan 350
    COMP_LZS_UNZIP,
    COMP_LEGEND_OF_MANA,
    COMP_DIZZY,
    COMP_EDL1,
    COMP_EDL2,          // scan 355
    COMP_DUNGEON_KID,
    COMP_LUNAR_LZ17,
    COMP_LUNAR_LZ18,
    COMP_FRONTMISSION2,
    COMP_RLEINC1,       // scan 360
    COMP_RLEINC2,
    COMP_EVOLUTION,
    COMP_PUYO_LZ10,
    COMP_PUYO_LZ11,
    COMP_NISLZS,        // scan 365
    COMP_UNKNOWN1,
    COMP_UNKNOWN2,
    COMP_UNKNOWN3,
    COMP_UNKNOWN4,
    COMP_UNKNOWN5,      // scan 370
    COMP_UNKNOWN6,
    COMP_UNKNOWN7,
    COMP_UNKNOWN8,
    COMP_UNKNOWN9,
    COMP_UNKNOWN10,     // scan 375
    COMP_UNKNOWN11,
    COMP_UNKNOWN12,
    COMP_UNKNOWN13,
    COMP_UNKNOWN14,
    COMP_UNKNOWN15,     // scan 380
    COMP_UNKNOWN16,
    COMP_UNKNOWN17,
    COMP_UNKNOWN18,
    COMP_UNKNOWN19,
    COMP_BLACKDESERT,   // scan 385
    COMP_BLACKDESERT_RAW,
    COMP_PUCRUNCH,
    COMP_ZPAQ,
    COMP_ZYXEL_LZS,
    COMP_BLOSC,         // scan 390
    COMP_GIPFELI,
    COMP_CRUSH,
    COMP_YAPPY,
    COMP_LZG,
    COMP_DOBOZ,         // scan 395
    COMP_TORNADO,
    COMP_XPKSQSH,
    COMP_AMIGA_UNSQUASH,
    COMP_AMIGA_BYTEKILLER,
    COMP_AMIGA_FLASHSPEED,  // scan 400
    COMP_AMIGA_IAMICE,
    COMP_AMIGA_IAMATM,
    COMP_AMIGA_ISC1P,
    COMP_AMIGA_ISC2P,
    COMP_AMIGA_ISC3P,       // scan 405
    COMP_AMIGA_UPCOMP,
    COMP_AMIGA_UPHD,
    COMP_AMIGA_BYTEKILLER3,
    COMP_AMIGA_BYTEKILLER2,
    COMP_AMIGA_CRUNCHMANIA17b,  // scan 410
    COMP_AMIGA_POWERPACKER,
    COMP_AMIGA_STONECRACKER2,
    COMP_AMIGA_STONECRACKER3,
    COMP_AMIGA_STONECRACKER4,
    COMP_AMIGA_CRUNCHMASTER,    // scan 415
    COMP_AMIGA_CRUNCHMANIA,
    COMP_AMIGA_CRUNCHMANIAh,
    COMP_AMIGA_CRUNCHOMATIC,
    COMP_AMIGA_DISCOVERY,
    COMP_AMIGA_LIGHTPACK,       // scan 420
    COMP_AMIGA_MASTERCRUNCHER,
    COMP_AMIGA_MAXPACKER,
    COMP_AMIGA_MEGACRUNCHER,
    COMP_AMIGA_PACKIT,
    COMP_AMIGA_SPIKECRUNCHER,   // scan 425
    COMP_AMIGA_TETRAPACK,
    COMP_AMIGA_TIMEDECRUNCH,
    COMP_AMIGA_TRYIT,
    COMP_AMIGA_TUC,
    COMP_AMIGA_TURBOSQUEEZER61, // scan 430
    COMP_AMIGA_TURBOSQUEEZER80,
    COMP_AMIGA_TURTLESMASHER,
    COMP_AMIGA_DMS,
    COMP_AMIGA_PACKFIRE,
    COMP_ALBA_BPE,      // scan 435
    COMP_ALBA_BPE2,
    COMP_FLZP,
    COMP_SR2,
    COMP_SR3,
    COMP_BPE2v3,        // scan 440
    COMP_BPE_ALT1,
    COMP_BPE_ALT2,
    COMP_CBPE,
    COMP_SCPACK0,
    COMP_LZMA_0,        // scan 445
    COMP_LZMA_86HEAD0,
    COMP_LZMA_86DEC0,
    COMP_LZMA_86DECHEAD0,
    COMP_LZMA_EFS0,
    COMP_LZMA2_0,       // scan 450
    COMP_LZMA2_86HEAD0,
    COMP_LZMA2_86DEC0,
    COMP_LZMA2_86DECHEAD0,
    COMP_LZMA2_EFS0,
    COMP_LZOVL,         // scan 455
    COMP_NITROSDK_DIFF8,
    COMP_NITROSDK_DIFF16,
    COMP_NITROSDK_HUFF8,
    COMP_NITROSDK_HUFF16,
    COMP_NITROSDK_LZ,   // scan 460
    COMP_NITROSDK_RL,
    COMP_QCMP,
    COMP_SPARSE,
    COMP_STORMHUFF,
    COMP_GZIP_STRICT,   // scan 465
	COMP_CT_HughesTransform,
	COMP_CT_LZ77,
	COMP_CT_ELSCoder,
	COMP_CT_RefPack,
    COMP_QFS,           // scan 470
    COMP_PXP,
    COMP_BOH,
    COMP_GRC,
    COMP_ZEN,
    COMP_LZHUFXR,       // scan 475
    COMP_FSE,
    COMP_FSE_RLE,
    COMP_ZSTD,
    COMP_CSC,
    COMP_RNCb,          // scan 480
    COMP_RNCb_RAW,
    COMP_RNCc_RAW,
    COMP_AZO,
    COMP_PP20,
    COMP_DS_BLZ,        // scan 485
    COMP_DS_HUF,
    COMP_DS_LZE,
    COMP_DS_LZS,
    COMP_DS_LZX,
    COMP_DS_RLE,        // scan 490
    COMP_FAB,
    COMP_LZ4F,
    COMP_PCLZFG,
    COMP_LZOO,
    COMP_DELZC,         // scan 495
    COMP_DEHUFF,
    COMP_HEATSHRINK,
    COMP_NEPTUNIA,
    COMP_SMAZ,
    COMP_LZFX,          // scan 500
    COMP_PITHY,
    COMP_ZLING,
    COMP_DENSITY,
    COMP_BROTLI,
    COMP_RLE32,         // scan 505
    COMP_RLE35,
    COMP_BSC,
    COMP_SHOCO,
    COMP_WFLZ,
    COMP_FASTARI,       // scan 510
    COMP_RLE_ORCOM,
    COMP_DICKY,
    COMP_SQUISH,
    COMP_LZNT1,
    COMP_XPRESS,        // scan 515
    COMP_XPRESS_HUFF,
    COMP_LZJODY,
    COMP_TRLE,
    COMP_SRLE,
    COMP_MRLE,          // scan 520
    COMP_LUNAR_LZ19,
    COMP_JCH,
    COMP_LZRW1KH,
    COMP_LZSS0,
	COMP_LHA_lz5,       // scan 525
	COMP_LHA_lzs,
	COMP_LHA_lh1,
	COMP_LHA_lh4,
	COMP_LHA_lh5,
	COMP_LHA_lh6,       // scan 530
	COMP_LHA_lh7,
	COMP_LHA_lhx,
	COMP_LHA_pm1,
	COMP_LHA_pm2,
    COMP_SQX1,          // scan 535
    COMP_MDIP_ARAD,
    COMP_MDIP_ARST,
    COMP_MDIP_DELTA,
    COMP_MDIP_FREQ,
    COMP_MDIP_HUFFMAN,  // scan 540
    COMP_MDIP_CANONICAL,
    COMP_MDIP_LZSS,
    COMP_MDIP_LZW,
    COMP_MDIP_RICE,
    COMP_MDIP_RLE,      // scan 545
    COMP_MDIP_VPACKBITS,
    COMP_BIZARRE,
    COMP_BIZARRE_SKIP,
    COMP_LZSSX,
    COMP_ASH,           // scan 550
    COMP_YAY0,
    COMP_DSTACKER,
    COMP_DSTACKER_SD3,
    COMP_DSTACKER_SD4,
    COMP_DBLSPACE,      // scan 555
    COMP_DBLSPACE_JM,
    COMP_XREFPACK,
    COMP_XREFPACK0,
    COMP_QCMP2,
    COMP_DEFLATEX,      // scan 560
    COMP_ZLIBX,
    COMP_LZRW1a,
    COMP_LZRW2,
    COMP_LZRW3a,
    COMP_LZRW5,         // scan 565
    COMP_LEGO_IXS,
    COMP_MCOMP,
    COMP_MCOMP0,
    COMP_MCOMP1,
    COMP_MCOMP2,        // scan 570
    COMP_MCOMP3,
    COMP_MCOMP4,
    COMP_MCOMP5,
    COMP_MCOMP6,
    COMP_MCOMP7,        // scan 575
    COMP_MCOMP8,
    COMP_MCOMP9,
    COMP_MCOMP10,
    COMP_MCOMP13,
    COMP_MCOMP14,       // scan 580
    COMP_MCOMP15,
    COMP_MCOMP16,
    COMP_MCOMP17,
    COMP_IROLZ,
    COMP_IROLZ2,        // scan 585
    COMP_UCLPACK,
    COMP_ACE,
    COMP_EA_COMP,
    COMP_EA_HUFF,
    COMP_EA_JDLZ,       // scan 590
    COMP_TORNADO_BYTE,
    COMP_TORNADO_BIT,
    COMP_TORNADO_HUF,
    COMP_TORNADO_ARI,
    COMP_LBALZSS1,      // scan 595
    COMP_LBALZSS2,
    COMP_DBPF,
    COMP_TITUS_LZW,
    COMP_TITUS_HUFFMAN,
    COMP_KB_LZW,        // scan 600
    COMP_KB_DOSLZW,
    COMP_CARMACK,
    COMP_MBASH,
    COMP_DDAVE,
    COMP_GOT,           // scan 605
    COMP_SKYROADS,
    COMP_ZONE66,
    COMP_EXEPACK,
    COMP_DE_LZW,
    COMP_JJRLE,         // scan 610
    COMP_K13RLE,
    COMP_SFRLC,
    COMP_WESTWOOD1,
    COMP_WESTWOOD3,
    COMP_WESTWOOD3b,    // scan 615
    COMP_WESTWOOD40,
    COMP_WESTWOOD80,
    COMP_PKWARE_DCL,
    COMP_TERSE,
    COMP_TERSE_SPACK_RAW,   // scan 620
    COMP_TERSE_PACK_RAW,
    COMP_REDUCE1,
    COMP_REDUCE2,
    COMP_REDUCE3,
    COMP_REDUCE4,       // scan 625
    COMP_LZW_ENGINE,
    COMP_LZW_BASH,
    COMP_LZW_EPFS,
    COMP_LZW_STELLAR7,
    COMP_ULTIMA6,       // scan 630
    COMP_LZ5,
    COMP_LZ5F,
    COMP_YALZ77,
    COMP_LZKN1,
    COMP_LZKN2,         // scan 635
    COMP_LZKN3,
    COMP_TFLZSS,
    COMP_SYNLZ1,
    COMP_SYNLZ1b,
    COMP_SYNLZ1partial, // scan 640
    COMP_SYNLZ2,
    COMP_PPMZ2,
    COMP_OPENDARK,
    COMP_DSLZSS,
    COMP_KOF,           // scan 645
    COMP_KOF1,
    COMP_RFPK,
    COMP_WP16,
    COMP_LZ4_STREAM,
    COMP_OODLE,         // scan 650
    COMP_OODLE_LZH,
    COMP_OODLE_LZHLW,
    COMP_OODLE_LZNIB,
    COMP_OODLE_LZB16,
    COMP_OODLE_LZBLW,   // scan 655
    COMP_OODLE_LZNA,
    COMP_OODLE_BitKnit,
    COMP_OODLE_LZA,
    COMP_OODLE_LZQ1,
    COMP_OODLE_LZNIB2,  // scan 660
    COMP_SEGS,
    COMP_OODLE_Selkie,
    COMP_OODLE_Akkorokamui,
    COMP_ALZ,
    COMP_REVELATION_ONLINE, // scan 665
    COMP_PS_LZ77,
    COMP_LZFSE,
    COMP_ZLE,
    COMP_KOF2,
    COMP_KOF3,          // scan 670
    COMP_HSQ,
    COMP_FACT5LZ,
    COMP_LZCAPTSU,
    COMP_TF3_RLE,
    COMP_WINIMPLODE,    // scan 675
    COMP_DZIP,
    COMP_DZIP_COMBUF,
    COMP_LBALZSS1X,
    COMP_LBALZSS2X,
    COMP_GHIREN,        // scan 680
    COMP_FALCOM_DIN,
    COMP_FALCOM_DIN1,
    COMP_FALCOM_DIN0,
    COMP_FALCOM_DINX,
    COMP_GLZA,          // scan 685
    COMP_M99CODER,
    COMP_LZ4X,
    COMP_TAIKO,
    COMP_LZ77EA_970,
    COMP_DRV3_SRD,      // scan 690
    COMP_RECET,
    COMP_LIZARD,

        // nop
    COMP_NOP,
        // compressors
    COMP_ZLIB_COMPRESS      = 10000,
    COMP_DEFLATE_COMPRESS,
    COMP_LZO1_COMPRESS,
    COMP_LZO1X_COMPRESS,
    COMP_LZO2A_COMPRESS,
    COMP_XMEMLZX_COMPRESS,
    COMP_BZIP2_COMPRESS,
    COMP_GZIP_COMPRESS,
    COMP_LZSS_COMPRESS,
    COMP_SFL_BLOCK_COMPRESS,
    COMP_SFL_RLE_COMPRESS,
    COMP_SFL_NULLS_COMPRESS,
    COMP_SFL_BITS_COMPRESS,
    COMP_LZF_COMPRESS,
    COMP_BRIEFLZ_COMPRESS,
    COMP_JCALG_COMPRESS,
    COMP_BCL_HUF_COMPRESS,
    COMP_BCL_LZ_COMPRESS,
    COMP_BCL_RICE_COMPRESS,
    COMP_BCL_RLE_COMPRESS,
    COMP_BCL_SF_COMPRESS,
    COMP_SZIP_COMPRESS,
    COMP_HUFFMANLIB_COMPRESS,
    COMP_LZMA_COMPRESS,
    COMP_LZMA_86HEAD_COMPRESS,
    COMP_LZMA_86DEC_COMPRESS,
    COMP_LZMA_86DECHEAD_COMPRESS,
    COMP_LZMA_EFS_COMPRESS,
    COMP_FALCOM_COMPRESS,
    COMP_KZIP_ZLIB_COMPRESS,
    COMP_KZIP_DEFLATE_COMPRESS,
    COMP_PRS_COMPRESS,
    COMP_RNC_COMPRESS,
    COMP_LZ4_COMPRESS,
    COMP_SFL_BLOCK_CHUNKED_COMPRESS,
    COMP_SNAPPY_COMPRESS,
    COMP_ZPAQ_COMPRESS,
    COMP_BLOSC_COMPRESS,
    COMP_GIPFELI_COMPRESS,
    COMP_YAPPY_COMPRESS,
    COMP_LZG_COMPRESS,
    COMP_DOBOZ_COMPRESS,
    COMP_NITROSDK_COMPRESS,
    COMP_HEX_COMPRESS,
    COMP_BASE64_COMPRESS,
    COMP_LZMA2_COMPRESS,
    COMP_LZMA2_86HEAD_COMPRESS,
    COMP_LZMA2_86DEC_COMPRESS,
    COMP_LZMA2_86DECHEAD_COMPRESS,
    COMP_LZMA2_EFS_COMPRESS,
    COMP_LZMA_0_COMPRESS,
    COMP_LZMA2_0_COMPRESS,
    COMP_STORMHUFF_COMPRESS,
	COMP_CT_HughesTransform_COMPRESS,
	COMP_CT_LZ77_COMPRESS,
	COMP_CT_ELSCoder_COMPRESS,
	COMP_CT_RefPack_COMPRESS,
	COMP_DK2_COMPRESS,
    COMP_QFS_COMPRESS,
    COMP_LZHUFXR_COMPRESS,
    COMP_FSE_COMPRESS,
    COMP_ZSTD_COMPRESS,
    COMP_DS_BLZ_COMPRESS,
    COMP_DS_HUF_COMPRESS,
    COMP_DS_LZE_COMPRESS,
    COMP_DS_LZS_COMPRESS,
    COMP_DS_LZX_COMPRESS,
    COMP_DS_RLE_COMPRESS,
    COMP_HEATSHRINK_COMPRESS,
    COMP_SMAZ_COMPRESS,
    COMP_LZFX_COMPRESS,
    COMP_PITHY_COMPRESS,
    COMP_ZLING_COMPRESS,
    COMP_DENSITY_COMPRESS,
    COMP_BSC_COMPRESS,
    COMP_SHOCO_COMPRESS,
    COMP_WFLZ_COMPRESS,
    COMP_FASTARI_COMPRESS,
    COMP_DICKY_COMPRESS,
    COMP_SQUISH_COMPRESS,
    COMP_LZHL_COMPRESS,
    COMP_LZHAM_COMPRESS,
    COMP_TRLE_COMPRESS,
    COMP_SRLE_COMPRESS,
    COMP_MRLE_COMPRESS,
    COMP_CPK_COMPRESS,
    COMP_LZRW1KH_COMPRESS,
    COMP_BPE_COMPRESS,
    COMP_NRV2b_COMPRESS,
    COMP_NRV2d_COMPRESS,
    COMP_NRV2e_COMPRESS,
    COMP_LZSS0_COMPRESS,
    COMP_CLZW_COMPRESS,
    COMP_QUICKLZ_COMPRESS,
    COMP_ZOPFLI_ZLIB_COMPRESS,
    COMP_ZOPFLI_DEFLATE_COMPRESS,
    COMP_PKWARE_DCL_COMPRESS,
    COMP_LZ5_COMPRESS,
    COMP_YALZ77_COMPRESS,
    COMP_SYNLZ1_COMPRESS,
    COMP_SYNLZ2_COMPRESS,
    COMP_PPMZ2_COMPRESS,
    COMP_EA_JDLZ_COMPRESS,
    COMP_OODLE_COMPRESS,
    COMP_LZFSE_COMPRESS,
    COMP_M99CODER_COMPRESS,
    COMP_LZ4X_COMPRESS,
    COMP_YUKE_BPE_COMPRESS,
    COMP_LZO1A_COMPRESS,
    COMP_LZO1B_COMPRESS,
    COMP_LZO1C_COMPRESS,
    COMP_LZO1F_COMPRESS,
    COMP_LZO1Y_COMPRESS,
    COMP_LZO1Z_COMPRESS,
    COMP_LIZARD_COMPRESS,

    // remember to put the _COMPRESS ones also in file.c for reimporting
        // nop
    COMP_ERROR
};



#define QUICK_COMP_ENUM(X) \
    COMP_##X,
#define QUICK_COMP_ASSIGN(X) \
    else if(!stricmp(str, #X)) \
        g_compression_type = COMP_##X;
#define QUICK_COMP_ASSIGN2(X,Y) \
    else if(!stricmp(str, #X) || !stricmp(str, #Y)) \
        g_compression_type = COMP_##X;
#define QUICK_COMP_ASSIGN3(X,Y,Z) \
    else if(!stricmp(str, #X) || !stricmp(str, #Y) || !stricmp(str, #Z)) \
        g_compression_type = COMP_##X;
#define QUICK_COMP_CASE(X) \
    case COMP_##X:  set_int3(COMP_##X, in, zsize, out, size);



#define QUICK_CRYPT_CASE(X) \
    if(X) { \
        if(datalen < 0) return 0; \
        set_int3(X, data, datalen, NULL, NULL);



//#pragma pack(1)



enum {
    LZMA_FLAGS_NONE         = 0,
    LZMA_FLAGS_86_HEADER    = 1,
    LZMA_FLAGS_86_DECODER   = 2,
    LZMA_FLAGS_EFS          = 4,
    LZMA_FLAGS_PROP0        = 0x1000,
    LZMA_FLAGS_NOP
};



typedef struct {
    void    *info;
    u8      *data;
    u_int   size;
} data_t;



typedef struct {
    u8      active;
    int     vars;
    int     *var;           // example: idx of i and j
    int     arrays;
    data_t  *array;         // list of arrays containing the various values of i:j
} sub_variable_t;



typedef struct {
    // for optimizing the usage of the memory I use a static buffer and an allocated pointer used if
    // the static buffer is not big enough
    // pros: fast and avoids memory consumption with xalloc
    // cons: wastes memory, moreover with -9 (compared with the allocated only version)

#ifndef QUICKBMS_VAR_STATIC
    union {
#endif
    u8      *name;          // name of the variable, it can be also a fixed number since "everything" is handled as a variable
    u8      *name_alloc;
#ifndef QUICKBMS_VAR_STATIC
    };
#endif
#ifdef QUICKBMS_VAR_STATIC
    u8      name_static[VAR_NAMESZ + 1];
#endif

#ifndef QUICKBMS_VAR_STATIC
    union {
#endif
    u8      *value;         // content of the variable
    u8      *value_alloc;
#ifndef QUICKBMS_VAR_STATIC
    };
#endif
#ifdef QUICKBMS_VAR_STATIC
    u8      value_static[VAR_VALUESZ + 1];
#endif

    int     value32;        // number

#ifndef QUICKBMS_VAR_STATIC
    union {
#endif
    u_int   size;           // used for avoiding to waste realloc too much, not so much important and well used in reality
    u_int   real_size;      // work-around to avoid to "touch" the size value
#ifndef QUICKBMS_VAR_STATIC
    };
#endif

    u8      isnum;          // 1 if it's a number, 0 if a string
    u8      constant;       // 1 if the variable is a fixed number and not a "real" variable
    u8      binary;         // 1 if the variable is binary
    u8      reserved;

    sub_variable_t  *sub_var;
} variable_t;



typedef struct {
    int     var[MAX_ARGS];  // pointer to a variable
    int     num[MAX_ARGS];  // simple number
    u8      *str[MAX_ARGS]; // fixed string
    u8      type;           // type of command to execute
    u8      *debug_line;    // used with -v
    int     bms_line_number;
} command_t;



#define FDBITS \
    u8      bitchr; \
    u8      bitpos; \
    u_int   bitoff;



typedef struct {
    u8      byte;
    u8      idx;    // it's necessary to save the memory although idx can be truncated
    u8      flags;
    u8      *name;
} hexhtml_t;



typedef struct {
    FILE    *fd;
    u8      *fullname;      // just the same input filename, like c:\myfile.pak or ..\..\myfile.pak
    u8      *filename;      // input filename only, like myfile.pak
    u8      *basename;      // input basename only, like myfile
    u8      *fileext;       // input extension only, like pak
    u8      *filepath;
    u8      *fullbasename;
    FDBITS
    hexhtml_t   *hexhtml;
    u_int   hexhtml_size;
    u_int   coverage;       // experimental coverage
    void    *sd;            // socket operations
    void    *pd;            // process memory operations
    void    *ad;            // audio operations
    void    *vd;            // video operations
    void    *md;            // Windows messages operations
    u8      *prev_basename;
} filenumber_t;



typedef struct {
    u8      *data;
    u_int   pos;
    u_int   size;
    u_int   maxsize;
    FDBITS
    hexhtml_t   *hexhtml;
    u_int   hexhtml_size;
    u_int   coverage;       // experimental coverage
} memory_file_t;



typedef struct {
    u_int       allocated_elements;
    u_int       elements;
    variable_t  *var;
} array_t;



typedef struct {
    u8      *name;
    //u_int   offset; // unused at the moment
    u_int   size;
} files_t;



typedef struct {
    u32     g1;
    u16     g2;
    u16     g3;
    u8      g4;
    u8      g5;
    u8      g6;
    u8      g7;
    u8      g8;
    u8      g9;
    u8      g10;
    u8      g11;
} clsid_t;



filenumber_t    g_filenumber[MAX_FILES + 1];
variable_t      g_variable_main[MAX_VARS + 1];
variable_t      *g_variable = g_variable_main;  // remember to reinitialize it every time (to avoid problems with callfunction)
command_t       g_command[MAX_CMDS + 1];
memory_file_t   g_memory_file[MAX_FILES + 1];
array_t         g_array[MAX_ARRAYS + 1];



#ifndef DISABLE_SSL
HMAC_CTX        *hmac_ctx       = NULL;
EVP_CIPHER_CTX  *evp_ctx        = NULL;
EVP_MD_CTX      *evpmd_ctx      = NULL;
BF_KEY          *blowfish_ctx   = NULL;
typedef struct {
    AES_KEY     ctx;
    u8          ivec[AES_BLOCK_SIZE];
    u8          ecount[AES_BLOCK_SIZE];
	unsigned    num;
    int         type;
} aes_ctr_ctx_t;
enum {
    aes_ctr_ctx_ctr,
    aes_ctr_ctx_ige,
    aes_ctr_ctx_bi_ige,
    aes_ctr_ctx_heat,
};
aes_ctr_ctx_t   *aes_ctr_ctx    = NULL;
aes_ctr_ctx_t   *zip_aes_ctx    = NULL;
typedef struct {
    BIGNUM  *n;
    BIGNUM  *e;
    BIGNUM  *c;
    BN_CTX  *bn_tmp;
    BIGNUM  *r;
    int     zed;
} modpow_context;
modpow_context *modpow_ctx = NULL;
#endif
tea_context     *tea_ctx        = NULL;
xtea_context    *xtea_ctx       = NULL;
xxtea_context   *xxtea_ctx      = NULL;
swap_context    *swap_ctx       = NULL;
math_context    *math_ctx       = NULL;
xmath_context   *xmath_ctx      = NULL;
random_context  *random_ctx     = NULL;
xor_context     *xor_ctx        = NULL;
rot_context     *rot_ctx        = NULL;
rotate_context  *rotate_ctx     = NULL;
reverse_context *reverse_ctx    = NULL;
inc_context     *inc_ctx        = NULL;
charset_context *charset_ctx    = NULL;
charset_context *charset2_ctx   = NULL;
TWOFISH_context *twofish_ctx    = NULL;
SEED_context    *seed_ctx       = NULL;
serpent_context_t *serpent_ctx  = NULL;
ICE_KEY         *ice_ctx        = NULL; // must be not allocated
Rotorobj        *rotor_ctx      = NULL;
ssc_context     *ssc_ctx        = NULL;
wincrypt_context *wincrypt_ctx  = NULL;
cunprot_context *cunprot_ctx    = NULL;
u32             *zipcrypto_ctx  = NULL;
u32             *threeway_ctx   = NULL;
void            *skipjack_ctx   = NULL;
ANUBISstruct    *anubis_ctx     = NULL;
aria_ctx_t      *aria_ctx       = NULL;
u32             *crypton_ctx    = NULL;
u32             *frog_ctx       = NULL;
gost_ctx_t      *gost_ctx       = NULL;
int             lucifer_ctx     = 0;
u32             *mars_ctx       = NULL;
u32             *misty1_ctx     = NULL;
NOEKEONstruct   *noekeon_ctx    = NULL;
seal_ctx_t      *seal_ctx       = NULL;
safer_key_t     *safer_ctx      = NULL;
int             kirk_ctx        = -1;
u8              *pc1_128_ctx    = NULL;
u8              *pc1_256_ctx    = NULL;
sph_context     *sph_ctx        = NULL;
u32             *mpq_ctx        = NULL;
#ifndef DISABLE_MCRYPT
    MCRYPT      mcrypt_ctx      = NULL;
#endif
u32             *rc6_ctx        = NULL;
xor_prev_next_context *xor_prev_next_ctx = NULL;
typedef struct {
    void    *openssl_rsa_private;
    void    *openssl_rsa_public;
#ifndef DISABLE_TOMCRYPT
    rsa_key tomcrypt_rsa;
#endif
    int     is_tomcrypt;
    u8      *ivec;  // currently unused
    int     ivecsz;
} rsa_context;
rsa_context     *rsa_ctx        = NULL;
#ifndef DISABLE_TOMCRYPT
    typedef struct {
        int     idx;
        int     cipher;
        int     hash;
        u8      *key;
        int     keysz;
        u8      *ivec;      // allocated
        int     ivecsz;
        u8      *nonce;     // allocated
        int     noncelen;
        u8      *header;    // allocated
        int     headerlen;
        u8      *tweak;     // allocated
    } TOMCRYPT;
    TOMCRYPT    *tomcrypt_ctx   = NULL;
#endif
crc_context     *crc_ctx        = NULL;
u8              *execute_ctx    = NULL;
u8              *calldll_ctx    = NULL;
typedef struct {
    int     algo;
    u8      *key;           // allocated
    int     keysz;
    u8      *ivec;          // allocated
    int     ivecsz;
} ecrypt_context;
ecrypt_context  *ecrypt_ctx     = NULL;
enum {
#define QUICKBMS_ECRYPT_defs
#include "encryption/ecrypt.h"
#undef QUICKBMS_ECRYPT_defs
};
ISAAC_ctx_t     *isaac_ctx      = NULL;
int             isaac_vernam_ctx    = 0;
int             isaac_caesar_ctx    = 0;
int             hsel_ctx            = 0;



quickiso_ctx_t  *g_quickiso         = NULL;
quickzip_ctx_t  *g_quickzip         = NULL;
FILE    *g_listfd                   = NULL;
int     g_codepage_default          = -1;   // necessary for the -P option and the bms initialization
int     g_last_cmd                  = 0,
        g_codepage                  = -1,   // ok
        g_bms_line_number           = 0,
        g_extracted_files           = 0,
        g_reimported_files          = 0,
        g_endian                    = MYLITTLE_ENDIAN,
        g_list_only                 = 0,
        g_force_overwrite           = 0,
        g_force_rename              = 0,
        g_verbose                   = 0,
        g_quiet                     = 0,
        g_quick_gui_exit            = 0,
        g_compression_type          = COMP_ZLIB,
        *g_file_xor_pos             = NULL,
        g_file_xor_size             = 0,
        *g_file_rot_pos             = NULL,
        g_file_rot_size             = 0,
        *g_file_crypt_pos           = NULL,
        g_file_crypt_size           = 0,
        g_comtype_dictionary_len    = 0,
        g_comtype_scan              = 0,
        g_encrypt_mode              = 0,
        g_append_mode               = APPEND_MODE_NONE,
        g_temporary_file_used       = 0,
        g_quickbms_version          = 0,
        g_decimal_notation          = 1,    // myitoa is a bit slower (due to the %/) but is better for some strings+num combinations
        g_mex_default               = 0,
        g_script_uses_append        = 0,
        g_write_mode                = 0,
        g_input_total_files         = 0,
        g_endian_killer             = 0,
        g_void_dump                 = 0,
        g_reimport                  = 0,
        g_enable_hexhtml            = 0,
        g_continue_anyway           = 0,
        g_yes                       = 0,
        g_int3                      = 0,
        g_is_gui                    = 0,
        g_memfile_reimport_name     = -1,
        g_lame_add_var_const_workaround = 0,
        g_reimport_zero             = 0,
        g_keep_temporary_file       = 0;
        //g_min_int                   = 1 << ((sizeof(int) << 3) - 1),
        //g_max_int                   = (u_int)(1 << ((sizeof(int) << 3) - 1)) - 1;
u8      g_current_folder[PATHSZ + 1]= "",  // just the current folder when the program is launched
        g_bms_folder[PATHSZ + 1]    = "",
        g_bms_script[PATHSZ + 1]    = "",
        g_exe_folder[PATHSZ + 1]    = "",
        g_file_folder[PATHSZ + 1]   = "",
        g_temp_folder[PATHSZ + 1]   = "",
        *g_output_folder            = NULL,     // points to fdir
        **g_filter_files            = NULL,     // the wildcard
        **g_filter_in_files         = NULL,     // the wildcard
        *g_file_xor                 = NULL,     // contains all the XOR numbers
        *g_file_rot                 = NULL,     // contains all the rot13 numbers
        *g_file_crypt               = NULL,     // nothing
        *g_comtype_dictionary       = NULL,
        *g_quickbms_execute_file    = NULL,
        *g_force_output             = NULL,
        *g_compare_folder           = NULL;
int     EXTRCNT_idx                 = 0,
        BytesRead_idx               = 0,
        NotEOF_idx                  = 0,
        SOF_idx                     = 0,
        EOF_idx                     = 0;



// experimental input and output
int     enable_sockets              = 0,
        enable_process              = 0,
        enable_audio                = 0,
        enable_video                = 0,
        enable_winmsg               = 0,
        enable_calldll              = 0,
        enable_execute_pipe         = 0;



#ifdef WIN32
    OSVERSIONINFO   g_osver         = {0};
#endif



//#pragma pack()

