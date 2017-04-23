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

// all the compression algorithms

// what to do if the output buffer is overflowed:
// - break      ok: return what has been written till now which is very good for the compression scanner and buggy implementations
// - return -1  error: return an error and interrupt the extraction
#define quickbms_unz_output_overflow    break   // return -1

void *calldll_alloc(u8 *dump, u32 dumpsz, u32 argc, ...);

#define MYALLOC_ZEROES  16  // long story, anyway keep 16 for both XmemDecompress and general padding/blocks (indeed AES uses 16 bytes)
#define ASURACMP    // comment it if the input doesn't have the first 8 bytes assigned to zsize and size
#include "included/asura_huffboh.c"
#include "included/lzss.c"
#include "included/lzssx.c"
#include "compression/quicklz.h"
//#include "compression/unq3huff.c"
int unq3huff( unsigned char *in, int insz, unsigned char *out, int outsz );
#include "included/unrlew.c"
#include "included/unmeng.c"
#include "included/unlz2k.c"
#include "included/undarksector.c"
#include "included/un49g.c"
#include "included/unthandor.c"
#include "included/tzar_lzss.c"
#include "compression/lzh.h"
#include "compression/sr3c.h"
#include "included/undk2.c"
#include "included/stalker_lza.c"
#include "included/puyo.c"
#include "included/rdc.c"
#include "included/ilzr.c"
#include "compression/libLZR.h"
#include "included/mppc.c"
#include "included/un434a.c"
#include "included/fal_codec.c"
#include "compression/doomhuff.h"
#include "included/msf.c"
#include "included/ntcompress.c"
#include "included/undact.c"
#include "included/lz77_0.c"
#include "included/lzbss.c"
//#include "included/bgbpaq0.c"
int BPAQ0_DecodeData(u8 *in, u8 *out);
//#include "included/dict.c"
int DictDecode (u8 *buf, unsigned bufsize, u8 *outbuf, unsigned *outsize);
#include "included/rep.c"
#include "included/elias.c"
#include "included/kzip_old.c"
#include "libs/uberflate/uberflate.c"
#include "included/enet_compress.c"
#include "included/lzfu.c"
#include "included/he3.c"
#include "included/ntfs_compress.c"
#include "included/comprlib.c"
#include "included/hd2.c"
#include "included/prs.cpp"
#include "included/sega_lz77.c"
#include "included/unyakuza.c"
#define LZ4F_DISABLE_OBSOLETE_ENUMS
#include "libs/lz4/lz4.h"
#include "libs/lz4/lz4frame.h"
#include "libs/lz4/lz4hc.h"
LZ4_streamDecode_t  *g_LZ4_streamDecode = NULL;
#define LZ5F_DISABLE_OBSOLETE_ENUMS
#include "libs/lz5/lz5.h"
#include "libs/lz5/lz5frame.h"
#include "libs/lz5/lz5hc.h"
#include "libs/lizard/lizard_compress.h"
#include "libs/lizard/lizard_decompress.h"
#include "included/lunar.c"
#include "included/goldensun.c"
#include "included/luminousarc.c"
#include "compression/fastlz.h"
//#include "included/zax.c"
int zax_uncompress(unsigned char *infd, int insz, unsigned char *outfd, int outsz);
#include "compression/Shrinker.h"
#include "libs/mmini/mmini.h"
#include "libs/clzw/lzw.h"
#include "included/lzham.c"
#include "included/sega_lzs2.c"
#include "libs/lzlib/lzlib.h"
#include "included/undflt.c"
#include "included/ffce.c"
#include "libs/snappy/snappy-c.h"
#include "compression/scummvm.h"
#include "included/compression_unknown.c"
#include "included/blackdesert_unpack.c"
#include "included/zyxel_lzsd.c"
#include "libs/blosc/blosclz.h"
#include "included/crush.c"
#include "libs/liblzg/src/include/lzg.h"
#include "included/yappy.c"
#include "libs/aplib/depacks.h"
#include "included/xpksqsh.c"
#include "included/unpxp.c"
#include "included/boh.c"
#include "included/qfs.c"
#include "libs/zstd/common/fse.h"
#include "libs/zstd/zstd.h"
#define HEATSHRINK_DYNAMIC_ALLOC
#include "libs/heatshrink/heatshrink_decoder.h"
#include "libs/heatshrink/heatshrink_encoder.h"
#include "libs/TurboRLE/trle.h"
#include "libs/TurboRLE/ext/mrle.h"
#include "compression/smaz.h"
#include "compression/lzfx.h"
#include "compression/pithy.h"
#include "libs/density/src/density_api.h"
#include "libs/brotli/dec/decode.h"
#include "libs/libbsc/libbsc.h"
#include "libs/shoco/shoco.h"
#include "compression/wfLZ.h"
#include "compression/FastAri.h"
#include "compression/dicky.h"
#include "compression/squish.h"
#include "libs/ms-compress/include/lznt1.h"
#include "libs/ms-compress/include/xpress.h"
#include "libs/ms-compress/include/xpress_huff.h"
#include "included/neptunia.c"
#include "included/compresslayla.c"
#include "libs/lhasa/lib/public/lha_decoder.h"
#include "included/old_bizarre.c"
#include "libs/liblzf/lzf.h"
// never use lzf_compress, use EVER lzf_compress_best!
unsigned int
lzf_compress_best (const void *const in_data, unsigned int in_len,
	           void *out_data, unsigned int out_len
#if LZF_STATE_ARG
              , LZF_STATE_BEST state
#endif
              );
#include "libs/zopfli/zopfli.h"
#include "included/yay0dec.c"
#include "compression/tinf.h"
#include "included/lego_ixs.c"
#include "libs/mylibmcomp/libmcomp.c"
#include "included/ea_comp.c"
#include "included/ea_huff.c"
#include "included/ea_jdlz.c"
#include "compression/filter-lzw.h"
#include "included/kofdecompress.c"
#include "included/unrfpk.c"
#include "included/wp16.c"
#include "included/oodle.c"
#include "included/rodecompress.c"
#include "libs/lzfse/src/lzfse.h"
#include "libs/mydzip/dzip.c"
int stac_decompress(unsigned char*buf_in, int len_in, unsigned char*buf_out, int len_out);
int sd3_decomp(void* pin,int lin, void* pout, int lout, int flg);
int sd4_decomp(void* pin,int lin, void* pout, int lout, int flg);
int ds_dec(void* pin,int lin, void* pout, int lout, int flg);
int jm_dec(void* pin,int lin, void* pout, int lout, int flg);
int refpack_decompress_safe(const uint8_t *indata, size_t insize,
	size_t *bytes_read_out, uint8_t *outdata, size_t outsize,
	size_t *bytes_written_out, uint32_t *compressed_size_out,
	uint32_t *decompressed_size_out
    , int skip_header);
u8* DecryptAsh( const u8* ba_data , int *ret_size, int optional_outsz);
int bpe_compress (unsigned char *in, int insz, unsigned char *out, int outsz, int yuke);
int sqx1_decoder(unsigned char *in, int insz, unsigned char *out, int outsz, int has_compflags);
int dipperstein_decompress(unsigned char *in, int insz, unsigned char *out, int outsz, int compression);
unsigned int lzrw1kh_Compression(u8 *Source, u8 *Dest, unsigned int SourceSize);
unsigned int lzrw1kh_Decompression(u8 *Source, u8 *Dest, unsigned int SourceSize);
  void *lzhlight_initComp(void);
  void lzhlight_delComp(void *comp);
  size_t lzhlight_compress(void *comp, unsigned char *buf, size_t size, unsigned char *ret);
  void *lzhlight_initDecomp(void);
  size_t lzhlight_decompress(void *decomp, unsigned char *buf, size_t size, unsigned char *ret, size_t retsize);
  void lzhlight_delDecomp(void *decomp);
extern int lzjody_compress(const unsigned char * const, unsigned char * const,
		const unsigned int, const unsigned int);
extern int lzjody_decompress(const unsigned char * const, unsigned char * const,
		const unsigned int, const unsigned int);
int csc_decompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int zling_compress(unsigned char *in, int insz, unsigned char *out, int outsz);
int zling_decompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int de_compress(unsigned long ibytes, int mb, unsigned char *infp, unsigned char *out);
int de_huffman(unsigned long obytes, unsigned char *infp, unsigned char *out_ptr);
int lzd(unsigned char * input_f, unsigned char * output_f);
void  BLZ_Decode(char *filename);
void  BLZ_Encode(char *filename, int mode);
void  HUF_Decode(char *filename);
void  HUF_Encode(char *filename, int cmd);
void  LZE_Decode(char *filename);
void  LZE_Encode(char *filename);
void  LZS_Decode(char *filename);
void  LZS_Encode(char *filename, int mode);
void  LZX_Decode(char *filename);
void  LZX_Encode(char *filename, int cmd, int vram);
void  RLE_Decode(char *filename);
void  RLE_Encode(char *filename);
int nintendo_ds_set_inout(unsigned char *in, int insz, unsigned char *out, int outsz);
#include "included/nintendo.c"
int unpp20(unsigned char *in, int insz, unsigned char *out, int outsz);
int unazo(unsigned char *in, int insz, unsigned char *out, int outsz);
int __cdecl zen_decompress (char* pScrBuffer, char* pDstBuffer, int dwSize);
int pucrunch_UnPack(int loadAddr, const unsigned char *data, unsigned char *file, int flags);
static int clzw_outsz = 0;
void lzw_writebuf(void *stream, char *buf, unsigned size) {
    memcpy(stream + clzw_outsz, buf, size);
    clzw_outsz += size;
}
int unlpaq8(unsigned char *in, int insz, unsigned char *out, int size, int mem, int meth);
int rLZV1 (unsigned char *in, unsigned char *out, int ilen, int len);
int lzmat_decode(u8 *pbOut, u32 *pcbOut, u8 *pbIn, u32 cbIn);
// 7z_advancecomp is used only for zlib/deflate compression on Windows and it doesn't affect the performance (memory/cpu when launched)
//#ifdef WIN32
int advancecomp_rfc1950(unsigned char *in, int insz, unsigned char *out, int outsz);
int advancecomp_deflate(unsigned char *in, int insz, unsigned char *out, int outsz);
int advancecomp_lzma(unsigned char *in, int insz, unsigned char *out, int outsz, int lzma_flags);
//#else
//    #define zlib_compress       advancecomp_rfc1950
//    #define deflate_compress    advancecomp_deflate
//    //#define lzma_compress       advancecomp_lzma
//#endif
int KENS_Nemesis(unsigned char *in, int insz, unsigned char *out, int outsz);
int KENS_Kosinski(unsigned char *in, int insz, unsigned char *out, int outsz, int Moduled);
int KENS_Enigma(unsigned char *in, int insz, unsigned char *out, int outsz);
int KENS_Saxman(unsigned char *in, int insz, unsigned char *out, int outsz);
int _rnc_unpack(const unsigned char* input, unsigned long input_size, unsigned char* output, unsigned long have_ret_len);
void *rnc_pack (void *data, long datalen, long *packlen);
long rnc_unpack (void *packed, void *unpacked, long *leeway, long packed_len, long unpacked_len);
int PAK_explode(unsigned char * srcBuffer, unsigned char * dstBuffer, unsigned compressedSize, unsigned uncompressedSize, unsigned short flags);
int gz_unpack(unsigned char *in, int insz, unsigned char *out, int outsz);
int dmc2_uncompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int ahuff_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int arith_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int arith1_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int arith1e_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int arithn_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int compand_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int huff_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int tdcb_lzss_init(int x1, int x2, int x3, int x4);
int lzss_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int lzw12_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int lzw15v_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int silence_ExpandMemory(unsigned char *in, int insz, unsigned char *out, int outsz);
int lzrw1_compress_decompress(unsigned char *p_wrk_mem, unsigned char *p_src_first, unsigned int src_len, unsigned char *p_dst_first, unsigned int *p_dst_len);
int lzrw1a_compress_decompress(unsigned char *p_wrk_mem, unsigned char *p_src_first, unsigned int src_len, unsigned char *p_dst_first, unsigned int *p_dst_len);
int lzrw2_compress_decompress(unsigned char *p_wrk_mem, unsigned char *p_src_first, unsigned int src_len, unsigned char *p_dst_first, unsigned int *p_dst_len);
int lzrw3_compress_decompress(unsigned char *p_wrk_mem, unsigned char *p_src_first, unsigned int src_len, unsigned char *p_dst_first, unsigned int *p_dst_len);
int lzrw3a_compress_decompress(unsigned char *p_wrk_mem, unsigned char *p_src_first, unsigned int src_len, unsigned char *p_dst_first, unsigned int *p_dst_len);
int lzrw5_compress_decompress(unsigned char *p_wrk_mem, unsigned char *p_src_first, unsigned int src_len, unsigned char *p_dst_first, unsigned int *p_dst_len);
#define perform_lzrw_decompress(X,Y) \
    t32 = size; \
    p = calloc(Y, 1); \
    lzrw##X##_compress_decompress(p, in, zsize, out, &t32); \
    FREE(p) \
    size = t32;
int unsqueeze(unsigned char *in, int insz, unsigned char *out, int outsz);
int d3101(unsigned char *in, int insz, unsigned char *out, int outsz);
int yuke_bpe(unsigned char *in, int insz, unsigned char *out, int outsz, int fill_outsz);
int huffman_decode_memory(const unsigned char *bufin, int bufinlen, unsigned char **bufout, int *pbufoutlen);
int huffman_encode_memory(const unsigned char *bufin, int bufinlen, unsigned char **pbufout, int *pbufoutlen);
void Huffman_Uncompress( unsigned char *in, unsigned char *out, unsigned insize, unsigned outsize );
int Huffman_Compress( unsigned char *in, unsigned char *out, unsigned insize );
void LZ_Uncompress( unsigned char *in, unsigned char *out, unsigned insize );
int LZ_Compress( unsigned char *in, unsigned char *out, unsigned insize );
void Rice_Uncompress( void *in, void *out, unsigned insize, unsigned outsize, int format );
int Rice_Compress( void *in, void *out, unsigned insize, int format );
unsigned RLE_Uncompress( unsigned char *in, unsigned insize, unsigned char *out, unsigned outsize );
unsigned RLE_Compress( unsigned char *in, unsigned insize, unsigned char *out, unsigned outsize );
void SF_Uncompress( unsigned char *in, unsigned char *out, unsigned insize, unsigned outsize );
int SF_Compress( unsigned char *in, unsigned char *out, unsigned insize );
int Scz_Decompress_Buffer2Buffer( char *inbuffer, int N, char **outbuffer, int *M );
//int szip_allow_encoding = 0;
int SZ_encoder_enabled();
int SZ_BufftoBuffDecompress(void *dest, size_t *destLen, const void *source, size_t sourceLen, void *param);
int SZ_BufftoBuffCompress(void *dest, size_t *destLen, const void *source, size_t sourceLen, void *param);
int unbpe2(unsigned char *in, int insz, unsigned char *out, int outsz);
int strexpand(unsigned char *dest, unsigned char *source, int sourcelen, int maxlen, unsigned char *input_pairtable, int input_pairtable_default);
int hstest_hs_unpack(unsigned char *out, unsigned char *in, int insz);
int hstest_unpackc(unsigned char *out, unsigned char *in, int insz);
int unsixpack(unsigned char *in, int insz, unsigned char *out, int outsz);
int unashford(unsigned char *in, int insz, unsigned char *out, int outsz);
__stdcall int JCALG1_Decompress_Small(void *Source, void *Destination);
__stdcall void * JCALG1_AllocFunc(unsigned nMemSize) { return(malloc(nMemSize)); }
__stdcall int JCALG1_DeallocFunc(void *pBuffer) { free(pBuffer); return 1; }
__stdcall int JCALG1_CallbackFunc(unsigned pSourcePos, unsigned pDestinationPos) { return 1; }
__stdcall unsigned JCALG1_Compress(void *Source, unsigned Length, void *Destination, unsigned WindowSize, void *pAlloc, void *pDealloc, void *pCallback, int bDisableChecksum);
int unjam(unsigned char *in, int insz, unsigned char *out, int outsz);
int unsrank(unsigned char *in, int insz, unsigned char *out, int outsz);
int ZzUncompressBlock(unsigned char *buffer);
int sh_DecodeBlock(unsigned char *iBlock, unsigned char *oBlock, int bSize);
unsigned blz_depack_safe(const void *source, unsigned srclen, void *destination, unsigned depacked_length);
unsigned blz_depack(const void *source, void *destination, unsigned depacked_length);
unsigned blz_workmem_size(unsigned length);
unsigned blz_max_packed_size(unsigned length);
unsigned blz_pack(const void *source, void *destination, unsigned length, void *workmem);
int unpaq6(unsigned char *in, int insz, unsigned char *out, int outsz, int levelx);
int unppmdi(unsigned char *in, int insz, unsigned char *out, int outsz);
int unppmdi_raw(unsigned char *in, int insz, unsigned char *out, int outsz, int SaSize, int MaxOrder, int MRMethod);
int unppmdg(unsigned char *in, int insz, unsigned char *out, int outsz);
int unppmdg_raw(unsigned char *in, int insz, unsigned char *out, int outsz, int SaSize, int MaxOrder);
int unppmdj(unsigned char *in, int insz, unsigned char *out, int outsz);
int unppmdj_raw(unsigned char *in, int insz, unsigned char *out, int outsz, int SaSize, int MaxOrder, int CutOff);
int unppmdh(unsigned char *in, int insz, unsigned char *out, int outsz);
int unppmdh_raw(unsigned char *in, int insz, unsigned char *out, int outsz, int SaSize, int MaxOrder);
int unshrink(unsigned char *in, int insz, unsigned char *out, int outsz);
int irolz_uncompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int irolz2_uncompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int unquad(unsigned char *in, int insz, unsigned char *out, int outsz);
int unbalz(unsigned char *in, int insz, unsigned char *out, int outsz);
unsigned GRZip_DecompressBlock(unsigned char * Input, unsigned Size, unsigned char * Output);
int de_lzah(unsigned char *in, int insz, unsigned char *out, int obytes);
int de_lzh(unsigned char *in, int ibytes, unsigned char *out, int obytes, int bits);
int bpe_expand(unsigned char *in, int insz, unsigned char *out, int outsz);
int unlzh(unsigned char *in, int insz, unsigned char *out, int outsz);
int unlzari(unsigned char *in, int insz, unsigned char *out, int outsz);
int uncompress_lzw(unsigned char *in, int insz, unsigned char *out, int outsz, int init_byte);
int undmc(unsigned char *in, int insz, unsigned char *out, int outsz);
int unlzx(unsigned char *in, int insz, unsigned char *out, int outsz);
int unmspack(unsigned char *in, int insz, unsigned char *out, int outsz, int window_bits, int interval, int algo);
uint32_t unlzw(uint8_t *outbuff, uint32_t maxsize, uint8_t *in, uint32_t insize);
uint32_t unlzwx(uint8_t *outbuff, uint32_t maxsize, uint8_t *in, uint32_t insize);
u32 __stdcall nitroDecompress(u8 *srcp, u32 size, u8 *dstp, signed char depth);
u32 __stdcall nitroCompress(u8 *srcp, u32 size, u8 *dstp, char *compList, u8 rawHeader);
u32 DiffFiltRead(u8 *srcp, u32 size, u8 *dstp, u8 diffBitSize);
u32 RLCompRead(u8 *srcp, u32 size, u8 *dstp);
u32 LZCompRead(u8 *srcp, u32 size, u8 *dstp);
u32 HuffCompRead(u8 *srcp, u32 size, u8 *dstp, u8 huffBitSize);
int unctw(unsigned char *in, int insz, unsigned char *out, int outsz);
int lzpx_unpack(unsigned char *in, unsigned char *out);
long ultima4_lzwDecompress(unsigned char* compressedMem, unsigned char* decompressedMem, long compressedSize);
int iris_decompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int iris_huffman(char *in, int insz, char *out, int outsz);
int iris_uo_huffman(char *in, int insz, char *out, int outsz);
int LZXdecompress(unsigned char *inbuf, unsigned char *outbuf, unsigned inlen, unsigned outlen);
int MRCIDecompressWrapper(const void *pb, int cb, const void *pOut, int cbOut); // return is S_OK
int zpaq_decompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int zpaq_compress(unsigned char *in, int insz, unsigned char *out, int outsz);
int gipfeli_uncompress(void *in, int insz, void *out, int outsz);
int gipfeli_compress(void *in, int insz, void *out, int outsz);
int doboz_decompress(void *in, int insz, void *out, int outsz);
int doboz_compress(void *in, int insz, void *out, int outsz);
int tornado_decompress(unsigned char *in, int insz, unsigned char *out, int outsz, int algo);
int flzp_decompress(unsigned char *in, int insz, unsigned char *out);
int sr3_decompress(unsigned char *in, int insz, unsigned char *out, int outsz, int version, int profile);
int StormLib_Compress_huff(void * out, int outsz, void * in, int insz);
int StormLib_Decompress_huff(void * out, int outsz, void * in, int insz);
enum CompressorTypes  
{
	CT_RawCompressor   = 0,
	CT_HughesTransform = 1,
	CT_LZ77            = 2,
	CT_ELSCoder        = 3,
	CT_RefPack         = 4,
};
int shadowforce_decompress(int algo, unsigned char *in, int insz, unsigned char *out, int outsz);
int shadowforce_compress(int algo, unsigned char *in, int insz, unsigned char *out, int outsz);
void _compressLZ(u8** dest, unsigned* dest_sz, void* src, unsigned src_sz);
void _decompressLZ(u8** dest, unsigned* dest_sz, void* src, unsigned src_sz);
int unace1(unsigned char *in, int insz, unsigned char *out, int outsz);
int opentitus_lzw_decode(unsigned char *input, int in_len, unsigned char *output, int out_len);
int opentitus_huffman_decode(unsigned char *input, int in_len, unsigned char *output, int out_len);
int KB_funLZW(char *result, unsigned int max, unsigned char *in, int insz);
int DOS_LZW(char *dst, int dst_max, char *src, int src_len);
int filter_bash_unrle(uint8_t *out, int lenOut,	const uint8_t *in, int lenIn);
int filter_ddave_unrle(uint8_t *out, int lenOut,	const uint8_t *in, int lenIn);
int filter_got_unlzss(uint8_t *out, int lenOut,	const uint8_t *in, int lenIn);
int filter_skyroads_unlzs(uint8_t *out, int lenOut,	/*const*/ uint8_t *in, int lenIn);
int filter_z66_decompress(uint8_t *out, int lenOut,/*const*/ uint8_t *in, int lenIn);
int filter_stargunner_decompress(const uint8_t* in,	unsigned int expanded_size, uint8_t* out);
int deLZW(void* _src, void *_dst, int dstSize);
int jazz_jackrabbit_rle(unsigned char *compressed, int compressed_length, unsigned char *out);
int keen13_rle(unsigned char *in, int insz, unsigned char *out, int outsz);
int sango_fighter_rlc(unsigned char *in, int insz, unsigned char *out, int outsz);
int westwood1(unsigned char *c_data, int c_data_Length, unsigned char *data, int data_Length);
int westwood3(unsigned char *src, unsigned char *dest, int len, int swapWord);
int westwood40(unsigned char *Source, unsigned char *Dest);
int westwood80(unsigned char *Source, unsigned char *Dest);
int splay_trees(unsigned char *in, int insz, unsigned char *out, int outsz, int do_compress);
int arithshift_compress(unsigned char *in, int insz, unsigned char *out, int outsz);
int arithshift_decompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int pkware_dcl_explode(unsigned char *in, int insz, unsigned char *out, int outsz);
int pkware_dcl_implode(unsigned char *in, int insz, unsigned char *out, int outsz);
int terse_decompress(unsigned char *in, int insz, unsigned char *out, int outsz, int is_raw_pack_spack /*-1:PACK 1:PACK*/, int force_binary);
int reduce_decompress(unsigned char *in, int insz, unsigned char *out, int outsz, int factor);
int ultima6_lzw_decompress(unsigned char *source, long source_length, unsigned char *destination, long destination_length);
int yalz77_compress(unsigned char *in, int insz, unsigned char *out, int outsz);
int yalz77_decompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int lzkn1_decompress(unsigned char *input, unsigned char *output);
int lzkn2_decompress(byte *input, byte *output);
int lzkn3_decompress(byte *input, byte *output);
int ppmz2_encode(unsigned char *rawBuf, int rawLen, unsigned char *out, int outsz, unsigned char *conditionBuf, int conditionLen);
int ppmz2_decode(unsigned char *compBuf, int compLen, unsigned char *out, int outsz, unsigned char *conditionBuf, int conditionLen);
int opendark_DecodeFile(unsigned char *in, int insz, unsigned char *out, int outsz);
int alz_decompress(unsigned char *in, int insz, unsigned char *out, int outsz, int type);
int fact5lz_decompress(byte *input, byte *output);
ushort LZCapTsu_decompress(byte *input, byte *output);
int tf3_rle_decompress(byte *data, byte *output, int out_size);
int winimplode_explode(unsigned char *input);
#include "included/falcom_din.c"
int glza_decompress(unsigned char *in, int insz, unsigned char *out, int outsz);
int m99coder(unsigned char *infile, int insz, unsigned char *outfile, int dec_enc);
int lz4x(unsigned char *fin, int flen, unsigned char *fout, int dec_enc);



int get_cpu_number(void) {
    #ifdef WIN32
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        return info.dwNumberOfProcessors;
    #else
        #ifdef _SC_NPROCESSORS_ONLN
        return sysconf(_SC_NPROCESSORS_ONLN);
        #endif
    #endif
    return -1;
}



// in recompression mode I consider MAXZIPLEN as universal for any algorithm, indeed I don't use /1000

void alloc_err(const char *fname, i32 line, const char *func);
int MAXZIPLEN(int n) {
    int     ret;
    if(n < 0) ALLOC_ERR;
    ret = ((n)+(((n)/10)+1)+12+4096);
    if(ret < n) ALLOC_ERR;
    return ret;
}

//#define MAXZIPLEN(n) ((n)+(((n)/10)+1)+12+512)  // 10 instead of 1000 and + 512
//#define MAXZIPLEN(n) ((n)+(((n)/1000)+1)+12)    // this is the correct one for zlib/deflate

#define QUICK_IN_OUT \
    unsigned char   *inl    = in + insz, \
                    *o      = out, \
                    *outl   = out + outsz;

#define lame_feof(X)    ((infile  >= infilel)  ? EOF : 0)
#define lame_getc(X)    ((infile  >= infilel)  ? EOF : (*infile++))
#define lame_putc(Y,X)  ((outfile >= outfilel) ? EOF : (*outfile++ = Y))
#define lame_fgetc      lame_getc
#define lame_fputc      lame_putc

// if I'm not in error, this is good if *ret_outsz was 0 and ret_out wasn't allocated
#define not_ret_out_boh \
    if(!*ret_out) { \
        *ret_outsz = 0; \
        *ret_out = calloc(*ret_outsz, 1); \
        if(!*ret_out) STD_ERR(QUICKBMS_ERROR_MEMORY); \
    }



int uncopy(unsigned char *in, int insz, unsigned char *out, int outsz) {
    int     sz;
    if(insz <= outsz) sz = insz;
    else              sz = outsz;
    memcpy(out, in, sz);
    if(outsz > sz) memset(out + sz, 0, outsz - sz); // padding
    return(outsz);
}



int unlzo(u8 *in, int insz, u8 *out, int outsz, int type) {
    lzo_uint    len = outsz;
    int         err = LZO_E_OK;

#ifdef DISABLE_LZO
    if(type == COMP_LZO1X) {
        if(g_comtype_dictionary) {
            fprintf(stderr, "\nError: LZO1X dictionary not supported with DISABLE_LZO\n");
            myexit(QUICKBMS_ERROR_COMPRESSION);
        } else {
            err = lzo1x_decompress_safe(in, insz, out, &len, NULL);
        }
    } else {
        fprintf(stderr, "\nError: unsupported LZO decompression %d\n", type);
        return -1;
    }
#else
    switch(type) {
        case COMP_LZO1:  { err = lzo1_decompress(in, insz, out, &len, NULL); break; }
        case COMP_LZO1A: { err = lzo1a_decompress(in, insz, out, &len, NULL); break; }
        case COMP_LZO1B: { err = lzo1b_decompress_safe(in, insz, out, &len, NULL); break; }
        case COMP_LZO1C: { err = lzo1c_decompress_safe(in, insz, out, &len, NULL); break; }
        case COMP_LZO1F: { err = lzo1f_decompress_safe(in, insz, out, &len, NULL); break; }
        case COMP_LZO1X: {
            if(g_comtype_dictionary) {
                err = lzo1x_decompress_dict_safe(in, insz, out, &len, NULL, g_comtype_dictionary, g_comtype_dictionary_len);
            } else {
                err = lzo1x_decompress_safe(in, insz, out, &len, NULL);
            }
            break;
        }
        case COMP_LZO1Y: {
            if(g_comtype_dictionary) {
                err = lzo1y_decompress_dict_safe(in, insz, out, &len, NULL, g_comtype_dictionary, g_comtype_dictionary_len);
            } else {
                err = lzo1y_decompress_safe(in, insz, out, &len, NULL);
            }
            break;
        }
        case COMP_LZO1Z: {
            if(g_comtype_dictionary) {
                err = lzo1z_decompress_dict_safe(in, insz, out, &len, NULL, g_comtype_dictionary, g_comtype_dictionary_len);
            } else {
                err = lzo1z_decompress_safe(in, insz, out, &len, NULL);
            }
            break;
        }
        case COMP_LZO2A: { err = lzo2a_decompress_safe(in, insz, out, &len, NULL); break; }
        default: {
            fprintf(stderr, "\nError: unsupported LZO decompression %d\n", type);
            return -1;
            break;
        }
    }
#endif
    if((err != LZO_E_OK) && (err != LZO_E_INPUT_NOT_CONSUMED)) {
        fprintf(stderr, "\nError: the compressed LZO input is wrong or incomplete (%d)\n", err);
        return -1;
    }
    return len;
}



int lzo_compress(u8 *in, int insz, u8 *out, int outsz, int type) {
    lzo_uint    len     = outsz;
    int         err     = LZO_E_OK;
    static u8   *wrkmem = NULL;

#ifdef DISABLE_LZO
    if(type == COMP_LZO1X_COMPRESS) {
        if(g_comtype_dictionary) {
            fprintf(stderr, "\nError: LZO1X dictionary not supported with DISABLE_LZO\n");
            myexit(QUICKBMS_ERROR_COMPRESSION);
        } else {
            wrkmem = realloc(wrkmem, LZO1X_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            err = lzo1x_1_compress(in, insz, out, &len, wrkmem);
        }
    } else {
        fprintf(stderr, "\nError: unsupported LZO compression %d\n", type);
        return -1;
    }
#else
    switch(type) {
        case COMP_LZO1_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1_99_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            err = lzo1_99_compress(in, insz, out, &len, wrkmem);
            break;
        }
        case COMP_LZO1X_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1X_999_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            if(g_comtype_dictionary) {
                err = lzo1x_999_compress_dict(in, insz, out, &len, wrkmem, g_comtype_dictionary, g_comtype_dictionary_len);
            } else {
                err = lzo1x_999_compress(in, insz, out, &len, wrkmem);
            }
            break;
        }
        case COMP_LZO2A_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO2A_999_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            err = lzo2a_999_compress(in, insz, out, &len, wrkmem);
            break;
        }
        // useless compressors
        case COMP_LZO1A_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1A_99_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            err = lzo1a_99_compress(in, insz, out, &len, wrkmem);
            break;
        }
        case COMP_LZO1B_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1B_999_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            err = lzo1b_999_compress(in, insz, out, &len, wrkmem);
            break;
        }
        case COMP_LZO1C_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1C_999_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            err = lzo1c_999_compress(in, insz, out, &len, wrkmem);
            break;
        }
        case COMP_LZO1F_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1F_999_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            err = lzo1f_999_compress(in, insz, out, &len, wrkmem);
            break;
        }
        case COMP_LZO1Y_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1Y_999_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            if(g_comtype_dictionary) {
                err = lzo1y_999_compress_dict(in, insz, out, &len, wrkmem, g_comtype_dictionary, g_comtype_dictionary_len);
            } else {
                err = lzo1y_999_compress(in, insz, out, &len, wrkmem);
            }
            break;
        }
        case COMP_LZO1Z_COMPRESS: {
            wrkmem = realloc(wrkmem, LZO1Z_999_MEM_COMPRESS);
            if(!wrkmem) STD_ERR(QUICKBMS_ERROR_MEMORY);
            if(g_comtype_dictionary) {
                err = lzo1z_999_compress_dict(in, insz, out, &len, wrkmem, g_comtype_dictionary, g_comtype_dictionary_len);
            } else {
                err = lzo1z_999_compress(in, insz, out, &len, wrkmem);
            }
            break;
        }
        default: {
            fprintf(stderr, "\nError: unsupported LZO compression %d\n", type);
            return -1;
            break;
        }
    }
#endif
    if(err != LZO_E_OK) {
        fprintf(stderr, "\nError: LZO compression (%d)\n", err);
        return -1;
    }
    return len;
}



int ucl_compress(u8 *in, int insz, u8 *out, int outsz, int type) {
#ifdef DISABLE_UCL
    fprintf(stderr, "\nError: UCL support has been disabled in this build\n");
    return -1;
#else
    ucl_uint    len;
    int         err = UCL_E_OK;

    len = outsz;
    switch(type) {
        case COMP_NRV2b_COMPRESS: err = ucl_nrv2b_99_compress(in, insz, out, &len, NULL, 10, NULL, NULL); break;
        case COMP_NRV2d_COMPRESS: err = ucl_nrv2d_99_compress(in, insz, out, &len, NULL, 10, NULL, NULL); break;
        case COMP_NRV2e_COMPRESS: err = ucl_nrv2e_99_compress(in, insz, out, &len, NULL, 10, NULL, NULL); break;
        default: {
            fprintf(stderr, "\nError: unsupported UCL compression %d\n", type);
            return -1;
            break;
        }
    }
    if((err != UCL_E_OK) && (err != UCL_E_INPUT_NOT_CONSUMED)) {
        fprintf(stderr, "\nError: the compressed UCL input is wrong or incomplete (%d)\n", err);
        return -1;
    }
    return len;
#endif
}



int ucl_decompress(u8 *in, int insz, u8 *out, int outsz, int type) {
#ifdef DISABLE_UCL
    fprintf(stderr, "\nError: UCL support has been disabled in this build\n");
    return -1;
#else
    ucl_uint    len;
    int         i,
                err = UCL_E_OK;

    #define ucl_decompress_scan(X,Y) \
        err = ucl_nrv##X##_decompress_safe_##Y(in, insz, out, &len, NULL)

    #define ucl_decompress_scan2(X) { \
                 if(i == 0) ucl_decompress_scan(X, 8); \
            else if(i == 1) ucl_decompress_scan(X, le32); \
            else if(i == 2) ucl_decompress_scan(X, le16); \
            else return -1; \
        }

    for(i = 0;; i++) {
        len = outsz;
        switch(type) {
            case COMP_NRV2b: ucl_decompress_scan2(2b) break;
            case COMP_NRV2d: ucl_decompress_scan2(2d) break;
            case COMP_NRV2e: ucl_decompress_scan2(2e) break;
            default: return -1; break;
        }
        if((err == UCL_E_OK) || (err == UCL_E_INPUT_NOT_CONSUMED)) {
            return len;
        }
    }
    return -1;
#endif
}



static const u8 define_Z_FULL_FLUSH[12] = "Z_FULL_FLUSH";



#define ZIP_BASE(NAME,WBITS) \
int NAME(u8 *in, int insz, u8 *out, int outsz) { \
    static z_stream *z  = NULL; \
    int     no_error = 0; \
    int     ret, \
            sync = Z_FINISH; \
    \
    if(!in && !out) { \
        if(z) { \
            deflateEnd(z); \
            FREE(z); \
        } \
        z = NULL; \
        return -1; \
    } \
    \
    if(!z) { \
        z = calloc(sizeof(z_stream), 1); \
        if(!z) return -1; \
        memset(z, 0, sizeof(z_stream)); \
        if(deflateInit2(z, 9, Z_DEFLATED, WBITS, 9, Z_DEFAULT_STRATEGY)) { \
            fprintf(stderr, "\nError: zlib initialization error\n"); \
            return -1; \
        } \
    } \
    deflateReset(z); \
    \
    if(g_comtype_dictionary) { \
        if((g_comtype_dictionary_len >= sizeof(define_Z_FULL_FLUSH)) && !memcmp(g_comtype_dictionary, define_Z_FULL_FLUSH, sizeof(define_Z_FULL_FLUSH))) { \
            sync = Z_FULL_FLUSH; \
            if(g_comtype_dictionary_len > sizeof(define_Z_FULL_FLUSH)) deflateSetDictionary(z, g_comtype_dictionary + sizeof(define_Z_FULL_FLUSH), g_comtype_dictionary_len - sizeof(define_Z_FULL_FLUSH)); \
        } else { \
            deflateSetDictionary(z, g_comtype_dictionary, g_comtype_dictionary_len); \
        } \
    } \
    \
    z->next_in   = in; \
    z->avail_in  = insz; \
    z->next_out  = out; \
    z->avail_out = outsz; \
    ret = deflate(z, sync); \
    if((ret != Z_STREAM_END) && !no_error) { \
        fprintf(stderr, "\nError: the compressed zlib/deflate input is wrong or incomplete (%d)\n", ret); \
        return -1; \
    } \
    return z->total_out; \
}
ZIP_BASE(zlib_compress,    15)
ZIP_BASE(deflate_compress, -15)



#define UNZIP_BASE(NAME,WBITS) \
int NAME(u8 *in, int insz, u8 *out, int outsz, int no_error) { \
    static z_stream *z  = NULL; \
    int     ret, \
            sync = Z_FINISH; \
    \
    if(!in && !out) { \
        if(z) { \
            inflateEnd(z); \
            FREE(z); \
        } \
        z = NULL; \
        return -1; \
    } \
    \
    if(!z) { \
        z = calloc(sizeof(z_stream), 1); \
        if(!z) return -1; \
        memset(z, 0, sizeof(z_stream)); \
        if(inflateInit2(z, WBITS)) { \
            fprintf(stderr, "\nError: zlib initialization error\n"); \
            return -1; \
        } \
    } \
    inflateReset(z); \
    \
    if(g_comtype_dictionary) { \
        if((g_comtype_dictionary_len >= sizeof(define_Z_FULL_FLUSH)) && !memcmp(g_comtype_dictionary, define_Z_FULL_FLUSH, sizeof(define_Z_FULL_FLUSH))) { \
            sync = Z_FULL_FLUSH; \
            if(g_comtype_dictionary_len > sizeof(define_Z_FULL_FLUSH)) inflateSetDictionary(z, g_comtype_dictionary + sizeof(define_Z_FULL_FLUSH), g_comtype_dictionary_len - sizeof(define_Z_FULL_FLUSH)); \
        } else { \
            inflateSetDictionary(z, g_comtype_dictionary, g_comtype_dictionary_len); \
        } \
    } \
    \
    z->next_in   = in; \
    z->avail_in  = insz; \
    z->next_out  = out; \
    z->avail_out = outsz; \
    ret = inflate(z, sync); \
    if((ret != Z_STREAM_END) && !no_error) { \
        fprintf(stderr, "\nError: the compressed zlib/deflate input is wrong or incomplete (%d)\n", ret); \
        return -1; \
    } \
    return z->total_out; \
}
UNZIP_BASE(unzip_zlib,    15)
UNZIP_BASE(unzip_deflate, -15)



int unzip_dynamic(u8 *in, int insz, u8 **ret_out, int *ret_outsz, int fixed_wbits) {
    z_stream z;
    int     err,
            retsz,
            addsz,
            wbits,
            retry;

    if(fixed_wbits) {
        wbits = fixed_wbits;
    } else {
        if((in[0] == 0x78) || (in[0] == 0x68)) {    // just a simple guess to save time
            wbits = 15;     // zlib
        } else {
            wbits = -15;    // deflate
        }
    }

    retry = 0;
redo:
    memset(&z, 0, sizeof(z_stream));
    if(inflateInit2(&z, wbits)) {
        fprintf(stderr, "\nError: zlib initialization error\n");
        return -1;
    }

    addsz = insz / 4;
    if(!addsz) addsz = insz;
    not_ret_out_boh

    retsz = 0;
    z.next_in  = in;
    z.avail_in = insz;
    while(z.avail_in) {
        z.next_out  = *ret_out + retsz;
        z.avail_out = *ret_outsz - retsz;
        err = inflate(&z, Z_FINISH);
        retsz = (u8 *)z.next_out - *ret_out;
        if(err == Z_STREAM_END) break;
        if(((err == Z_OK) && z.avail_in) || (err == Z_BUF_ERROR)) {
            if(!z.avail_out) myalloc(ret_out, *ret_outsz + addsz, ret_outsz);
        } else {
            //if(retsz <= 0) {
                //printf("\nError: invalid zlib compressed data (%d)\n", err);
                retsz = -1;
            //}
            break;
        }
    }
    inflateEnd(&z);
    if(retsz < 0) {
        if(!fixed_wbits) {
            if(wbits > 0) { // zlib->deflate
                wbits = -15;
            } else {        // deflate->zlib
                wbits = 15;
            }
            retry++;
            if(retry < 2) goto redo;
        }
        myalloc(ret_out, insz, ret_outsz);
        memcpy(*ret_out, in, insz);
        retsz = insz;
    }
    return retsz;
}



#ifdef WIN32    // it's a zlib with the adding of inflateBack9 which is not default
#include "compression/infback9.h"
typedef struct {
    u8      *p;
    u8      *l;
} zlib_func_t;
static unsigned zlib_inf(zlib_func_t *data, u8 **ret) {
    unsigned    len;

    *ret = data->p;
    len = data->l - data->p;
    data->p += len;
    return len;
}
static int zlib_outf(zlib_func_t *data, u8 *buff, int len) {
    //int     size = data->l - data->p;
    if((data->p + len) > data->l) return -1;
    memcpy(data->p, buff, len);
    data->p += len;
    return 0;
}
int inflate64(u8 *in, int insz, u8 *out, int outsz) {
    static unsigned char *window = NULL;    // from gun.c
    zlib_func_t myin,
                myout;
    z_stream z; // I don't know if inflate64 supports Reset
    int     ret;

    if(!window) {
        window = malloc(65536);
        if(!window) return -1;
    }

    memset(&z, 0, sizeof(z_stream));
    if(inflateBack9Init(&z, window)) {
        fprintf(stderr, "\nError: inflate64 initialization error\n");
        return -1;
    }

    if(g_comtype_dictionary) {    // supported?
        inflateSetDictionary(&z, g_comtype_dictionary, g_comtype_dictionary_len);
    }

    myin.p  = in;
    myin.l  = in + insz;
    myout.p = out;
    myout.l = out + outsz;

    z.next_in   = in;
    z.avail_in  = insz;
    z.next_out  = out;
    z.avail_out = outsz;
    ret = inflateBack9(&z,
        (void *)zlib_inf,  &myin,
        (void *)zlib_outf, &myout);
    if(ret != Z_STREAM_END) {
        inflateBack9End(&z);    // reset not supported by inflate9
        fprintf(stderr, "\nError: the compressed deflate64 input is wrong or incomplete (%d)\n", ret);
        return -1;
    }

    outsz = myout.p - out;
    inflateBack9End(&z);
    return(outsz);
}
#else
int inflate64(u8 *in, int insz, u8 *out, int outsz) {
    fprintf(stderr, "\nError: inflate64 is not supported on this platform\n");
    myexit(QUICKBMS_ERROR_COMPRESSION);
    return -1;
}
#endif



int unbzip2(u8 *in, int insz, u8 *out, int outsz) { // no reset in bzlib
    int     err;

    err = BZ2_bzBuffToBuffDecompress(out, &outsz, in, insz, 0, 0);
    if(err != BZ_OK) {
        fprintf(stderr, "\nError: invalid bz2 compressed data (%d)\n", err);
        return -1;
    }
    return(outsz);
}



int bzip2_compress(u8 *in, int insz, u8 *out, int outsz) {
    int     err;

    err = BZ2_bzBuffToBuffCompress(out, &outsz, in, insz, 9, 0, 0);
    if(err != BZ_OK) {
        fprintf(stderr, "\nError: invalid bz2 compressed data (%d)\n", err);
        return -1;
    }
    return(outsz);
}



int unbzip2_file(u8 *in, int insz, u8 **ret_out, int *ret_outsz) { // no reset in bzlib
    bz_stream bz;
    int     err,
            retsz,
            addsz;

    bz.bzalloc = NULL;
    bz.bzfree  = NULL;
    bz.opaque  = NULL;
    if(BZ2_bzDecompressInit(&bz, 0, 0)
      != BZ_OK) return -1;

    addsz = insz / 4;
    if(!addsz) addsz = insz;
    not_ret_out_boh

    retsz = 0;
    bz.next_in  = in;
    bz.avail_in = insz;
    while(bz.avail_in) {
        bz.next_out  = *ret_out + retsz;
        bz.avail_out = *ret_outsz - retsz;
        err = BZ2_bzDecompress(&bz);
        retsz = (u8 *)bz.next_out - *ret_out;
        if(err == BZ_STREAM_END) break;
        if(((err == BZ_OK) && bz.avail_in) || (err == BZ_OUTBUFF_FULL)) {
            if(!bz.avail_out) myalloc(ret_out, *ret_outsz + addsz, ret_outsz);
        } else {
            //if(retsz <= 0) {
                fprintf(stderr, "\nError: invalid bz2 compressed data (%d)\n", err);
                retsz = -1;
            //}
            break;
        }
    }
    BZ2_bzDecompressEnd(&bz);
    return(retsz);
}



u32 swap32be(u32 n);
u32 swap32le(u32 n);
int unxmemlzx(u8 *in, int insz, u8 **ret_out, int *ret_outsz) {
#ifdef WIN32
    typedef VOID*                       XMEMDECOMPRESSION_CONTEXT;
    typedef enum _XMEMCODEC_TYPE {
        XMEMCODEC_DEFAULT =             0,
        XMEMCODEC_LZX =                 1
    } XMEMCODEC_TYPE;
    typedef struct _XMEMCODEC_PARAMETERS_LZX {
        DWORD Flags;
        DWORD WindowSize;
        DWORD CompressionPartitionSize;
    } XMEMCODEC_PARAMETERS_LZX;
    HRESULT WINAPI XMemCreateDecompressionContext(
        XMEMCODEC_TYPE                  CodecType,
        CONST VOID*                     pCodecParams,
        DWORD                           Flags,
        XMEMDECOMPRESSION_CONTEXT*      pContext
    );
    HRESULT WINAPI XMemDecompress(
        XMEMDECOMPRESSION_CONTEXT       Context,
        VOID*                           pDestination,
        SIZE_T*                         pDestSize,
        CONST VOID*                     pSource,
        SIZE_T                          SrcSize
    );
    HRESULT WINAPI XMemDecompressSegmentTD(
        XMEMDECOMPRESSION_CONTEXT       Context,
        VOID*                           pDestination,
        SIZE_T*                         pDestSize,
        CONST VOID*                     pSource,
        SIZE_T                          SrcSize,
        SIZE_T                          DestSize,
        SIZE_T                          Offset
    );
    VOID WINAPI XMemDestroyDecompressionContext(
        XMEMDECOMPRESSION_CONTEXT       Context
    );

    //#define XCOMPRESS_FILE_IDENTIFIER_LZXTDECODE        0x0FF512ED
    #pragma pack(2)
    typedef struct {
        u32     Identifier;
        u16     Version;
        u16     Reserved;
        u32     CRC_Hash;
        u32     Flags;
    } xcompress_decode_t;
    #pragma pack()

    //#define XCOMPRESS_FILE_IDENTIFIER_LZXNATIVE         0x0FF512EE
    #pragma pack(2)
    typedef struct {
        u32     Identifier;
        u16     Version;
        u16     Reserved;
        u32     ContextFlags;
          u32   Flags;
          u32   WindowSize;
          u32   CompressionPartitionSize;
        u32     UncompressedSizeHigh;
        u32     UncompressedSizeLow;
        u32     CompressedSizeHigh;
        u32     CompressedSizeLow;
        u32     UncompressedBlockSize;
        u32     CompressedBlockSizeMax;
    } xcompress_native_t;
    #pragma pack()

    XMEMDECOMPRESSION_CONTEXT ctx = NULL;
    XMEMCODEC_PARAMETERS_LZX  param;
    xcompress_native_t  *xcompress_native = NULL;
    xcompress_decode_t  *xcompress_decode = NULL;
    SIZE_T  ret,
            t;
    HRESULT hr;
    int     i;

    not_ret_out_boh

    if(insz > 4) {
        u32 (*swap)(u32 n) = swap32be;
        u32     CompressedBlockSize,
                UncompressedBlockSize,
                Flags;
        u64     CompressedSize,
                UncompressedSize;
        u8      *inl = in + insz;

        if(!memcmp(in, "\x0F\xF5\x12\xEE", 4)) {        // big
            xcompress_native = (void *)in;
            swap = swap32be;
        } else if(!memcmp(in, "\xee\x12\xf5\x0f", 4)) { // little?
            xcompress_native = (void *)in;
            swap = swap32le;
        } else if(!memcmp(in, "\x0F\xF5\x12\xED", 4)) { // big
            xcompress_decode = (void *)in;
            swap = swap32be;
        } else if(!memcmp(in, "\xed\x12\xf5\x0f", 4)) { // little?
            xcompress_decode = (void *)in;
            swap = swap32le;
        }

        if(xcompress_decode) {
            Flags = swap(xcompress_decode->Flags);

            int Segments = (Flags >> 6) & 0xffff;
            static const int BitsPerSize_Table[4] = { 20, 32, 0, 0 };   // only 2 types exist
            int BitsPerSize = BitsPerSize_Table[(Flags >> 0x16) & 3];
            int CompressedBlockSize = 0x8000 << ((Flags >> 4) & 3);

            u8 *segment = in;

            in += sizeof(xcompress_decode_t);
            if(in > inl) { ret = -1; goto quit; }

            t = 20;
            if(Flags & 0x00c00000) t += 12;
            t = ((t * Segments) + 31) >> 5;

            u8 *p = in + (t * 4);
            if(p > inl) { ret = -1; goto quit; }

            param.Flags = 0;
            param.WindowSize = 1 << ((Flags & 0xf) + 0xf);
            param.CompressionPartitionSize = 0;
            hr = XMemCreateDecompressionContext(
                XMEMCODEC_DEFAULT,
                &param,
                0x80000000,
                &ctx);
            if(hr != S_OK) { ret = -1; goto quit; }

            int     extract;
            u8      *backup_in = in;
            for(extract = 0; extract < 2; extract++) {
                u32     bits = 0,   // keep them here!
                        old  = 0,
                        num  = 0;
                ret = 0;
                in = backup_in;
                for(i = 0; i < Segments; i++) {
                    if(BitsPerSize & 31) {
                        bits = (bits + BitsPerSize) & 31;
                        if((bits > 0) && (bits <= BitsPerSize)) {
                            num = swap(QUICK_GETi32(in, 0));
                            in += 4;
                        } else {
                            num = old;
                            old = 0;
                        }
                        UncompressedBlockSize = (num >> (32 - bits)) | (old << bits);
                        old = num & ((1 << (32 - bits)) - 1);
                    } else {
                        UncompressedBlockSize = swap(QUICK_GETi32(in, 0));
                        in += 4;
                    }
                    if(!extract) {
                        ret += UncompressedBlockSize;
                    } else {
                        u32 Offset;
                        for(Offset = 0; Offset < UncompressedBlockSize; Offset += t) {
                            if(p > inl) { ret = -1; goto quit; }
                            t = UncompressedBlockSize - Offset;
                            if(t > CompressedBlockSize) t = CompressedBlockSize;
                            hr = XMemDecompressSegmentTD(ctx, *ret_out + ret, &t, p, CompressedBlockSize - (p - segment), UncompressedBlockSize, Offset);
                            if(hr != S_OK) { ret = -1; goto quit; }
                            ret += t;
                        }
                        segment += CompressedBlockSize;
                        p = segment;
                    }
                }
                if(!extract) {
                    myalloc(ret_out, ret, ret_outsz);
                }
            }

            goto quit;
        }

        if(xcompress_native) {
            Flags = swap(xcompress_native->Flags);
            xcompress_native->WindowSize = swap(xcompress_native->WindowSize);
            xcompress_native->CompressionPartitionSize = swap(xcompress_native->CompressionPartitionSize);
            UncompressedSize = ((u64)swap(xcompress_native->UncompressedSizeHigh) << (u64)32) | (u64)swap(xcompress_native->UncompressedSizeLow);
            CompressedSize   = ((u64)swap(xcompress_native->CompressedSizeHigh)   << (u64)32) | (u64)swap(xcompress_native->CompressedSizeLow);

            in += sizeof(xcompress_native_t);
            if(in > inl) { ret = -1; goto quit; }
            if((inl - in) < CompressedSize) { ret = -1; goto quit; }

            param.Flags = Flags;
            param.WindowSize = xcompress_native->WindowSize;
            param.CompressionPartitionSize = xcompress_native->CompressionPartitionSize;
            XMemCreateDecompressionContext(
                XMEMCODEC_DEFAULT,
                &param,
                0,
                &ctx);

            myalloc(ret_out, UncompressedSize, ret_outsz);

            for(ret = 0; (in < inl) && (ret < UncompressedSize); ret += t, in += CompressedBlockSize) {
                CompressedBlockSize = swap(QUICK_GETi32(in, 0));
                in += 4;
                if((in + CompressedBlockSize) < in)  { ret = -1; goto quit; }
                if((in + CompressedBlockSize) > inl) { ret = -1; goto quit; }
                t = UncompressedSize - ret;

                // normal version - DO NOT USE IT!!! it crashes with dsh_situation.xmac!
                //hr = XMemDecompress(ctx, *ret_out + ret, &t, in, CompressedBlockSize);

                // alternative version: added only to grant 100% compatibility (like the DMC4 note below) but it's useless
                u8      tmp[MYALLOC_ZEROES];
                memcpy(tmp, in + CompressedBlockSize, MYALLOC_ZEROES);
                memset(in + CompressedBlockSize, 0, MYALLOC_ZEROES);
                hr = XMemDecompress(ctx, *ret_out + ret, &t, in, CompressedBlockSize + MYALLOC_ZEROES);
                memcpy(in + CompressedBlockSize, tmp, MYALLOC_ZEROES);

                if(hr != S_OK) { ret = -1; goto quit; }
            }
            goto quit;
        }
    }

    if(g_comtype_dictionary) {
        param.Flags = 0;
        param.WindowSize = 128 * 1024;
        param.CompressionPartitionSize = 512 * 1024;
        //sscanf(g_comtype_dictionary, "%d %d",
        get_parameter_numbers(g_comtype_dictionary,
            (int *)&param.WindowSize, (int *)&param.CompressionPartitionSize, NULL);
    }

    // XMemResetDecompressionContext is used only for the streams

    hr = XMemCreateDecompressionContext(
        XMEMCODEC_DEFAULT,
        g_comtype_dictionary ? &param : NULL,
        0,  // or also 0x80000000 but it seems the same
        &ctx);
    if(hr != S_OK) { ret = -1; goto quit; }

    ret = *ret_outsz;
    hr = XMemDecompress(ctx, *ret_out, &ret, in, insz + MYALLOC_ZEROES); // + MYALLOC_ZEROES: ehmmmm long story, watch myalloc() and DMC4
    if(hr != S_OK) { ret = -1; goto quit; }

quit:
    if(ctx) XMemDestroyDecompressionContext(ctx);
    return ret;
#else
    fprintf(stderr, "\nError: XMemDecompress is implemented only on Windows\n");
    return -1;
#endif
}



int xmem_compress(u8 *in, int insz, u8 *out, int outsz) {
#ifdef WIN32
    typedef VOID*                       XMEMCOMPRESSION_CONTEXT;
    typedef enum _XMEMCODEC_TYPE {
        XMEMCODEC_DEFAULT =             0,
        XMEMCODEC_LZX =                 1
    } XMEMCODEC_TYPE;
    typedef struct _XMEMCODEC_PARAMETERS_LZX {
        DWORD Flags;
        DWORD WindowSize;
        DWORD CompressionPartitionSize;
    } XMEMCODEC_PARAMETERS_LZX;
    HRESULT WINAPI XMemCreateCompressionContext(
        XMEMCODEC_TYPE                  CodecType,
        CONST VOID*                     pCodecParams,
        DWORD                           Flags,
        XMEMCOMPRESSION_CONTEXT*        pContext
    );
    HRESULT WINAPI XMemCompress(
        XMEMCOMPRESSION_CONTEXT         Context,
        VOID*                           pDestination,
        SIZE_T*                         pDestSize,
        CONST VOID*                     pSource,
        SIZE_T                          SrcSize
    );
    VOID WINAPI XMemDestroyCompressionContext(
        XMEMCOMPRESSION_CONTEXT         Context
    );

    XMEMCOMPRESSION_CONTEXT   ctx;
    XMEMCODEC_PARAMETERS_LZX  param;
    SIZE_T  ret;
    HRESULT hr;

    if(g_comtype_dictionary) {
        param.Flags = 0;
        param.WindowSize = 128 * 1024;
        param.CompressionPartitionSize = 512 * 1024;
        //sscanf(g_comtype_dictionary, "%d %d",
        get_parameter_numbers(g_comtype_dictionary,
            (int *)&param.WindowSize, (int *)&param.CompressionPartitionSize, NULL);
    }

    hr = XMemCreateCompressionContext(
        XMEMCODEC_DEFAULT,
        g_comtype_dictionary ? &param : NULL,
        0,
        &ctx);
    if(hr != S_OK) { ret = -1; goto quit; }

    // XMemResetCompressionContext is used only for the streams

    ret = outsz;
    hr = XMemCompress(ctx, out, &ret, in, insz); // no MYALLOC_ZEROES!
    if(hr != S_OK) { ret = -1; goto quit; }

quit:
    if(ctx) XMemDestroyCompressionContext(ctx);
    return ret;
#else
    fprintf(stderr, "\nError: XMemCompress is implemented only on Windows\n");
    return -1;
#endif
}



int hex2byte(u8 *hex) {
    static const signed char hextable[256] =
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff"
        "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

    if((hextable[hex[0]] < 0) || (hextable[hex[1]] < 0)) return -1;
    return((hextable[hex[0]] << 4) | hextable[hex[1]]);
}



// automatically does: hexadecimal, quoted printable, percentage encoding
int unhex(u8 *in, int insz, u8 *out, int outsz) {
    QUICK_IN_OUT
    int     c;

    while(in < inl) {
        c = hex2byte(in);
        if(c < 0) {
            in++;
        } else {
            if(o >= outl) return -1;
            *o++ = c;
            in += 2;
        }
    }
    return o - out;
}



int unbase64(u8 *in, int insz, u8 *out, int outsz) {
    int     xlen,
            a   = 0,
            b   = 0,
            c,
            step;
    u8      *limit,
            *data,
            *p;
    static const u8 base[128] = {   // supports also the Gamespy base64 and URLs
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3e,0x00,0x3e,0x00,0x3f,
        0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
        0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x3e,0x00,0x3f,0x00,0x3f,
        0x00,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x00,0x00,0x00,0x00,0x00
    };

    if(insz < 0) insz = strlen(in);
    xlen = ((insz >> 2) * 3) + 1;    // NULL included in output for text
    if((in != out) && (outsz >= 0)) {
        if(outsz < xlen) return -1;
    } else {
        outsz = xlen;
    }
    data = in;

    p = out;
    limit = data + insz;

    for(step = 0; /* data < limit */; step++) {
        do {
            if(data >= limit) {
                c = 0;
                break;
            }
            c = *data;
            data++;
            if((c == '=') || (c == '_')) {  // supports also the Gamespy base64
                c = 0;
                break;
            }
        } while(c && ((c <= ' ') || (c > 0x7f)));
        if(!c) break;

        switch(step & 3) {
            case 0: {
                a = base[c];
                break;
            }
            case 1: {
                b = base[c];
                *p++ = (a << 2)        | (b >> 4);
                break;
            }
            case 2: {
                a = base[c];
                *p++ = ((b & 15) << 4) | (a >> 2);
                break;
            }
            case 3: {
                *p++ = ((a & 3) << 6)  | base[c];
                break;
            }
        }
    }
    *p = 0;
    return(p - out);
}



int unexplode(u8 *in, int insz, u8 *out, int outsz) {
typedef struct {
    u8      *in;
    int     insz;
    int     outsz;
} explode_info_t;

unsigned explode_read(void *how, unsigned char **buf) {
    explode_info_t *explode_info;

    explode_info = (explode_info_t *)how;
    *buf = explode_info->in;
    return(explode_info->insz);
}
int explode_write(void *how, unsigned char *buf, unsigned len) {
    explode_info_t *explode_info;

    explode_info = (explode_info_t *)how;
    explode_info->outsz = len;
    return 0;
}

    explode_info_t explode_info;

    explode_info.in    = in;
    explode_info.insz  = insz;
    explode_info.outsz = -1;

    blast(explode_read, &explode_info, explode_write, &explode_info, out, outsz);
    return(explode_info.outsz);
}



char *lzma_status_code(int code) {
    switch(code) {
        case SZ_OK: return "OK"; break;
        case SZ_ERROR_DATA: return "ERROR_DATA"; break;
        case SZ_ERROR_MEM: return "ERROR_MEM"; break;
        case SZ_ERROR_CRC: return "ERROR_CRC"; break;
        case SZ_ERROR_UNSUPPORTED: return "ERROR_UNSUPPORTED"; break;
        case SZ_ERROR_PARAM: return "ERROR_PARAM"; break;
        case SZ_ERROR_INPUT_EOF: return "ERROR_INPUT_EOF"; break;
        case SZ_ERROR_OUTPUT_EOF: return "ERROR_OUTPUT_EOF"; break;
        case SZ_ERROR_READ: return "ERROR_READ"; break;
        case SZ_ERROR_WRITE: return "ERROR_WRITE"; break;
        case SZ_ERROR_PROGRESS: return "ERROR_PROGRESS"; break;
        case SZ_ERROR_FAIL: return "ERROR_FAIL"; break;
        case SZ_ERROR_THREAD: return "ERROR_THREAD"; break;
        case SZ_ERROR_ARCHIVE: return "ERROR_ARCHIVE"; break;
        case SZ_ERROR_NO_ARCHIVE: return "ERROR_NO_ARCHIVE"; break;
        default: return "unknown error"; break;
    }
    return "";
}



void lzma_set_properties(CLzmaEncProps *props, int dictsz) {
        props->level = 9;            /*  0 <= level <= 9 */
        props->dictSize = 1<<dictsz; /* (1 << 12) <= dictSize <= (1 << 27) for 32-bit version
                                       (1 << 12) <= dictSize <= (1 << 30) for 64-bit version
                                       default = (1 << 24) */
        // xz wants lc+lp <= 4
        //props->lc = 1;               /* 0 <= lc <= 8, default = 3 */
        //props->lp = 3;               /* 0 <= lp <= 4, default = 0 */
        props->lc = 8;               /* 0 <= lc <= 8, default = 3 */
        props->lp = 4;               /* 0 <= lp <= 4, default = 0 */

        props->pb = 0; /* yeah 0!*/  /* 0 <= pb <= 4, default = 2 */
        //props->algo = 1;             /* 0 - fast, 1 - normal, default = 1 */
        props->fb = 273;             /* 5 <= fb <= 273, default = 32 */
        //props->btMode = 1;           /* 0 - hashChain Mode, 1 - binTree mode - normal, default = 1 */
        props->numHashBytes = 4;     /* 2, 3 or 4, default = 4 */
        //props->mc = (1 << 30);       /* 1 <= mc <= (1 << 30), default = 32 */

    props->writeEndMark = 1;
    props->numThreads = get_cpu_number();
    // if(props->numThreads <= 0) LZMA will fix it automatically
}



#define LZMA_COMPRESS_SET_FLAGS \
    if(flags & LZMA_FLAGS_EFS) { \
        if(outsz < 4) return(-2); \
        o[0] = 0; \
        o[1] = 0 >> 8; \
        o[2] = propsz; \
        o[3] = propsz >> 8; \
        o     += 4; \
        outsz -= 4; \
    } \
    if(flags & LZMA_FLAGS_86_DECODER) { \
        if(outsz < 1) return(-3); \
        o[0] = filter; \
        o++; \
        outsz--; \
    } \
    if(flags & LZMA_FLAGS_86_HEADER) { \
        if(outsz < 8) return(-4); \
        o[0] = insz; \
        o[1] = insz >> 8; \
        o[2] = insz >> 16; \
        o[3] = insz >> 24; \
        o[4] = 0; \
        o[5] = 0; \
        o[6] = 0; \
        o[7] = 0; \
        o     += 8; \
        outsz -= 8; \
    } \


    
int lzma_compress(u8 *in, int insz, u8 *out, int outsz, int flags) {
void *SzAlloc(void *p, size_t size) { return(real_calloc(size, 1)); }  // xmalloc doesn't return in case of error
void SzFree(void *p, void *address) { if(address) real_free(address); }
ISzAlloc g_Alloc = { SzAlloc, SzFree };

	CLzmaEncHandle  lzma;
    CLzmaEncProps   props;
    SizeT   t,
            outlen;
    int     err,
            filter  = 0,
            propsz  = 5,
            dictsz  = 27;   // it means: allocate (1 << (dictsz + 2)) bytes
    u8      *o;

    lzma = LzmaEnc_Create(&g_Alloc);
	if(!lzma) return -1;

redo:
    o = out;
    LzmaEncProps_Init(&props);
    LzmaEncProps_Normalize(&props);

    lzma_set_properties(&props, dictsz);

    LzmaEnc_SetProps(lzma, &props);

    if(flags & LZMA_FLAGS_PROP0) {
        propsz = 0;
    } else {
        t = outsz;
        LzmaEnc_WriteProperties(lzma, o, &t);
        propsz = t;
        o     += propsz;
        outsz -= propsz;
    }

        /* flags */

    LZMA_COMPRESS_SET_FLAGS

        /* compression */

    outlen = outsz;
    err = LzmaEnc_MemEncode(lzma, o, &outlen, in, insz, props.writeEndMark, NULL, &g_Alloc, &g_Alloc);
    if((err == SZ_ERROR_PARAM) || (err == SZ_ERROR_MEM)) {
        dictsz--;
        if(dictsz >= 12) goto redo;
    }
    if(err != SZ_OK) {
        LzmaEnc_Destroy(lzma, &g_Alloc, &g_Alloc);
        fprintf(stderr, "\nError: lzma error %s\n", lzma_status_code(err));
        return -5;
    }
    LzmaEnc_Destroy(lzma, &g_Alloc, &g_Alloc);
    return((o - out) + outlen);
}



SRes myLzma2Enc_MemEncode(CLzma2EncHandle pp, Byte *dest, SizeT *destLen, const Byte *src, SizeT srcLen,
    int writeEndMark, ICompressProgress *progress)
{
    SizeT   remaining = *destLen;
    int     overflow = 0;

    SRes myLzma2Enc_read(void *p, void *buf, size_t *size) {
        size_t  len;
        len = srcLen;
        if(len) {
            if(len > *size) len = *size;
            memcpy(buf, src, len);
            src    += len;
            srcLen -= len;
        }
        *size   = len;
        return SZ_OK;
    }
    
    size_t myLzma2Enc_write(void *p, const void *buf, size_t size) {
        size_t  len;
        len = remaining;
        if(len) {
            if(len > size) len = size;
            memcpy(dest, buf, len);
            dest      += len;
            remaining -= len;
        } else {
            overflow = 1;
        }
        return len;
    }


  SRes res;
  
  ISeqInStream  inz;
  inz.Read = myLzma2Enc_read;
  ISeqOutStream outz;
  outz.Write = myLzma2Enc_write;
  
  res = Lzma2Enc_Encode(pp, &outz, &inz, progress);

  *destLen -= remaining;    // write the bytes that we have written (max_size - available_size = written_size)
  
  if (overflow)
    return SZ_ERROR_OUTPUT_EOF;
  return res;
}



int lzma2_compress(u8 *in, int insz, u8 *out, int outsz, int flags) {
void *SzAlloc(void *p, size_t size) { return(real_calloc(size, 1)); }  // xmalloc doesn't return in case of error
void SzFree(void *p, void *address) { if(address) real_free(address); }
ISzAlloc g_Alloc = { SzAlloc, SzFree };

	CLzma2EncHandle  lzma2;
    CLzma2EncProps   props;
    SizeT   outlen;
    int     err,
            filter  = 0,
            propsz  = 1,
            dictsz  = 27;   // it means: allocate (1 << (dictsz + 2)) bytes
    u8      *o;

    lzma2 = Lzma2Enc_Create(&g_Alloc, &g_Alloc);
	if(!lzma2) return -1;

redo:
    o = out;
    Lzma2EncProps_Init(&props);
    Lzma2EncProps_Normalize(&props);

    lzma_set_properties(&props.lzmaProps, dictsz);
    
    props.numBlockThreads = props.lzmaProps.numThreads;
    props.numTotalThreads = props.lzmaProps.numThreads;
    
    Lzma2Enc_SetProps(lzma2, &props);

    if(flags & LZMA_FLAGS_PROP0) {
        propsz = 0;
    } else {
        *o = Lzma2Enc_WriteProperties(lzma2);
        o     += propsz;
        outsz -= propsz;
    }

        /* flags */

    LZMA_COMPRESS_SET_FLAGS

        /* compression */

    outlen = outsz;
    err = myLzma2Enc_MemEncode(lzma2, o, &outlen, in, insz, props.lzmaProps.writeEndMark, NULL);
    if((err == SZ_ERROR_PARAM) || (err == SZ_ERROR_MEM)) {
        dictsz--;
        if(dictsz >= 12) goto redo;
    }
    if(err != SZ_OK) {
        Lzma2Enc_Destroy(lzma2);
        fprintf(stderr, "\nError: lzma2 error %s\n", lzma_status_code(err));
        return -5;
    }
    Lzma2Enc_Destroy(lzma2);
    return((o - out) + outlen);
}



void show_lzma_error(int status) {
    fprintf(stderr, "\nError: the compressed LZMA input is wrong or incomplete (%d)\n", status);
    switch(status) {
        case LZMA_STATUS_NOT_FINISHED:                  fprintf(stderr, "       stream was not finished\n"); break;
        case LZMA_STATUS_NEEDS_MORE_INPUT:              fprintf(stderr, "       you must provide more input bytes\n"); break;
        case LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK:   fprintf(stderr, "       there is probability that stream was finished without end mark\n"); break;
        default: break;
    }
}



// Some notes about why lzma_dynamic (auto_size != 0) works on some files and lzma doesn't.
// Some games truncate the compressed data before the end and so the lzma API returns
// LZMA_STATUS_NEEDS_MORE_INPUT which is considered (correctly) an error.
// lzma_dynamic instead ignores the error and so it's able to dump the data.

// LZMA_FLAGS_EFS: 2 bytes version, 2 bytes props size, props and data
#define LZMA2_PROPS_SIZE    1
static const u8 lzma_default_prop[]  = "\x5d" "\x00\x00\x00\x01";  // 16Mb dictionary size, default for lzma
static const u8 lzma2_default_prop[] = "\x18";

#define UNLZMA_BASE(LZMA_VER) \
int unlzma##LZMA_VER(u8 *in, int insz, u8 **ret_out, int outsz, int lzma_flags, int *ret_outsz, int auto_size) { \
void *SzAlloc(void *p, size_t size) { return real_calloc(size, 1); } \
void SzFree(void *p, void *address) { if(address) real_free(address); } \
ISzAlloc g_Alloc = { SzAlloc, SzFree }; \
    \
    CLzma##LZMA_VER##Dec    lzma; \
    ELzmaStatus status; \
    SizeT   inlen, \
            outlen; \
    int     i, \
            backup_insz, \
            backup_outsz, \
            init    = 0, \
            x86State, \
            filter  = 0, \
            propsz  = LZMA##LZMA_VER##_PROPS_SIZE; \
    u8      *out, \
            *prop   = NULL, \
            *backup_in; \
    \
    backup_in    = in; \
    backup_insz  = insz; \
    backup_outsz = outsz; \
    \
    if(lzma_flags & LZMA_FLAGS_PROP0) { \
        prop   = (u8 *)lzma##LZMA_VER##_default_prop; \
        propsz = sizeof(lzma##LZMA_VER##_default_prop) - 1; \
        if(g_comtype_dictionary) { \
            prop   = g_comtype_dictionary; \
            propsz = g_comtype_dictionary_len; \
        } \
    } \
    \
    if(lzma_flags & LZMA_FLAGS_EFS) { \
        if(insz < 4) { outlen = -1; goto quit; } \
        propsz = in[2] | (in[3] << 8); \
        in   += 4; \
        insz -= 4; \
    } \
    \
    if(lzma_flags & LZMA_FLAGS_86_DECODER) { \
        if(insz < 1) { outlen = -2; goto quit; } \
        filter = in[0]; \
        in   += 1; \
        insz -= 1; \
    } \
    \
    if(insz < propsz) { outlen = -3; goto quit; } \
    if(!prop) { \
        prop   = in; \
        in   += propsz; \
        insz -= propsz; \
    } \
    \
    not_ret_out_boh \
    out = *ret_out; \
    if(lzma_flags & LZMA_FLAGS_86_HEADER) { \
        if(insz < 8) { outlen = -4; goto quit; } \
        i = QUICK_GETi32(in, 0); \
        if(i < 0) { outlen = -5; goto quit; } \
        if(!auto_size) { \
            outsz = i; \
            myalloc(&out, outsz, ret_outsz); \
            *ret_out = out; \
        } \
        in   += 8; \
        insz -= 8; \
    } \
    \
    inlen  = insz; \
    outlen = outsz; \
    \
    memset(&lzma, 0, sizeof(lzma)); \
    Lzma##LZMA_VER##Dec_Construct(&lzma); \
    if((void *)Lzma##LZMA_VER##Dec_Allocate == (void *)Lzma2Dec_Allocate) { \
        if(Lzma2Dec_Allocate((void *)&lzma, prop[0], &g_Alloc) != SZ_OK) { \
            if(Lzma2Dec_AllocateProbs((void *)&lzma, prop[0], &g_Alloc) != SZ_OK) { outlen = -6; goto quit; } \
        } \
    } else { \
        if(LzmaDec_Allocate((void *)&lzma, prop, propsz, &g_Alloc) != SZ_OK) { \
            if(LzmaDec_AllocateProbs((void *)&lzma, prop, propsz, &g_Alloc) != SZ_OK) { outlen = -7; goto quit; } \
        } \
    } \
    Lzma##LZMA_VER##Dec_Init(&lzma); \
    init = 1; \
    \
    int     r; \
    if(auto_size) { \
        int     _ip, \
                _ir, \
                _or, \
                outsz_inc; \
        \
        outsz_inc = outsz / 100; \
        if(!outsz_inc) outsz_inc++; \
        if(outsz_inc < (1024 * 1024)) outsz_inc = (1024 * 1024); \
        \
        outlen = 0; \
        for(_ip = 0; _ip < inlen; _ip += _ir) { \
            _or = outsz - outlen; \
            _ir = inlen - _ip; \
            r = Lzma##LZMA_VER##Dec_DecodeToBuf(&lzma, out + outlen, &_or, in + _ip, &_ir, LZMA_FINISH_ANY, &status); \
            if(r != SZ_OK) { \
                if(!auto_size) show_lzma_error(status); \
                outlen = -8; \
                goto quit; \
            } \
            outlen += _or; \
            if((status == LZMA_STATUS_FINISHED_WITH_MARK) || (status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK)) break; \
            \
            if(!_ir && !_or) { outlen = -10; goto quit; } \
            \
            outsz += outsz_inc; \
            if(outsz < 0) { outlen = -9; goto quit; } \
            myalloc(&out, outsz, ret_outsz); \
            *ret_out = out; \
        } \
    } else { \
        r = Lzma##LZMA_VER##Dec_DecodeToBuf(&lzma, out, &outlen, in, &inlen, LZMA_FINISH_END, &status); \
        if( \
            (r != SZ_OK) \
         || !((status == LZMA_STATUS_FINISHED_WITH_MARK) || (status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK))) { \
            if(!auto_size) show_lzma_error(status); \
            outlen = - (100 + status); \
            goto quit; \
        } \
    } \
    if(filter) { \
        x86_Convert_Init(x86State); \
        x86_Convert(out, outlen, 0, &x86State, 0); \
    } \
quit: \
    if(init) Lzma##LZMA_VER##Dec_Free(&lzma, &g_Alloc); \
    in    = backup_in; \
    insz  = backup_insz; \
    outsz = backup_outsz; \
    \
    if((int)outlen < 0) { \
        if(auto_size) { \
            static const int lzma_flags_scanner[] = { \
                LZMA_FLAGS_NONE, \
                LZMA_FLAGS_86_HEADER, \
                LZMA_FLAGS_86_DECODER, \
                LZMA_FLAGS_86_DECODER | LZMA_FLAGS_86_HEADER, \
                LZMA_FLAGS_EFS, \
                LZMA_FLAGS_PROP0 | LZMA_FLAGS_NONE, \
                LZMA_FLAGS_PROP0 | LZMA_FLAGS_86_HEADER, \
                LZMA_FLAGS_PROP0 | LZMA_FLAGS_86_DECODER, \
                LZMA_FLAGS_PROP0 | LZMA_FLAGS_86_DECODER | LZMA_FLAGS_86_HEADER, \
                LZMA_FLAGS_PROP0 | LZMA_FLAGS_EFS, \
                -1 \
            }; \
            for(i = 0; lzma_flags_scanner[i] >= 0; i++) { \
                if(lzma_flags != lzma_flags_scanner[i]) continue; \
                lzma_flags = lzma_flags_scanner[i + 1]; \
                if(lzma_flags < 0) break; \
                return unlzma##LZMA_VER(in, insz, ret_out, outsz, lzma_flags, ret_outsz, auto_size); \
            } \
            myalloc(ret_out, insz, ret_outsz); \
            memcpy(*ret_out, in, insz); \
            outlen = insz; \
        } \
    } \
    return outlen; \
}

UNLZMA_BASE()
UNLZMA_BASE(2)



int ungzip(u8 *in, int insz, u8 **ret_out, int *ret_outsz, int strict) {
    int     fsize = 0,
            guess_minsize;
    u8      flags,
            cm,
            *inl,
            *out;

    if(insz < 14) return -1;
    if(in[0] != 0x1f) return -1;
    not_ret_out_boh
    if(in[1] == 0x8b) {         // gzip
    } else if(in[1] == 0x9e) {  // old gzip
    } else if(in[1] == 0x1e) {  // pack
        return gz_unpack(in + 2, insz - 2, *ret_out, *ret_outsz);
    } else if(in[1] == 0x9d) {  // lzw (experimental with known size only)
        return uncompress_lzw(in + 3, insz - 3, *ret_out, *ret_outsz, in[2]);
    } else if(in[1] == 0xa0) {  // lzh (experimental with known size only)
        return unlzh(in + 2, insz - 2, *ret_out, *ret_outsz);
    } else return -1;
    inl = in + insz;

    // CRC32 and ISIZE
    if(strict) {
        inl -= 4;
        fsize = QUICK_GETi32(inl, 0);   // ISIZE
        inl -= 4;
        //QUICK_GETi32(inl, 0);   // CRC32

    } else {
        guess_minsize = (insz - 12);    // blah
        if(guess_minsize) guess_minsize -= (guess_minsize / 1000);  // blah
        if(guess_minsize < 0) guess_minsize = 0;
        for(inl -= 4; inl > in; inl--) {  // lame, simple and working
            //fsize = getxx(inl, 4);
            fsize = QUICK_GETi32(inl, 0); // little endian
            if(fsize < guess_minsize) continue;
            if(fsize > 0) break;
        }

        // The problem is caused by those gzip archives that don't have a size at the end,
        // so if we have one of these files we are unable to know where the compressed
        // stream really ends resulting in a partial output file.
        // And no, we cannot rely on the possible crc32 field because it's calculated on
        // the output data.
        // Example: the archives of the Anomaly games that contain gzip files without size at end.
        inl = in + insz;
    }
    
    // sometimes the gzip archives don't have the decompressed size at the end
    //if(fsize < insz) fsize = insz;
    if(fsize < 0) fsize = *ret_outsz;
    if(fsize > 0x40000000) fsize = *ret_outsz;  // ???

    in += 2;        // id1/id2
    cm = *in++;     // cm
    flags = *in++;  // flg
    in += 4;        // mtime
    in++;           // xfl
    in++;           // os
    if(flags & 4) {
        in += 2 + (in[0] | (in[1] << 8));
        if(in >= inl) return -1;
    }
    if(flags & 8)  in += strlen(in) + 1;    // name (adding support for names is chaotic and insecure)
    if(flags & 16) in += strlen(in) + 1;    // comment
    if(flags & 2)  in += 2;                 // crc
    if(in >= inl) return -1;

    out = *ret_out;
    myalloc(&out, fsize, ret_outsz);
    *ret_out = out;

    switch(cm) {    // based on the ZIP format, totally unrelated to the gzip format
        case 0:  fsize = uncopy(in, inl - in, out, fsize);                  break;
        case 8:  fsize = unzip_dynamic(in, inl - in, &out, ret_outsz, 0);   break;
        case 1:  fsize = unshrink(in, inl - in, out, fsize);                break;
        case 6:  fsize = unexplode(in, inl - in, out, fsize);               break;
        case 9:  fsize = inflate64(in, inl - in, out, fsize);               break;
        case 12: fsize = unbzip2(in, inl - in, out, fsize);                 break;
        case 14: fsize = unlzma(in, inl - in, &out, fsize, LZMA_FLAGS_EFS, &fsize, 0); break;
        case 21: fsize = unxmemlzx(in, inl - in, &out, ret_outsz);          break;
        case 64: fsize = undarksector(in, inl - in, out, fsize, 1);         break;
        case 98: fsize = unppmdi(in, inl - in, out, fsize);                 break;
        default: fsize = unzip_dynamic(in, inl - in, &out, ret_outsz, 0);   break;
    }
    *ret_out = out;
    return fsize;
}



int gzip_compress(u8 *in, int insz, u8 *out, int outsz) {
    int     len,
            crc;
    u8      *o;

    if(outsz < 18) return -1;
    o = out;
    *o++ = 0x1f;    // ID1
    *o++ = 0x8b;    // ID2
    *o++ = 0x08;    // CM
    *o++ = 0x00;    // FLG
    *o++ = 0;  *o++ = 0;  *o++ = 0;  *o++ = 0;  // MTIME
    *o++ = 0x00;    // XFL
    *o++ = 0x00;    // OS
    //len = deflate_compress(in, insz, o, outsz - (o - out));
    len = advancecomp_deflate(in, insz, o, outsz - (o - out));
    if(len < 0) return len;
    o += len;
    crc = crc32(0, in, insz);  // CRC32
    *o++ = crc;
    *o++ = crc >> 8;
    *o++ = crc >> 16;
    *o++ = crc >> 24;
    *o++ = insz;    // ISIZE
    *o++ = insz >> 8;
    *o++ = insz >> 16;
    *o++ = insz >> 24;
    return o - out;
}



// modified from http://cvs.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/uts/common/fs/zfs/lzjb.c
#define NBBY 8
#define	MATCH_BITS	6
#define	MATCH_MIN	3
#define	MATCH_MAX	((1 << MATCH_BITS) + (MATCH_MIN - 1))
#define	OFFSET_MASK	((1 << (16 - MATCH_BITS)) - 1)
#define	LEMPEL_SIZE	256

int
lzjb_decompress(u8 *s_start, u8 *d_start, size_t s_len, size_t d_len)
{
	u8 *src = s_start;
	u8 *dst = d_start;
	u8 *d_end = (u8 *)d_start + d_len;
	u8 *cpy, copymap = 0;
	int copymask = 1 << (NBBY - 1);

	while (dst < d_end) {
		if ((copymask <<= 1) == (1 << NBBY)) {
			copymask = 1;
			copymap = *src++;
		}
		if (copymap & copymask) {
			int mlen = (src[0] >> (NBBY - MATCH_BITS)) + MATCH_MIN;
			int offset = ((src[0] << NBBY) | src[1]) & OFFSET_MASK;
			src += 2;
			if ((cpy = dst - offset) < (u8 *)d_start)
				return (-1);
			while (--mlen >= 0 && dst < d_end)
				*dst++ = *cpy++;
		} else {
			*dst++ = *src++;
		}
	}
	return (dst - d_start);
}



// from http://rosettacode.org/wiki/Run-length_encoding#C
/*
int rle_decode(char *out, const char *in, int l)
{
  int i, tb;
  char c;
 
  for(tb=0 ; l>=0 ; l -= 2 ) {
    i = *in++;
    c = *in++;
    tb += i;
    while(i-- > 0) *out++ = c;
  }
  return tb;
}
*/

// http://www.compuphase.com/compress.htm
int unrle(unsigned char *output,unsigned char *input,int length)
{
  signed char count;
  unsigned char *o = output;

  while (length>0) {
    count=(signed char)*input++;
    if (count>0) {
      /* replicate run */
      memset(o,*input++,count);
    } else if (count<0) {
      /* literal run */
      count=(signed char)-count;
      memcpy(o,input,count);
      input+=count;
    } /* if */
    o+=count;
    length-=count;
  } /* while */
  return(o - output);
}



// must be configured
int another_rle(u8 *in, int insz, u8 *out, int outsz) {
    int     escape_chr = 0,
            i,
            o,
            c,
            n,
            lastc   = 0x80;

    if(g_comtype_dictionary) {
        //sscanf(g_comtype_dictionary, "%d", &escape_chr);
        get_parameter_numbers(g_comtype_dictionary, &escape_chr, NULL);
    }

    for(i = o = 0; ; lastc = c) {
        if(i >= insz) break;
        c = in[i++];
        if(c == escape_chr) {
            if(i >= insz) break;
            n = in[i++];
            if(n == escape_chr) {
                if(o >= outsz) quickbms_unz_output_overflow;
                out[o++] = escape_chr;
            } else {
                if((o + n) > outsz) quickbms_unz_output_overflow;
                memset(out + o, lastc, n);
                o += n;
            }
        } else {
            if(o >= outsz) quickbms_unz_output_overflow;
            out[o++] = c;
        }
    }
    return o;
}



int unquicklz(u8 *in, int insz, u8 *out, int outsz) {
    static qlz_state_decompress *state = NULL;
    if(!state) {
        state = malloc(sizeof(qlz_state_decompress));
        if(!state) return -1;
    }
    memset(state, 0, sizeof(qlz_state_decompress));
    int tmp = qlz_size_decompressed(in);
    if((tmp < 0) || (tmp > outsz)) return -1;
    return(qlz_decompress(in, out, state));
}



int doquicklz(u8 *in, int insz, u8 *out, int outsz) {
    static qlz_state_compress *state = NULL;
    if(!state) {
        state = malloc(sizeof(qlz_state_compress));
        if(!state) return -1;
    }
    memset(state, 0, sizeof(qlz_state_compress));
    //int tmp = qlz_size_compressed(in);    // gives an error so who cares
    //if((tmp < 0) || (tmp > outsz)) return -1;
    return(qlz_compress(in, out, insz, state));
}



// from libavcodec lcldec.c for the LossLess Codec Library
unsigned mszh_decomp(unsigned char * srcptr, int srclen, unsigned char * destptr, unsigned destsize)
{
    unsigned char *destptr_bak = destptr;
    unsigned char *destptr_end = destptr + destsize;
    unsigned char mask = 0;
    unsigned char maskbit = 0;
    unsigned ofs, cnt;

    while ((srclen > 0) && (destptr < destptr_end)) {
        if (maskbit == 0) {
            mask = *(srcptr++);
            maskbit = 8;
            srclen--;
            continue;
        }
        if ((mask & (1 << (--maskbit))) == 0) {
            if (destptr + 4 > destptr_end)
                break;
            *(int*)destptr = *(int*)srcptr;
            srclen -= 4;
            destptr += 4;
            srcptr += 4;
        } else {
            ofs = *(srcptr++);
            cnt = *(srcptr++);
            ofs += cnt * 256;
            cnt = ((cnt >> 3) & 0x1f) + 1;
            ofs &= 0x7ff;
            srclen -= 2;
            cnt *= 4;
            if (destptr + cnt > destptr_end) {
                cnt =  destptr_end - destptr;
            }
            if((destptr - ofs) < destptr_bak) return -1;
            if((destptr + cnt) > destptr_end) quickbms_unz_output_overflow;
            for (; cnt > 0; cnt--) {
                *(destptr) = *(destptr - ofs);
                destptr++;
            }
        }
    }

    return (destptr - destptr_bak);
}



int uudecode(u8 *in, int insz, u8 *out, int outsz, int xxe) {
    QUICK_IN_OUT
    int     cnt,
            c,
            m = 0;
    u8      a = 0,
            b = 0;
    static const u8 xxe_set[] = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    if(!strnicmp(in, "begin", 5)) {
        while((in < inl) && (*in != '\n') && (*in != '\r')) in++;
    }

    for(cnt = -1; in < inl; in++) {
        if(*in < ' ') {
            if(!strnicmp(in + 1, "end", 3)) break;
            continue;
        }
        a = b;
        if(xxe) {
            for(b = 0; xxe_set[b]; b++) {
                if(xxe_set[b] == *in) break;
            }
            b &= 0x3f;
        } else {
            b = (*in - ' ') & 0x3f;
        }
        if(m <= 0) {
            if(!strnicmp(in, "end", 3)) break;
            cnt = -1;
        }
        if(cnt < 0) {
            m = b;
        } else {
            switch(cnt & 3) {
                case 0: c = -1;                     break;
                case 1: c = (a << 2) | (b >> 4);    break;
                case 2: c = (a << 4) | (b >> 2);    break;
                case 3: c = (a << 6) | b;           break;
                default: break;
            }
            if(c >= 0) {
                if(o >= outl) quickbms_unz_output_overflow;
                *o++ = c;
                m--;
            }
        }
        cnt++;
    }
    return o - out;
}



// partially derived from http://www.stillhq.com/svn/trunk/ascii85/decode85.c
int unascii85(u8 *in, int insz, u8 *out, int outsz) {
    QUICK_IN_OUT
    static const unsigned pow85[] = { 85*85*85*85, 85*85*85, 85*85, 85, 1 };
    unsigned tuple;
    int     count,
            c;

    tuple = 0;
    count = 0;
    for(;;) {
        if(in >= inl) break;
        c = *in++;
        if(c <= ' ') continue;
        if(c == '<') {
            if(in >= inl) break;
            c = *in++;
            if(c == '~') {
                for(;;) {
                    if(in >= inl) break;
                    c = *in++;
                    if(c == 'z') {
                        if(count) break;
                        if((o + 4) > outl) return -1;
                        *o++ = 0;
                        *o++ = 0;
                        *o++ = 0;
                        *o++ = 0;
                    } else if(c == '~') {
                        if(in >= inl) break;
                        c = *in++;
                        if(c == '>') {
                            if(count > 0) {
                                count--;
                                tuple += pow85[count];
                                if((o + count) > outl) return -1;
                                if(count >= 1) *o++ = tuple >> 24;
                                if(count >= 2) *o++ = tuple >> 16;
                                if(count >= 3) *o++ = tuple >> 8;
                                if(count >= 4) *o++ = tuple;
                            }
                            if(in >= inl) break;
                            c = *in++;
                            break;
                        }
                    } else if(c <= ' ') {
                    } else {
                        if((c < '!') || (c > 'u')) break;
                        tuple += (c - '!') * pow85[count++];
                        if(count == 5) {
                            if((o + 4) > outl) return -1;
                            *o++ = tuple >> 24;
                            *o++ = tuple >> 16;
                            *o++ = tuple >> 8;
                            *o++ = tuple;
                            tuple = 0;
                            count = 0;
                        }
                    }
                }
            } else {
                if((o + 2) > outl) return -1;
                *o++ = '<';
                *o++ = c;
            }
        } else {
            if(o >= outl) return -1;
            *o++ = c;
        }
    }
    return o - out;
}



int unyenc(u8 *in, int insz, u8 *out, int outsz) {
    QUICK_IN_OUT
    u8      c;

    while(in < inl) {
        c = *in++;
        if((c == '\n') || (c == '\r')) continue;
        if(c == '=') {
            if(in >= inl) break;
            c = *in++;
            if(c == 'y') {
                while((in < inl) && (*in != '\n') && (*in != '\r')) in++;
                continue;
            }
            c -= 64;
        }
        c -= 42;
        if(o >= outl) return -1;
        *o++ = c;
    }
    return o - out;
}



int doomhuff(int type, u8 *in, int insz, u8 *out, int outsz, int enc) {
    float   myfreq[256],
            t;
    int     i,
            n;
    u8      *p;

    if(g_comtype_dictionary) {
        p = g_comtype_dictionary;
        for(i = 0; i < 256; i++) {
            if(sscanf(p, "%f%n", &t, &n) != 1) break;
            myfreq[i] = t;
            for(p += n; *p; p++) {
                if(*p <= ' ') continue;
                if(*p == ',') continue;
                break;
            }
        }
        if(i < 256) {
            fprintf(stderr, "\nError: the provided custom huffman table is incomplete (%d elements)\n", i);
            return -1;
        }
        doom_HuffInit(myfreq);
    } else if(type == 1) {
        doom_HuffInit(zdaemon_HuffFreq);
    } else if(type == 2) {
        doom_HuffInit(skulltag_HuffFreq);
    } else {
        doom_HuffInit(NULL);
    }
    if(!enc) {
        doom_HuffDecode(in, out, insz, &outsz, outsz);
    } else {
        doom_HuffEncode(in, out, insz, &outsz);
    }
    return(outsz);
}



// from Arkadi Kagan http://compressions.sourceforge.net/about.html
// converted to C by Luigi Auriemma
// I have ported only this one because the others are a mission-impossible, C++ sux
int CLZ77_Decode(unsigned char *target, long tlen, unsigned char *source, long slen) {
    static const int BITS_LEN = 4;
	long i;
	long block, len;
	long shift, border;
	unsigned char *s, *t, *p, *tl;
	unsigned char *flag;
	short *ptmp;

	t = target;
    tl = target + tlen;
	flag = source;
	block = 0;				// block - bit in single flag unsigned char
	shift = 16;				// shift offset to most significant bits
	border = 1;				// offset can`t be more then border
	for (s = source+1; (s < source+slen) && (t-target < tlen); )
	{
		if (shift > BITS_LEN)
			while (t-target >= border)
			{
				if (shift <= BITS_LEN) break;
				border = border << 1;
				shift--;
			}
		if (flag[0]&(1<<block))
		{
			ptmp = (short*)s;
			len = ((1<<shift)-1)&ptmp[0];
			p = t - (ptmp[0]>>shift) - 1;
            if((t + len) > tl) quickbms_unz_output_overflow;
			for (i = 0; i < len; i++) {
				t[i] = p[i];
            }
			t += len;
			s += 2;
		} else
		{
            if(t >= tl) quickbms_unz_output_overflow;
			*t++ = *s++;
			len = 1;
		}
		if (++block >= 8)
		{
			flag = s++;
			block = 0;
		}
	}
    return(t - target);
}



// modified by Luigi Auriemma
/*
 *  DHUFF.C:    Huffman Decompression Program.                            *
 *              14-August-1990    Bill Demas          Version 1.0         *
*/
int undhuff(unsigned char *in, int insz, unsigned char *out, int outsz) {
short           decomp_tree[512];
unsigned short  code[256];
unsigned char   code_length[256];

    unsigned char *inl;
    inl = in + insz;

    memset(decomp_tree, 0, sizeof(decomp_tree));
    memcpy(code, in, sizeof(code));                 in += sizeof(code);
    memcpy(code_length, in, sizeof(code_length));   in += sizeof(code_length);

   unsigned short  loop1;
   unsigned short  current_index;
   unsigned short  loop;
   unsigned short  current_node = 1;

   decomp_tree[1] = 1;

   for (loop = 0; loop < 256; loop++)
   {
      if (code_length[loop])
      {
	 current_index = 1;
	 for (loop1 = code_length[loop] - 1; loop1 > 0; loop1--)
	 {
	    current_index = (decomp_tree[current_index] << 1) +
			    ((code[loop] >> loop1) & 1);
        if(current_index > 512) return -1;
	    if (!(decomp_tree[current_index]))
	       decomp_tree[current_index] = ++current_node;
	 }
	 decomp_tree[(decomp_tree[current_index] << 1) +
	   (code[loop] & 1)] = -loop;
      }
   }

   unsigned short  cindex = 1;
   unsigned char   curchar;
   short           bitshift;

   unsigned  charcount = 0L;

   while (charcount < outsz)
   {
      if(in >= inl) break;
      curchar = *in++;;

      for (bitshift = 7; bitshift >= 0; --bitshift)
      {
	 cindex = (cindex << 1) + ((curchar >> bitshift) & 1);

	 if (decomp_tree[cindex] <= 0)
	 {
        //if(charcount >= outsz) quickbms_unz_output_overflow; // not necessary
        out[charcount] = (int) (-decomp_tree[cindex]);

	    if ((++charcount) == outsz)
               bitshift = 0;
            else
               cindex = 1;
	 }
	 else
	    cindex = decomp_tree[cindex];
      }
   }
    return(charcount);
}



// Finish submission to the Dr Dobbs contest written by Jussi Puttonen, Timo Raita and Jukka Teuhola.
int unfin(unsigned char *in, int insz, unsigned char *out, int outsz) {
#define FIN_INDEX(p1,p2) (((unsigned)(unsigned char)p1<<7)^(unsigned char)p2)
static char pcTable[32768U];
   int ci,co;            // characters (in and out)
   char p1=0, p2=0;      // previous 2 characters
   int ctr=8;            // number of characters processed for this mask
   unsigned char mask=0; // mask to mark successful predictions

int i = 0;
int o = 0;

   memset (pcTable, 32, 32768U); // space (ASCII 32) is the most used char

   for(;;) {
      if(i >= insz) break;
      ci = in[i++];
      // get mask (for 8 characters)
      mask = (unsigned char)(char)ci;

      // for each bit in the mask
      for (ctr=0; ctr<8; ctr++){
         if (mask & (1<<ctr)){
            // predicted character
            co = pcTable[FIN_INDEX(p1,p2)];
         } else {
            // not predicted character
            if(i >= insz) break;
            co = in[i++];
	    pcTable[FIN_INDEX(p1,p2)] = (char)co;
         }
         if(o >= outsz) quickbms_unz_output_overflow;
         out[o++] = co;
         p1 = p2; p2 = co;
      }
   }
   return o;
}



// Copyright (c) 2002 Chilkat Software, Inc.  All Rights Reserved
int CK_RLE_decompress(unsigned char *buf,
    int len, 
    unsigned char *out,
    int uncompressLen)
    {
    unsigned char header;
    unsigned char *outPtr = out;
    unsigned char i;
    int outSize = 0;

    while (len)
	{
	header = *buf;
	buf++;
	len--;

	if (!(header & 128))
	    {
	    // There are header+1 different bytes.
	    for (i=0; i<=header; i++)
		{
		if (outSize >= uncompressLen) quickbms_unz_output_overflow;
		*outPtr = *buf;
		outPtr++;
		outSize++;
		buf++;
		len--;
		}
	    }
	else
	    {
	    unsigned n = (header & 127) + 2;
	    for (i=0; i<n; i++)
		{
		if (outSize >= uncompressLen) quickbms_unz_output_overflow;
		*outPtr = *buf;
		outPtr++;
		outSize++;
		}
	    buf++;
	    len--;
	    }
	}

    uncompressLen = outSize;
    //return 0;
    return(uncompressLen);
    }



// this function has been created by me from scratch (based on calcc) and is NOT optimized
// note: if outsz is not of the exact size then the returned size will be padded
int multi_base_decoder(int base, int alt, u8 *in, int insz, u8 *out, int outsz, u8 *mytable) {
static const u8 big_table[256] =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
    "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
    "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
static const u8 hex_table[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const u8 b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const u8 g64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";   // gamespy
static const u8 b32_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const u8 z32_table[] = "ybndrfg8ejkmcpqxot1uwisza345h769";   // z-base-32
static const u8 c32_table[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   // Crockford's base32
static const u8 n32_table[] = "0123456789BCDFGHJKLMNPQRSTVWXYZ.";   // Nintendo
    u64     num;
    int     i,
            block    = 0,
            blockcpy = 0;
    u8      *p;
    u8      *table = NULL;

    if(mytable) {
        table = mytable;
    } else {
        if((base > 0) && (base <= 16)) {
            table = (u8 *)hex_table;
        } else if(base == 32) {
            switch(alt) {
                case 0: table = (u8 *)b32_table;    break;
                case 1: table = (u8 *)z32_table;    break;
                case 2: table = (u8 *)hex_table;    break;
                case 3: table = (u8 *)c32_table;    break;
                case 4: table = (u8 *)n32_table;    break;
                default: break;
            }
        } else if(base == 64) {
            switch(alt) {
                case 0: table = (u8 *)b64_table;    break;
                case 1: table = (u8 *)g64_table;    break;
                default: break;
            }
        } else if(base <= 62) {
            table = (u8 *)hex_table;
        } else {
            table = (u8 *)big_table;
        }
        if(!table) return -1;
    }

    num = 1;    // I'm sure that exists a better and simpler way but I'm stupid, sorry
    for(block = 0; num; block++) {
        num *= base;
        switch(num - 1) {
            case 0xffLL:
            case 0xffffLL:
            case 0xffffffLL:
            case 0xffffffffLL:
            case 0xffffffffffLL:
            case 0xffffffffffffLL:
            case 0xffffffffffffffLL:
            case 0xffffffffffffffffLL: {
                for(blockcpy = 0, --num; num; num >>= 8, blockcpy++);
                //num = 0;  // num is already 0
                break;
            }
            default: break;
        }
    }
    if(!(block & 1)) block--;   // if pair

    QUICK_IN_OUT

    num = 0;
    for(i = 0;; i++) {
        num *= (u64)base;
        if(in < inl) {
            p = memchr(table, *in, base);
            if(p) {
                num += (p - table);
                in++;
            } else {
                in = inl; // finish
            }
        }
        if(i >= block) {
            i = blockcpy;
            while(i--) {
                if(o >= outl) /* do NOT use return -1 here */ break;
                *o++ = num >> (u64)(i * 8);
            }
            num = 0;
            i = -1;
            if(in >= inl) break;
        }
    }
    //*o++ = 0;
    return o - out;
}



int unlzhlib(unsigned char *in, int insz, unsigned char *out, int outsz) {
    QUICK_IN_OUT

    void *mymalloc (unsigned n) {return malloc (n);}
    void myfree (void *p) {free (p);}
    int myread (void *p, int n) {
        if((in + n) > inl) n = inl - in;
        memcpy(p, in, n);
        in += n;
        return(n);
    }
    int mywrite (void *p, int n) {
        if((o + n) > outl) return -1;   // the return value is ignored by lzh_melt
        memcpy(o, p, n);
        o += n;
        return(n);
    }
    lzh_melt(myread, mywrite, mymalloc, myfree, outsz);
    return o - out;
}



/***********************************************************
*
*    rle3.c
*
*      ÉâÉìÉåÉìÉOÉXïÑçÜâªÇÃÉeÉXÉg
*      ÉâÉìí∑ïîï™ÇÉ}Å[ÉNïÑçÜÇ≈éØï Ç∑ÇÈ
*
***********************************************************/
//int rl3_decode(unsigned char *out, unsigned char *in, int size) {
int rl3_decode(unsigned char *in, int insz, unsigned char *out, int outsz, int mch) {
#define MINLEN   4
#define LIMIT1   240
#define LIMIT2   (256 * (256 - LIMIT1) + LIMIT1 - 1)
//unsigned char mch = 'Z';
if(mch < 0) mch = 'Z';
	int rpos = 0, wpos = 0;
	while (rpos < insz) {
		int c = in[rpos++];
		int i, le;
		if (c == mch) {
			/* ÉâÉìí∑Çì¸óÕ */
			le = in[rpos++];
			if (le >= LIMIT1) {
				le = ((le - LIMIT1) << 8) + in[rpos++] + LIMIT1;
			}
			le++;
			if (le >= MINLEN)  c = in[rpos++];
            if((wpos + le) > outsz) quickbms_unz_output_overflow;
			for (i = 0; i < le; i++)  out[wpos++] = c;
		} else {
            if(wpos >= outsz) quickbms_unz_output_overflow;
			out[wpos++] = c;
		}
	}
	return wpos;
}



typedef struct {
    unsigned char   *o;
    unsigned char   *ol;
} sr3c_write_ctx;
static int sr3c_write(const unsigned char *bytes, size_t n, int flush, sr3c_write_ctx *wc) {
    if((wc->o + n) > wc->ol) n = wc->ol - wc->o;
    if(n <= 0) return -1;
    memcpy(wc->o, bytes, n);
    wc->o += n;
    return 0;
}
int unsr3c(unsigned char *in, int insz, unsigned char *out, int outsz) {
    sr3c_context_t *ctx;
    sr3c_write_ctx  wc;

    wc.o  = out;
    wc.ol = out + outsz;
    ctx = sr3c_alloc((sr3c_output_f_t)sr3c_write, &wc);
    if(sr3c_uncompress(in, insz, ctx)) {
        sr3c_free(ctx);
        return -1;
    }
    sr3c_free(ctx);
    return(wc.o - out);
}



// the library contains both the smart and simple mode
// while the pre-compiled demo on the website uses only the smart mode
// and so it's needed to select the smart-only or smart+simple mode
int SFUnpackSeg(unsigned char *in, int insz, unsigned char *out, int outsz, int smart_only) {
    int     i   = 0,
            o   = 0,
            t,
            a,
            c,
            ident = 0;

    if(insz < 2) return -1;
    t = in[i] | (in[i + 1] << 8);
    i += 2;
    if(!smart_only) {
        if(t <= 0xff) {
            ident = t;
            t = 0;
        }
    }
    for(;;) {
        if(t) {
            if(insz <= t) break;
            c = in[insz - 2] | (in[insz - 1] << 8);
            insz -= 2;
            c -= (i + 1);
            if((o + c) > outsz) quickbms_unz_output_overflow;
            memcpy(out + o, in + i, c);
            i += c;
            o += c;
        } else {
            if(i >= insz) break;
            a = in[i++];
            if(a != ident) {
                if((o + 1) > outsz) quickbms_unz_output_overflow;
                out[o++] = a;
                continue;
            }
        }
        a = in[i++];
        c = in[i++];
        if(!c) {
            c = in[i] | (in[i + 1] << 8);
            i += 2;
        }
        c++;
        if((o + c) > outsz) quickbms_unz_output_overflow;
        memset(out + o, a, c);
        o += c;
    }
    if(t) {
        /*
        c = insz - i;
        if((o + c) > outsz) quickbms_unz_output_overflow;
        memcpy(out + o, in + i, c);
        i += c;
        o += c;
        */
        while(i < insz) {
            if(o >= outsz) break;
            out[o++] = in[i++];
        }
    }
    return o;
}
int SFUnpack(unsigned char *in, int insz, unsigned char *out, int outsz, int smart_only) {
    int     i   = 0,
            o   = 0,
            r,
            chunksz;

    for(;;) {
        if((i + 2) > insz) break;
        chunksz = in[i] | (in[i + 1] << 8);
        i += 2;
        if((i + chunksz) > insz) break;
        r = SFUnpackSeg(in + i, chunksz, out + o, outsz - o, smart_only);
        if(r < 0) break;
        i += chunksz;
        o += r;
    }
    return o;
}



// based on the information of Guy Ratajczak, it's just a lz77
int undarkstone(unsigned char *in, int insz, unsigned char *out, int outsz) {
    QUICK_IN_OUT
    int     i,
            j,
            flags,
            info,
            num;
    u8      *p;

    for(;;) {
        if(in >= inl) break;
        flags = *in++;
        for(i = 0; i < 8; i++) {
            if(o >= outl) break;    // needed
            if(flags & 1) {
                if(in >= inl) break;
                if(o >= outl) quickbms_unz_output_overflow;
                *o++ = *in++;
            } else {
                if((in + 2) > inl) break;
                info = in[0] | (in[1] << 8);
                in += 2;
                num = 3 + (info >> 10);
                p = o - (info & 0x3ff);
                if(p < out) return -1;
                if((o + num) > outl) quickbms_unz_output_overflow;
                for(j = 0; j < num; j++) {
                    *o++ = *p++;
                }
            }
            flags >>= 1;
        }
    }
    return o - out;
}



int sfl_block_chunked(unsigned char *in, int insz, unsigned char *out, int outsz) {
    int     chunk_zsize,
            chunk_size,
            i = 0,
            o = 0;

    while(o < outsz) {
        if((i + 2) > insz) break;
        chunk_zsize = in[i] | (in[i + 1] << 8);
        if(!chunk_zsize) break;
        i += 2;
        if((i + chunk_zsize) > insz) break;
        chunk_size = expand_block(in + i, out + o, chunk_zsize, outsz - o);
        i += chunk_zsize;
        o += chunk_size;
    }
    return o;
}



int sfl_block_chunked_compress(unsigned char *in, int insz, unsigned char *out, int outsz) {
    int     chunk_zsize,
            chunk_size,
            i = 0,
            o = 0;

    while(i < insz) {
        chunk_size = 0x7fff - 1;    // consider copy flag
        if(chunk_size > (insz - i)) chunk_size = insz - i;
        chunk_zsize = compress_block(in + i, out + o + 2, chunk_size);
        if(chunk_zsize < 0) return -1;
        out[o]     = chunk_zsize;
        out[o + 1] = chunk_zsize >> 8;
        i += chunk_size;
        o += 2 + chunk_zsize;
    }
    return o;
}



// code from tpu: http://forum.xentax.com/viewtopic.php?p=30387#p30387
/* PRS get bit form lsb to msb, FPK get it form msb to lsb */
int prs_8ing_get_bits(int n, char *sbuf, int *sptr, int *blen)
{
    static int fbuf = 0;
   int retv;

   retv = 0;
   while(n){
      retv <<= 1;
      if((*blen)==0){
         fbuf = sbuf[*sptr];
         //if(*sptr<256)
            //{ fprintf(stderr, "[%02x] ", fbuf&0xff); fflush(0); }
         (*sptr)++;
         (*blen) = 8;
      }

      if(fbuf&0x80)
         retv |= 1;

      fbuf <<= 1;
      (*blen) --;
      n --;
   }

   return retv;
}
int prs_8ing_uncomp(char *dbuf, int dlen, char *sbuf, int slen)
{
   int sptr;
   int dptr;
   int i, flag, len, pos;

   int blen = 0;

   sptr = 0;
   dptr = 0;
   while(sptr<slen){
      flag = prs_8ing_get_bits(1, sbuf, &sptr, &blen);
      if(flag==1){
         //if(sptr<256)
            //{ fprintf(stderr, "%02x ", (u8)sbuf[sptr]); fflush(0); }
         if(dptr<dlen)
            dbuf[dptr++] = sbuf[sptr++];
      }else{
         flag = prs_8ing_get_bits(1, sbuf, &sptr, &blen);
         if(flag==0){
            len = prs_8ing_get_bits(2, sbuf, &sptr, &blen)+2;
            pos = sbuf[sptr++]|0xffffff00;
         }else{
            pos = (sbuf[sptr++]<<8)|0xffff0000;
            pos |= sbuf[sptr++]&0xff;
            len = pos&0x07;
            pos >>= 3;
            if(len==0){
               len = (sbuf[sptr++]&0xff)+1;
            }else{
               len += 2;
            }
         }
         //if(sptr<256)
            //{ fprintf(stderr, "<%08x(%08x): %08x %d> \n", dptr, dlen, pos, len); fflush(0); }
         pos += dptr;
         for(i=0; i<len; i++){
            if(dptr<dlen)
               dbuf[dptr++] = dbuf[pos++];
         }
      }
   }

   return dptr;
}



// from cpk_uncompress.c of hcs: http://hcs64.com/files/utf_tab04.zip
// modified by Luigi Auriemma
// Decompress compressed segments in CRI CPK filesystems
static inline unsigned short CPK_get_next_bits(unsigned char *infile, int * const offset_p, unsigned char * const bit_pool_p, int * const bits_left_p, const int bit_count)
{
    unsigned short out_bits = 0;
    int num_bits_produced = 0;
    while (num_bits_produced < bit_count)
    {
        if (0 == *bits_left_p)
        {
            *bit_pool_p = infile[*offset_p];
            *bits_left_p = 8;
            --*offset_p;
        }

        int bits_this_round;
        if (*bits_left_p > (bit_count - num_bits_produced))
            bits_this_round = bit_count - num_bits_produced;
        else
            bits_this_round = *bits_left_p;

        out_bits <<= bits_this_round;
        out_bits |=
            (*bit_pool_p >> (*bits_left_p - bits_this_round)) &
            ((1 << bits_this_round) - 1);

        *bits_left_p -= bits_this_round;
        num_bits_produced += bits_this_round;
    }

    return out_bits;
}

#define CPK_GET_NEXT_BITS(bit_count) CPK_get_next_bits(infile, &input_offset, &bit_pool, &bits_left, bit_count)

int CPK_uncompress(unsigned char *infile, int input_size, unsigned char *output_buffer, int uncompressed_size) {
    if(uncompressed_size < 0x100) return -1;
    uncompressed_size -= 0x100; // blah, terrible algorithm or terrible implementation

    const int input_end = input_size - 0x100 - 1;
    int input_offset = input_end;
    const int output_end = 0x100 + uncompressed_size - 1;
    unsigned char bit_pool = 0;
    int bits_left = 0;
    int bytes_output = 0;
    int     i;

    if(input_size < 0x100) return -1;
    memcpy(output_buffer, infile + input_size - 0x100, 0x100);

    while ( bytes_output < uncompressed_size )
    {
        if(input_offset < 0) break;
        if (CPK_GET_NEXT_BITS(1))
        {
            int backreference_offset =
                output_end-bytes_output+CPK_GET_NEXT_BITS(13)+3;
            int backreference_length = 3;

            // decode variable length coding for length
            enum { vle_levels = 4 };
            int vle_lens[vle_levels] = { 2, 3, 5, 8 };
            int vle_level;
            for (vle_level = 0; vle_level < vle_levels; vle_level++)
            {
                int this_level = CPK_GET_NEXT_BITS(vle_lens[vle_level]);
                backreference_length += this_level;
                if (this_level != ((1 << vle_lens[vle_level])-1)) break;
            }
            if (vle_level == vle_levels)
            {
                int this_level;
                do
                {
                    this_level = CPK_GET_NEXT_BITS(8);
                    backreference_length += this_level;
                } while (this_level == 255);
            }

            //printf("0x%08lx backreference to 0x%lx, length 0x%lx\n", output_end-bytes_output, backreference_offset, backreference_length);
            for (i=0;i<backreference_length;i++)
            {
                output_buffer[output_end-bytes_output] = output_buffer[backreference_offset--];
                bytes_output++;
            }
        }
        else
        {
            // verbatim byte
            output_buffer[output_end-bytes_output] = CPK_GET_NEXT_BITS(8);
            //printf("0x%08lx verbatim byte\n", output_end-bytes_output);
            bytes_output++;
        }
    }

    return 0x100 + bytes_output;
}



/* ----------
 * pg_lzcompress.c -
 *
 *		This is an implementation of LZ compression for PostgreSQL.
 *		It uses a simple history table and generates 2-3 byte tags
 *		capable of backward copy information for 3-273 bytes with
 *		a max offset of 4095.
 ...(cut)...
 * Copyright (c) 1999-2009, PostgreSQL Global Development Group
 *
 * $PostgreSQL: pgsql/src/backend/utils/adt/pg_lzcompress.c,v 1.34 2009/06/11 14:49:03 momjian Exp $
 * ----------
 */
int
pglz_decompress(unsigned char *in, int insz, unsigned char *out, int outsz)
{
	const unsigned char *sp;
	const unsigned char *srcend;
	unsigned char *dp;
	unsigned char *destend;

	//sp = ((const unsigned char *) source) + sizeof(PGLZ_Header);
	//srcend = ((const unsigned char *) source) + VARSIZE(source);
	//dp = (unsigned char *) dest;
	//destend = dp + source->rawsize;
    sp      = in;
    srcend  = in + insz;
    dp      = out;
    destend = out + outsz;

	while (sp < srcend && dp < destend)
	{
		/*
		 * Read one control byte and process the next 8 items (or as many as
		 * remain in the compressed input).
		 */
		unsigned char ctrl = *sp++;
		int			ctrlc;

		for (ctrlc = 0; ctrlc < 8 && sp < srcend; ctrlc++)
		{
			if (ctrl & 1)
			{
				/*
				 * Otherwise it contains the match length minus 3 and the
				 * upper 4 bits of the offset. The next following byte
				 * contains the lower 8 bits of the offset. If the length is
				 * coded as 18, another extension tag byte tells how much
				 * longer the match really was (0-255).
				 */
				int		len;
				int		off;

				len = (sp[0] & 0x0f) + 3;
				off = ((sp[0] & 0xf0) << 4) | sp[1];
				sp += 2;
				if (len == 18)
					len += *sp++;

				/*
				 * Check for output buffer overrun, to ensure we don't clobber
				 * memory in case of corrupt input.  Note: we must advance dp
				 * here to ensure the error is detected below the loop.  We
				 * don't simply put the elog inside the loop since that will
				 * probably interfere with optimization.
				 */
				if (dp + len > destend)
				{
					dp += len;
					break;
				}

				/*
				 * Now we copy the bytes specified by the tag from OUTPUT to
				 * OUTPUT. It is dangerous and platform dependent to use
				 * memcpy() here, because the copied areas could overlap
				 * extremely!
				 */
				while (len--)
				{
					*dp = dp[-off];
					dp++;
				}
			}
			else
			{
				/*
				 * An unset control bit means LITERAL BYTE. So we just copy
				 * one from INPUT to OUTPUT.
				 */
				if (dp >= destend)		/* check for buffer overrun */
					break;		/* do not clobber memory */

				*dp++ = *sp++;
			}

			/*
			 * Advance the control bit
			 */
			ctrl >>= 1;
		}
	}

	/*
	 * Check we decompressed the right amount.
	 */
	//if (dp != destend || sp != srcend)
		//return -1; //elog(ERROR, "compressed data is corrupt");

	/*
	 * That's it.
	 */
    return(dp - out);
}



/*
Simple Compression using an LZ buffer
Part 3 Revision 1.d:
An introduction to compression on the Amiga by Adisak Pochanayon
*/
// modified by Luigi Auriemma
#define HISTORY_SIZE     4096
#define MASK_history     (HISTORY_SIZE-1)
#define MASK_upper       (0xF0)
#define MASK_lower       (0x0F)
#define SHIFT_UPPER      16
#define LSR_upper        4
#define MAX_COMP_LEN     17
unsigned char LZ_history[HISTORY_SIZE];

#define UnPackSLZ_writechar(outchar) \
{ \
  if(o >= outl) quickbms_unz_output_overflow; \
  *o++ = outchar; \
  LZ_history[lzhist_offset]=outchar; lzhist_offset=(lzhist_offset+1)&MASK_history; \
}

int UnPackSLZ(unsigned char *in, int insz, unsigned char *out, int outsz) {
    QUICK_IN_OUT

  short myTAG, mycount, myoffset;
  int loop1;
  short lzhist_offset=0;

  for(;;)  // loop forever (until goto occurs to break out of loop)
    {
      if(in >= inl) break;
      myTAG=*in++;
      for(loop1=0;(loop1!=8);loop1++)
        {
          if(myTAG&0x80)
            {
              if(in >= inl) break;
              if((mycount=*in++)==0)  // Check EXIT
                { goto skip2; } // goto's are gross but it's efficient :(
              else
                {
                  if(in >= inl) break;
                  myoffset=HISTORY_SIZE-(((MASK_upper&mycount)*SHIFT_UPPER)+(*in++));
                  mycount&=MASK_lower;
                  mycount+=2;
                  while(mycount!=0)
                    {
                      UnPackSLZ_writechar(LZ_history[(lzhist_offset+myoffset)&MASK_history]);
                      mycount--;
                    }
                }
            }
          else
            { if(in >= inl) break; UnPackSLZ_writechar(*in++); }
          myTAG+=myTAG;
        }
    }
skip2:
  return o - out;
}



int slz_triace_blah(int x, int n, int a, unsigned char **o, unsigned char *outl) {
    unsigned char   *t = *o;
    if(x < n) {
        n = (((n - x) - 1) >> 1) + 1;
        x += n * 2;
        if((t + (n * 2)) > outl) return -1;
        while(n--) {
            *t++ = a;
            *t++ = a >> 8;
        }
        *o = t;
    }
    return(x);
}
int slz_triace_old(unsigned char *in, int insz, unsigned char *out, int outsz, int type) {
    QUICK_IN_OUT
    int     flag, n, x, a;

    for(flag = 0; o < outl; flag >>= 1) {
        if(!(flag & 0xff00)) {
            if(in >= inl) break;
            flag = 0xff00 | *in++;
        }
        if(flag & 1) {
            if(in >= inl) break;
            if(o >= outl) quickbms_unz_output_overflow;
            *o++ = *in++;
        } else {
            if((in + 2) > inl) break;
            n = *in++;
            n |= (*in++ << 8);
            x = ((n >> 12) & 0x0f) + 3;
            n &= 0x0fff;
            if((x < 0x12) || (type != 2)) {
                if((o - n) < out) return -1;
                if((o + x) > outl) quickbms_unz_output_overflow;
                while(x--) {
                    *o = *(o - n);
                    o++;
                }
            } else {
                if(n < 0x100) {
                    if(in >= inl) break;
                    a = *in++;
                    n += 0x13;
                } else {
                    a = n & 0xff;
                    n = (((n >> 8) & 0xf) + 3);
                }
                a |= (a << 8);
                if((o - out) & 1) {
                    if(o >= outl) quickbms_unz_output_overflow;
                    *o++ = a;
                    if(n & 1) {
                        n = ((n - 2) >> 1) + 1;
                        if((o + (n * 2)) > outl) quickbms_unz_output_overflow;
                        while(n--) {
                            *o++ = a;
                            *o++ = a >> 8;
                        }
                    } else if((n - 1) > 1) {
                        x = slz_triace_blah(1, n - 1, a, &o, outl);
                        if(x < 0) return -1;
                        if(x < n) {
                            if(o >= outl) quickbms_unz_output_overflow;
                            *o++ = a;
                        }
                    } else if(n > 1) {
                        if(o >= outl) quickbms_unz_output_overflow;
                        *o++ = a;
                    }
                } else {
                    x = slz_triace_blah(0, n - 1, a, &o, outl);
                    if(x < 0) return -1;
                    if(x < n) {
                        if(o >= outl) quickbms_unz_output_overflow;
                        *o++ = a;
                    }
                }
            }
        }
    }
    return o - out;
}



int slz_triace(unsigned char *in, int insz, unsigned char **ret_out, int outsz, int mode, int *ret_outsz) {
/*----------------------------------------------------------------------------*/
/*--  slz.c - Simple SLZ decompressor                                       --*/
/*--  Copyright (C) 2011 CUE                                                --*/
/*--                                                                        --*/
/*--  This program is free software: you can redistribute it and/or modify  --*/
/*--  it under the terms of the GNU General Public License as published by  --*/
/*--  the Free Software Foundation, either version 3 of the License, or     --*/
/*--  (at your option) any later version.                                   --*/
/*--                                                                        --*/
/*--  This program is distributed in the hope that it will be useful,       --*/
/*--  but WITHOUT ANY WARRANTY; without even the implied warranty of        --*/
/*--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the          --*/
/*--  GNU General Public License for more details.                          --*/
/*--                                                                        --*/
/*--  You should have received a copy of the GNU General Public License     --*/
/*--  along with this program. If not, see <http://www.gnu.org/licenses/>.  --*/
/*----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
  SLZ header:
  - 0000:3 - signature, always "SLZ"
  - 0003:1 - compression mode: 0/STORE, 1/LZSS, 2/LZSS+RLE, 3/LZSS16
  - 0004:4 - decompressed length (sometimes wrong, do not use)
  - 0008:4 - compressed length
  - 000C:4 - offset to the 2nd file (0 if none), aligned to 4 bytes
------------------------------------------------------------------------------*/

  unsigned   flags = 0, pos = 0, len = 0;
    unsigned char   *out;
    u8      *slz = in;

    not_ret_out_boh
    out = *ret_out;

    if((insz >= 0x10) && !memcmp(slz, "SLZ", 3)) {
        mode = slz[3];
        outsz = QUICK_GETi32(slz, 8);
        if(outsz < 0) return -1;
        myalloc(&out, outsz, ret_outsz);
        *ret_out = out;
        slz += 0x10;
    }

    u8      *raw = out,
            *raw_end = out + outsz;

    if (!mode) {
      while (raw < raw_end) *raw++ = *slz++;
    } else {
      flags = 0;
      while (raw < raw_end) {
        if ((flags >>= 1) <= 0xFFFF) {
          flags = 0x00FF0000 | *slz++;
          if (mode == 3) flags |= 0xFF000000 | (*slz++ << 8);
        }

        if (flags & 1) {
          *raw++ = *slz++;
          if (mode == 3) *raw++ = *slz++;
        } else {
          pos = *slz++;
          len = *slz++;
          if ((mode == 2) && (len >= 0xF0)) {
            if (len > 0xF0) {
              len = (len & 0xF) + 3;
            } else {
              len = pos + 0x13;
              pos = *slz++;
            }
            while (len--) *raw++ = pos;
          } else {
            pos |= (len & 0xF) << 8;
            len = (len >> 4) + 3;
            if (mode == 3) {
              len = (len - 1) << 1;
              pos <<= 1;
            }
            //while (len--) *raw++ = *(raw - pos);
            while (len--) {
                *raw = *(raw - pos);
                raw++;
            }
          }
        }
      }
    }
    return(raw - out);
}



/*
// replaced by LZH-Light
#include "libs/lzhl/lzhl.h"
int unlzhl(unsigned char *in, int insz, unsigned char *out, int outsz) {
    LZHL_DHANDLE hnd;
    hnd = LZHLCreateDecompressor();
    if(!LZHLDecompress(hnd, out, &outsz, in, &insz)) outsz = -1;
    LZHLDestroyDecompressor(hnd);
    return(outsz);
}
*/


/*
int unlzrw3(unsigned char *in, int insz, unsigned char *out, int outsz) {
    static u8   *wrk_mem = NULL;
    if(!wrk_mem) {
        wrk_mem = malloc((4096 * sizeof(char *)) + 16);
        if(!wrk_mem) STD_ERR(QUICKBMS_ERROR_MEMORY);
    }
    lzrw3a_decompress(wrk_mem, in, insz, out, &outsz);
    return(outsz);
}
*/



/*
_DIFFERENTIAL COMPRESSION ALGORITHMS_
by James H. Sylvester
*/
int diffcomp(unsigned char *in, int insz, unsigned char *out, int outsz) {
    unsigned char   *infile   = in,
                    *infilel  = in + insz,
                    *outfile  = out,
                    *outfilel = out + outsz;

  const int blockfactor = 1;              /* adjust as desired */
  const int blocksize = blockfactor * 8;
  char  buffer [257] [8];             /* enter blocksize for second index */

  int   i, j;
  //FILE  *sf, *tf;        /* sourcefile & targetfile respectively */
  int   bestblock = -1;  /* best matching block in buffer */
  int   changeindex;

/* Initialize buffer with exactly same information as in PACK.C program. */
  for (i = 0; i < 256; i++)
    for (j = 0; j < blocksize; j++)
      buffer [i] [j] = i;
/* Reconstruct original data from encoded data in sourcefile. */
  while (1)  /* while true ==> stay in loop until internal exit */
  {
    if (bestblock == -1)     /* input data yet to be loaded */
    {
      bestblock = lame_getc(sf);
      if (bestblock == EOF)  /* original and encoded files had 0 bytes */
      {
        goto quit;
      }
      changeindex = lame_getc(sf);
    }
    else
    {
      bestblock = lame_getc(sf);
      if (bestblock == EOF)    /* input data ended with previous full block */
      {
        for (j = 0; j < blocksize; j++)  /* output full block */
          lame_putc(buffer [256] [j], tf);
        goto quit;
      }
      changeindex = lame_getc(sf);
      if (changeindex == EOF)  /* input data ended with unfull block */
      {
        for (j = 0; j < bestblock; j++)  /* reinterpret bestblock as  */
                                         /* last blocksize and output */
                                         /* this last, partial block  */
          lame_putc(buffer [256] [j], tf);
        goto quit;
      }
      for (j = 0; j < blocksize; j++)  /* output full block */
        lame_putc(buffer [256] [j], tf);
    }
    for (i = 0; i < blockfactor; i++)
    {
      if (i > 0)
        changeindex = lame_getc(sf);
      for (j = i*8; j < i*8+8; j++)
      {
        if (changeindex % 2 == 1)
          buffer [bestblock] [j] = lame_getc(sf);  /* directly load changes */
                                              /* into buffer bestblock */
        changeindex /= 2;
        buffer [256] [j] = buffer [bestblock] [j];  /* copy block info */
      }
    }
  }
quit:
  return(outfile - out);
}



int unlzs(unsigned char *in, int insz, unsigned char *out, int outsz, int big) {
    int     roff = 0,
            rlen = 0,
            ctype;

    ctype = RDP_MPPC_COMPRESSED | RDP_MPPC_FLUSH;
    if(big) ctype |= RDP_MPPC_BIG;
    if(mppc_expand(in, insz, ctype, &roff, &rlen) < 0) return -1;
    if(rlen < 0) return -1;
    if(rlen > outsz) rlen = outsz;
    memcpy(out, g_mppc_dict.hist + roff, rlen);
    return(rlen);
}



int moh_lzss(unsigned char *in, int insz, unsigned char *out, int outsz) {
    QUICK_IN_OUT
    unsigned        n,
                    x;
    unsigned char   b,
                    a;

    a = 0;
    b = 0;
    while(o < outl) {
        b <<= 1;
        if(!b) {
            if(in >= inl) break;
            a = *in++;
            b = 1;
        }
        if(a & b) {
            if(in >= inl) break;
            if(o >= outl) quickbms_unz_output_overflow;
            *o++ = *in++;
        } else {
            if((in + 2) > inl) break;
            x = in[0] | (in[1] << 8);
            in += 2;
            n = ((x >> 12) & 0xf) + 3;
            if((o + n) > outl) quickbms_unz_output_overflow;
            x = 0x1000 - (x & 0xfff);   // because it's already negative
            if((o - x) < out) return -1;
            while(n--) {
                *o = *(o - x);
                o++;
            }
        }
    }
    return o - out;
}



int moh_rle(unsigned char *in, int insz, unsigned char *out, int outsz) {
    QUICK_IN_OUT
    unsigned char   b,
                    s;

    while(o < outl) {
        if(in >= inl) break;
        s = *in++;
        if(s < 0x80) {
            s++;
            if((in + s) > inl) break;
            if((o + s) > outl) quickbms_unz_output_overflow;
            while(s--) {
                *o++ = *in++;
            }
        } else {
            if(in >= inl) break;
            b = *in++;
            s = 0x101 - s;
            if((o + s) > outl) quickbms_unz_output_overflow;
            while(s--) {
                *o++ = b;
            }
        }
    }
    return o - out;
}



// by thakis (http://www.amnoid.de/gc/)
// I have not verified if this algorithm is already implemented/known with other names but I guess yes... oh well
int decodeYaz0(u8* src, int srcSize, u8* dst, int uncompressedSize)
{
typedef struct {
  int srcPos, dstPos;
} Ret;
  Ret r = { 0, 0 };
  int i;
  //int srcPlace = 0, dstPlace = 0; //current read/write positions
  
  u32 validBitCount = 0; //number of valid bits left in "code" byte
  u8 currCodeByte = 0;
  while(r.dstPos < uncompressedSize)
  {
    //read new "code" byte if the current one is used up
    if(validBitCount == 0)
    {
      currCodeByte = src[r.srcPos];
      ++r.srcPos;
      validBitCount = 8;
    }
    
    if((currCodeByte & 0x80) != 0)
    {
      //straight copy
      dst[r.dstPos] = src[r.srcPos];
      r.dstPos++;
      r.srcPos++;
      //if(r.srcPos >= srcSize)
      //  return r;
    }
    else
    {
      //RLE part
      u8 byte1 = src[r.srcPos];
      u8 byte2 = src[r.srcPos + 1];
      r.srcPos += 2;
      //if(r.srcPos >= srcSize)
      //  return r;
      
      u32 dist = ((byte1 & 0xF) << 8) | byte2;
      u32 copySource = r.dstPos - (dist + 1);

      u32 numBytes = byte1 >> 4;
      if(numBytes == 0)
      {
        numBytes = src[r.srcPos] + 0x12;
        r.srcPos++;
        //if(r.srcPos >= srcSize)
        //  return r;
      }
      else
        numBytes += 2;

      //copy run
      for(i = 0; i < numBytes; ++i)
      {
        dst[r.dstPos] = dst[copySource];
        copySource++;
        r.dstPos++;
      }
    }
    
    //use next bit from "code" byte
    currCodeByte <<= 1;
    validBitCount-=1;    
  }

  return r.dstPos;
}



int byte2hex(u8 *input, int len, u8 *output, int outlen, int capital) {
    static const u8 hex_low[]  = "0123456789abcdef";
    static const u8 hex_high[] = "0123456789ABCDEF";
    int     i;
    u8      *o,
            *l,
            *hex;

    if(capital) hex = (u8 *)hex_high;
    else        hex = (u8 *)hex_low;

    if(len < 0) len = strlen(input);
    o = output;

    // out must be outlen+1
    if(outlen < 0) l = NULL;
    else           l = output + outlen;
    for(i = 0; i < len; i++) {
        if(l && ((o + 2) > l)) break;
        *o++ = hex[input[i] >> 4];
        *o++ = hex[input[i] & 15];
    }
    if(!l || (l && ((o + 1) <= l))) *o = 0;
    return o - output;
}



// code from Geoffrey W. Curtis
int undragonballz(u8 *in, int insz, u8 *out) {
    int     i;
    u8      *src,
            *src2,
            *end,
            *dst,
            v0,
            v1,
            v2,
            v3,
            v4;

    dst = out;
    src = in;
    end = src + insz;
    while (src < end)
    {
        v0 = *src++;
        
        v1 = (v0 >> 1) & 0x7F;
        v2 = (v1 >> 2);
        v3 = (v1 & 3);
        
        if (v0 & 1)
        {
            v4 = *src++;
            
            src2 = dst - v4;
        }
        else
        {
            src2 = src;
        }
        
        for (i = 0; i < v2; i++)
        {
            dst[0] = src2[0];
            dst[1] = src2[1];
            dst[2] = src2[2];
            dst[3] = src2[3];
            
            src2 += 4;
            dst += 4;
        }
        
        for (i = 0; i < v3; i++)
        {
            dst[0] = src2[0];
            
            ++src2;
            ++dst;
        }
        
        if (!(v0 & 1))
        {
            src = src2;
        }
    }
    return(dst - out);
}



int CRLE_Decode(u8 *target, int tlen, u8 *source, int slen)
{
	int i, s, t;
	u8 escape;
	s = t = 0;

	//tlen = ((DWORD*)source)[0];
	//s += sizeof(DWORD);
	escape = source[s];
	s++;

	//while (t < tlen)
    while((t < tlen) && (s < slen))
	{
		if (source[s] == escape)
		{
			for (i = 0; i < source[s+1]; i++)
				target[t++] = source[s+2];
			s += 3;
		}
		while((source[s] != escape) && (t < tlen))
			target[t++] = source[s++];
	}

	return t;
}



// ftp://ftp.elf.stuba.sk/pub/pc/pack/mar.rar
int MAR_RLE(unsigned char *HufBlock, int HufBlockSize, unsigned char *L, int N) {

   int I, BlockPos, Len, Inc, Code;

   BlockPos = 0;
   Len      = 0;
   Inc      = 1;

   for (I = 0; I < HufBlockSize; I++) {
      Code = HufBlock[I];
      if (Code == 0) {
         Len += Inc;
         Inc <<= 1;
      } else if (Code == 1) {
         Inc <<= 1;
         Len += Inc;
      } else {
         for (; Len > 0; Len--) L[BlockPos++] = 0;
         Len = 0;
         Inc = 1;
         L[BlockPos++] = Code - 1;
      }
   }

   for (; Len > 0; Len--) L[BlockPos++] = 0;

   //if (BlockPos != N) FatalError("BlockPos (%d) != N (%d) in DecodeRLE()",BlockPos,N);
    return(BlockPos);
}



// originally from http://gdcm.sourceforge.net
int gdcm_rle(unsigned char *in, int insz, unsigned char *out, int outsz) {
    int     numOutBytes = 0,
            numberOfReadBytes = 0;
    signed char byte;
        char nextByte;

    while( numberOfReadBytes < insz )
      {
      byte = in[numberOfReadBytes];
      numberOfReadBytes++;
      if( byte >= 0 /*&& byte <= 127*/ ) /* 2nd is always true */
        {
        memcpy( out + numOutBytes, in + numberOfReadBytes, byte+1 );
        numberOfReadBytes += byte+1;
        numOutBytes += byte+ 1;
        }
      else if( byte <= -1 && byte >= -127 )
        {
        nextByte = in[numberOfReadBytes];
        numberOfReadBytes++;
        memset(out + numOutBytes, nextByte, -byte + 1);
        numOutBytes += -byte + 1;
        }
      else /* byte == -128 */
        {
        //assert( byte == -128 );
        //out[numOutBytes++] = byte;  // added by me (Luigi) because I guess it's something missing
        }
        if(numOutBytes >= outsz) break;
        //assert( is.eof()
        //|| numberOfReadBytes + frame.Header.Offset[i] - is.tellg() == 0);
      //std::cerr << "numOutBytes: " << numOutBytes << " / " << length << "\n";
      //std::cerr << "numberOfReadBytes: " << numberOfReadBytes << "\n";
      }
    //assert( numOutBytes == length );

    return(numOutBytes);
}



enum { LZP_H_BITS=17, LZP_H_SIZE=1 << LZP_H_BITS, LZP_MATCH_FLAG=0xB5 };
#define LZP_ROR(x, y) ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define lzpC(X) (*(u32*)((X)-4))
static inline u32 lzpH(u32 c,u8* p) {
//    return (c+11*(c >> 15)+13*lzpC(p-1)) & (LZP_H_SIZE-1);
    return (c+5*LZP_ROR(c,17)+3*lzpC(p-1)) & (LZP_H_SIZE-1);
}
#define LZP_INIT(Pattern)                                                   \
    u32 i, k, n1=1, n=1;                                                   \
    u8* p, * InEnd=In+Size, * OutStart=Out, * HTable[LZP_H_SIZE];             \
    for (i=0;i < LZP_H_SIZE;i++)                HTable[i]=Pattern+5;            \
    lzpC(Out+4)=lzpC(In+4);                 lzpC(Out+8)=lzpC(In+8);         \
    i=lzpC(Out += 12)=lzpC(In += 12);       k=lzpH(i,Out);
int LZPDecode(u8* In,u32 Size,u8* Out,int MinLen)
{
    LZP_INIT(Out);
    do {
        p=HTable[k];
        if ( !--n )  { HTable[k]=Out;       n=n1; }
        if (*In++ != LZP_MATCH_FLAG || i != lzpC(p) || *--InEnd == 255)
                *Out++ = In[-1];
        else {
            HTable[k]=Out;                  n1 += (Out-p > (n1+1)*LZP_H_SIZE && n1 < 7);
            for (i=MinLen-1;*InEnd == 0;InEnd--)
                    i += 254;
            i += *InEnd;                    k=2*n1+2;
            do {
                if ( !--k ) { k=2*n1+1;     HTable[lzpH(lzpC(Out),Out)]=Out; }
                *Out++ = *p++;
            } while ( --i );
        }
        k=lzpH(i=lzpC(Out),Out);
    } while (In < InEnd);
    return (Out-OutStart);
}



int unpackbits(u8 *in, int insz, u8 *out) {
    int     i,
            j,
            o,
            count;

    o = 0;
    for(i = 0; i < insz;) {
        count = in[i++];
        if(count >= 128) {
            count = 256 - count;
            for(j = 0; j < (count + 1); j++) out[o++] = in[i];
            i++;
        } else {
            for(j = 0; j < (count + 1); j++) out[o++] = in[i++];
        }
    }
    return o;
}



// from Eduke32
#if defined(__POWERPC__)
static uint32_t eduke32_LSWAPIB(uint32_t a) { return(((a>>8)&0xff00)+((a&0xff00)<<8)+(a<<24)+(a>>24)); }
static uint16_t eduke32_SSWAPIB(uint16_t a) { return((a>>8)+(a<<8)); }
#else
#define eduke32_LSWAPIB(a) (a)
#define eduke32_SSWAPIB(a) (a)
#endif
int32_t eduke32_lzwuncompress(char *compbuf, int32_t compleng, char *ucompbuf, int32_t ucompleng)
{
    int32_t i, dat, leng, bitcnt, *lptr, numnodes, totnodes, nbits, oneupnbits, hmask, *prefix;
    char ch, *ucptr, *suffix;
    int32_t ucomp = (int32_t)ucompbuf;

    if (compleng >= ucompleng) { memcpy(ucompbuf,compbuf,ucompleng); return ucompleng; }

    totnodes = eduke32_LSWAPIB(((int32_t *)compbuf)[0]); if (totnodes <= 0 || totnodes >= ucompleng+256) return 0;

    prefix = (int32_t *)malloc(totnodes*sizeof(int32_t)); if (!prefix) return 0;
    suffix = (char *)malloc(totnodes*sizeof(uint8_t)); if (!suffix) { free(prefix); return 0; }

    numnodes = 256; bitcnt = (4<<3); nbits = 8; oneupnbits = (1<<8); hmask = ((oneupnbits>>1)-1);
    do
    {
        lptr = (int32_t *)&compbuf[bitcnt>>3]; dat = ((eduke32_LSWAPIB(lptr[0])>>(bitcnt&7))&(oneupnbits-1));
        bitcnt += nbits; if ((dat&hmask) > ((numnodes-1)&hmask)) { dat &= hmask; bitcnt--; }

        prefix[numnodes] = dat;

        ucompbuf++;
        for (leng=0; dat>=256; dat=prefix[dat])
        {
            if ((int32_t)ucompbuf+leng-ucomp > ucompleng) goto bail;
            ucompbuf[leng++] = suffix[dat];
        }

        ucptr = &ucompbuf[leng-1];
        for (i=(leng>>1)-1; i>=0; i--) { ch = ucompbuf[i]; ucompbuf[i] = ucptr[-i]; ucptr[-i] = ch; }
        ucompbuf[-1] = dat; ucompbuf += leng;

        suffix[numnodes-1] = suffix[numnodes] = dat;

        numnodes++; if (numnodes > oneupnbits) { nbits++; oneupnbits <<= 1; hmask = ((oneupnbits>>1)-1); }
    }
    while (numnodes < totnodes);

bail:
    free(suffix); free(prefix);
    return (int32_t)ucompbuf-ucomp;
}



/**
 * Decompress a block of RLE encoded memory.
 */
long xu4_rleDecompress(unsigned char *indata, long inlen, unsigned char *outdata, long outlen) {
    int i;
    unsigned char *p, *q;
    unsigned char ch, count, val;

    p = indata;
    q = outdata;
    while ((p - indata) < inlen) {
        ch = *p++;
        if (ch == 02) { // RLE_RUNSTART
            count = *p++;
            val = *p++;
            for (i = 0; i < count; i++) {
                *q++ = val;
                if ((q - outdata) >= outlen)
                    break;
            }
        } else {
            *q++ = ch;
            if ((q - outdata) >= outlen)
                break;
        }
    }

    return q - outdata;
}



// http://www.lemurproject.org
/*==========================================================================
 * Copyright (c) 2001 Carnegie Mellon University.  All Rights Reserved.
 *
 * Use of the Lemur Toolkit for Language Modeling and Information Retrieval
 * is subject to the terms of the software license set forth in the LICENSE
 * file included with this software, and also available at
 * http://www.lemurproject.org/license.html
 *
 *==========================================================================
 */
int RVLCompress_decompress_ints (unsigned char *data_ptr,
                                                  int *out_ptr,
                                                  int num_bytes)
{

  unsigned char *data_end_ptr = data_ptr + num_bytes;
  unsigned char *data_curr_ptr;
  int *out_ptr_end = out_ptr;

  for (data_curr_ptr=data_ptr; data_curr_ptr<data_end_ptr; out_ptr_end++) {
    if (*data_curr_ptr & 128) {
      *out_ptr_end = 127 & *data_curr_ptr;
      data_curr_ptr ++;
    } else if (*(data_curr_ptr+1) & 128) {
      *out_ptr_end = *data_curr_ptr |
        ((*(data_curr_ptr + 1) & 127) << 7);
      data_curr_ptr += 2;
    } else if (*(data_curr_ptr+2) & 128) {
      *out_ptr_end = *data_curr_ptr |
        (*(data_curr_ptr + 1) << 7) |
        ((*(data_curr_ptr + 2) & 127) << 14);
      data_curr_ptr += 3;
    } else if (*(data_curr_ptr+3) & 128) {
      *out_ptr_end = *data_curr_ptr |
        (*(data_curr_ptr + 1) << 7) |
        (*(data_curr_ptr + 2) << 14) |
        ((*(data_curr_ptr + 3) & 127) << 21);
      data_curr_ptr += 4;
    } else {
      *out_ptr_end = *data_curr_ptr |
        (*(data_curr_ptr + 1) << 7) |
        (*(data_curr_ptr + 2) << 14) |
        (*(data_curr_ptr + 3) << 21) |
        ((*(data_curr_ptr + 4) & 127) << 28);
      data_curr_ptr += 5;
    }
  } // for
  
  return (out_ptr_end - out_ptr);
}



// http://code.google.com/p/pdb2txt/
size_t	pdb_decompress(u8 *source,size_t srclen,u8 *dest,size_t destlen)
{
  u8	    *se=source+srclen;
  u8	    *de=dest+destlen;
  u8	    *dd=dest;

  while (source<se && dest<de) {
    size_t c=*source++;
    if (c>=1 && c<=8) { // copy
      while (c-- && source<se && dest<de)
	*dest++=*source++;
    } else if (c<=0x7f) // this char
      *dest++=(u8)c;
    else if (c>=0xc0) { // space + c&0x7f
      *dest++=' ';
      if (dest<de)
	*dest++=(u8)c&0x7f;
    } else if (source<se) { // copy from decoded buf
      c=(c<<8)|*source++;
      int k=(c&0x3fff)>>3;
      c=3+(c&7);
      if (dest-k<dd || dest+c>de) // invalid buffer
	break;
      while (c-- && dest<de) {
	*dest=dest[-k];
	++dest;
      }
    }
  }
  return dest-dd;
}



int rtldecompress(int type, u8 *in, int insz, u8 *out, int outsz) {
#define RTL_COMPRESSION_FORMAT_LZNT1         (0x0002)   // winnt
#define RTL_COMPRESSION_FORMAT_XPRESS        (0x0003)   // added in Windows 8
#define RTL_COMPRESSION_FORMAT_XPRESS_HUFF   (0x0004)   // added in Windows 8
#ifdef WIN32
    static HMODULE hlib = NULL;
    static DWORD WINAPI (*RtlDecompressBuffer)(
      /*IN*/    USHORT  CompressionFormat,
      /*OUT*/   PUCHAR  UncompressedBuffer,
      /*IN*/    ULONG   UncompressedBufferSize,
      /*IN*/    PUCHAR  CompressedBuffer,
      /*IN*/    ULONG   CompressedBufferSize,
      /*OUT*/   PULONG  FinalUncompressedSize
    ) = NULL;

    ULONG   ret;

    if(!RtlDecompressBuffer) {
        if(!hlib) hlib = LOADDLL("ntdll.dll");
        if(!hlib) hlib = LOADDLL("ntdll-8-32.dll");
        if(!hlib) return -1;
        RtlDecompressBuffer = GETFUNC("RtlDecompressBuffer");
        if(!RtlDecompressBuffer) return -1;
    }
    if(RtlDecompressBuffer(
        type,
        out,
        outsz,
        in,
        insz,
        &ret) != 0) return -1; // STATUS_SUCCESS is 0
    return ret;
#else
    return -1;
#endif
}



// code by MrAdults (SeÒor Casaroja's Noesis)
// http://forum.xentax.com/viewtopic.php?p=52279#p52279
int Model_GMI_Decompress(unsigned char *src, int srcLen, unsigned char *dst, int dstLen)
{
   int srcPtr = 0;
   int dstPtr = 0;
   int i;
   int j;

   while (srcPtr < srcLen && dstPtr < dstLen)
   {
      unsigned char ctrl = src[srcPtr++];
      for (i = 0; i < 8 && srcPtr < srcLen; i++)
      {
         if (ctrl & (1<<i))
         { //literal
            dst[dstPtr++] = src[srcPtr++];
         }
         else
         { //ofs+len
            short ol = *(short *)(src+srcPtr);
            srcPtr += sizeof(short);
            int len = 3 + ((ol>>8) & 15);
            int relOfs = (ol & 255) | ((ol>>12) << 8);
            int ofs = dstPtr - ((dstPtr-18-relOfs) & 4095);
            for (j = 0; j < len; j++)
            {
               if (ofs+j < 0 || ofs+j >= dstPtr)
               {
                  dst[dstPtr++] = 0;
               }
               else
               {
                  dst[dstPtr++] = dst[ofs+j];
               }
            }
         }
      }
   }
   return dstPtr;
}



/*
http://pastebin.com/186Amx8T
*/

int dewolf(unsigned char * src, int srclen, unsigned char * dest, int destlen) {
    unsigned char m = src[8];
    int ps = 9, pd = 0;
    while(ps < srclen && pd < destlen)
    {
        if(ps>=0x422)
            ps=ps;
        if(src[ps] == m)
        {
            ps++;
            if(src[ps] == m)
                dest[pd++] = src[ps++];
            else
            {
                if(src[ps] >= m)
                    src[ps]--;
                int pos = 0, len = (src[ps] >> 3) + 4;
                unsigned char type1 = src[ps++] & 7;
                unsigned char type2 = type1 >> 2;
                type1 &= 3;
                if(type2)
                    len += src[ps++] << 5;
 
                if(type1 == 0)
                    pos = src[ps++] + 1;
                else if(type1 == 1)
                {
                    pos = src[ps] + (src[ps + 1] << 8) + 1;
                    ps += 2;
                }
                else if(type1 == 2)
                {
                    pos = src[ps] + (src[ps + 1] << 8) + (src[ps + 2] << 16) + 1;
                    ps += 3;
                }
                else
                    type1 = type1;
 
                int k;
                for(k = 0; k < len; ++k)
                    dest[pd + k] = dest[pd - pos + k];
                pd += len;
            }
        }
        else
        {
            dest[pd++] = src[ps++];
        }
    }
    ps = 0;
    return(pd);
}



// code written by Ekey (h4x0r) of http://www.progamercity.net
// http://forum.xentax.com/viewtopic.php?p=80129&sid=d49d1cc543b79b937272aaff036fb046#p80129
unsigned __cdecl CO_Decompress(unsigned char *szOutBuf, unsigned szUncompressedSize, unsigned char *szInBuf)
{
  unsigned result;
  unsigned char *v4;
  int v5;
  char v6;
  char v7;
  int v8;
  int16_t v9;
  int v10;
  char v11;
  int v12;
  char v13;
  signed int v14;
  int16_t v15;
  int v16;
  char v17[4096];
  //int v19;
  unsigned char *v20;

  v4 = szInBuf;
  v5 = 0;
  memset(v17, 0, 0x1000u);
  result = 0;
LABEL_2:
  v6 = *(u8 *)v4;
  v15 = *(u8 *)v4++;
  v16 = 0;
  while ( v6 >= 0 )
  {
    v13 = *(u8 *)v4;
    if ( szUncompressedSize > result )
    {
      *(u8 *)(szOutBuf + result++) = v13;
      v17[(int16_t)v5] = v13;
      v5 = (v5 + 1) & 0xFFF;
      v14 = 1;
    }
    else
    {
      v14 = 0;
    }
    ++v4;
    if ( !v14 )
      return 0;
LABEL_13:
    v6 = 2 * v15;
    v15 *= 2;
    ++v16;
    if ( v16 == 8 )
      goto LABEL_2;
  }
  v7 = *(u8 *)v4;
  if ( !*(u8 *)v4 )
    return result;
  v9 = 16 * (256 - (u8)(v7 & 0xF0)) - *(u8 *)(v4 + 1);
  v10 = (v7 & 0xF) + 2;
  v8 = (u16)v10;
  v4 += 2;
  v20 = v4;
  if ( !(u16)v10 )
    goto LABEL_13;
  while ( 1 )
  {
    v12 = (int16_t)v5;
    v11 = v17[((int16_t)v5 + v9) & 0xFFF];
    if ( szUncompressedSize <= result )
      return 0;
    *(u8 *)(szOutBuf + result) = v11;
    --v8;
    ++result;
    v5 = (v5 + 1) & 0xFFF;
    v17[v12] = v11;
    if ( !(u16)v8 )
    {
      v4 = v20;
      goto LABEL_13;
    }
  }
  return result;
}



int unlzlib(u8 *in, int insz, u8 *out, int outsz) {
    int     i,
            o,
            len;

    // this method is terrible, I have found no examples
    // for doing a simple input->output job... really boring
    // note that I have not tried this thing
    struct LZ_Decoder  *lz;
    lz = LZ_decompress_open();
    if(!lz) return -1;
    i = 0;
    o = 0;
    for(;;) {
        if(i < insz) {
            LZ_decompress_write(lz, in + i, 1);
            i++;
            if(i >= insz) LZ_decompress_finish(lz);
        } else {
            if(LZ_decompress_finished(lz)) break;
        }
        if(!LZ_decompress_finished(lz)) {
            if(o >= outsz) {
                //quickbms_unz_output_overflow //o = -1;
                break;
            }
            len = LZ_decompress_read(lz, out + o, 1);
            if(len < 0) {
                o += len;
                break;
            }
            o += len;
        }
    }
    LZ_decompress_close(lz);
    return o;
}



// PSP_Nanoha
int lzs_unzip(u8 *datapart, int Size_DataPart, u8 *dictionarypart, int dictionarypart_Length, u8 *b_unzip, int size_unzip) {
    const int THRESHOLD = 2;
    int i, f;
                int i_out = 0, i_data = 0, i_dic = 0; //œ¬÷∏±ÅE
                byte c;
                UInt16 flags; //±ÅEæ£¨∂˛Ω¯÷∆µƒ16Œª¥””“µΩ◊Û±˙ÊæΩ”œ¬¿¥µƒ16◊È ˝æ› «∑ÒŒ™—πÀı∏Ò Ω(1≤ª—πÀı£¨0—πÀÅE

                flags = 0;
                for (; ; )
                {
                    if (i_data == Size_DataPart)  // ◊œ»,∂¡»ÅEΩ◊÷Ω⁄µΩflags
                        break;
                    flags = datapart[i_data++];  //œ»∂¡»ÅEƒ‘⁄µÕ8Œª
                    if (i_data == Size_DataPart)
                        break;
                    flags |= (UInt16)(datapart[i_data++] << 8); //∫Û∂¡»ÅEƒ‘⁄∏ﬂ8Œª

                    for ( f = 0; f < 16; f++) {  //Ω¯––16¥Œ∂¡»° ˝æ›µƒ≤Ÿ◊ÅE
                        if (((flags >> f) & 1) != 0)   //flagµƒ”“∆µ⁄fŒªŒ™1,±˙ÊæΩ”œ¬¿¥µƒ «∑«—πÀı ˝æ›
                        {
                            if (i_dic == dictionarypart_Length)
                                break;
                            c = dictionarypart[i_dic++];
                            if(i_out >= size_unzip) quickbms_unz_output_overflow;
                            b_unzip[i_out++] = c;  //ƒ«√¥÷±Ω”¥”◊÷µ‰∂Œ∂¡»°“ª◊÷Ω⁄µΩ  ‰≥ˆ ˝◊ÅE
                        }
                        else     //flagµƒ”“∆µ⁄fŒªŒ™0,±˙ÊæΩ”œ¬¿¥µƒ «—πÀı ˝æ›
                        {
                            if (i_data == Size_DataPart)
                                break;
                            UInt16 t = datapart[i_data++];
                            if (i_data == Size_DataPart)
                                break;
                            t |= (UInt16)(datapart[i_data++] << 8);  //∂¡»°¡Ω◊÷Ω⁄µΩt(∏˙flags“ª—ÅEœ»∂¡»ÅEƒ‘⁄µÕ8Œª)

                            int size = (int)(t & 0x1F) + THRESHOLD;  //tµƒ∫ÅEŒª + THRESHOLD Œ™≥§∂»
                            int offset = (int)(t >> 5);  //tµƒ«∞11Œ™Œ™æ‡¿ÅE

                            for ( i = 0; i < size; i++, i_out++) {  //¥”  ‰≥ˆ ˝◊Èµƒ µ±«∞Œª÷√ - offset ø™ º,∂¡»°size∏ˆ◊÷Ω⁄µΩ ‰≥ˆ ˝◊ÅE
                                if(i_out >= size_unzip) quickbms_unz_output_overflow;
                                b_unzip[i_out] = b_unzip[i_out - offset]; //¥Àπ˝≥Ã±ÿ–ÅEª∏ˆ◊÷Ω⁄“ª∏ˆ◊÷Ω⁄µƒΩ¯––
                            }

                        } //—≠ª∑Ω· ¯µƒÃıº˛Œ™ data∂Œ∂¡ÕÅEÛ‘Ÿ¥Œ ’µΩ∂¡»°data∂Œµƒ«ÅEÅE
                    }
                }
    return i_out;
}



// by CUE 2009
// http://www.romhacking.net/utilities/920/
int legend_of_mana(unsigned char *pak_buffer, int pak_length, unsigned char *raw_buffer, int raw_length) {
  unsigned char   *pak, *raw;
  unsigned char   code;
  unsigned char   x, y, z;
    signed char   i; // must be signed to extend the sign in the FB code
  unsigned short  n, p;

  //if (*pak_buffer == 0x01 /*MAGIC*/) pak = pak_buffer + 1;
  //else 
    pak = pak_buffer;
  raw = raw_buffer;

  do {
    /*
    // not enough memory?
    if (raw + MEMORY_FREE > raw_buffer + raw_length) {
      length = raw - raw_buffer;
      raw_length += MEGABYTE;
      raw_buffer = ReAssign(raw_buffer, raw_length, sizeof(char));
      raw = raw_buffer + length;
    }
    */

    // chunk
    switch (code = *pak++) {
      case 0xF0: // F0+XN: put (N+3) times {X}
        n = (*pak & 0xF) + 3;
        x = *pak++ >> 4;
        while (n--) {
          *raw++ = x;
        }
        break;

      case 0xF1: // F1+N+X: put (N+4) times {X}
        n = *pak++ + 4;
        x = *pak++;
        while (n--) {
          *raw++ = x;
        }
        break;

      case 0xF2: // F2+N+YX: put (N+2) times {X,Y}
        n = *pak++ + 2;
        x = *pak & 0xF;
        y = *pak++ >> 4;
        while (n--) {
          *raw++ = x;
          *raw++ = y;
        }
        break;

      case 0xF3: // F3+N+X+Y: put (N+2) times {X,Y}
        n = *pak++ + 2;
        x = *pak++;
        y = *pak++;
        while (n--) {
          *raw++ = x;
          *raw++ = y;
        }
        break;

      case 0xF4: // F4+N+X+Y+Z: put (N+2) times {X,Y,Z}
        n = *pak++ + 2;
        x = *pak++;
        y = *pak++;
        z = *pak++;
        while (n--) {
          *raw++ = x;
          *raw++ = y;
          *raw++ = z;
        }
        break;

      case 0xF5: // F5+N+X+{list}: put (N+4) times {X,byte}
        n = *pak++ + 4;
        x = *pak++;
        while (n--) {
          *raw++ = x;
          *raw++ = *pak++;
        }
        break;

      case 0xF6: // F6+N+X+Y+{list}: put (N+3) times {X,Y,byte}
        n = *pak++ + 3;
        x = *pak++;
        y = *pak++;
        while (n--) {
          *raw++ = x;
          *raw++ = y;
          *raw++ = *pak++;
        }
        break;

      case 0xF7: // F7+N+X+Y+Z+{list}: put (N+2) times {X,Y,Z,byte}
        n = *pak++ + 2;
        x = *pak++;
        y = *pak++;
        z = *pak++;
        while (n--) {
          *raw++ = x;
          *raw++ = y;
          *raw++ = z;
          *raw++ = *pak++;
        }
        break;

      case 0xF8: // F8+N+X: put from {X} to {X+(N+3)}
        n = *pak++ + 4;
        x = *pak++;
        while (n--) {
          *raw++ = x++;
        }
        break;

      case 0xF9: // F9+N+X: put from {X} to {X-(N+3)}
        n = *pak++ + 4;
        x = *pak++;
        while (n--) {
          *raw++ = x--;
        }
        break;

      case 0xFA: // FA+N+X+I: put from {X} to {X+(N+4)*I)}
        n = *pak++ + 5;
        x = *pak++;
        i = *pak++;
        while (n--) {
          *raw++ = x;
          x += i;
        }
        break;

      case 0xFB: // FB+N+X+Y+I: put from {YX} to {YX+(N+2)*I}
        n = *pak++ + 3;
        p = *(short *)pak; pak += 2;
        i = *pak++; // 'i' must be signed to extend the sign
        while (n--) {
          *(short *)raw = p; raw += 2;
          p += i;
        }
        break;

      case 0xFC: // FC+XY+NZ: put (N+4) bytes from '$-(ZXY+1)'
        p = (*(unsigned short *)pak++ & 0xFFF) + 1;
        n = (*pak++ >> 4) + 4;
        while (n--) {
          *raw = *(raw - p); raw++;
        }
        break;

      case 0xFD: // FD+X+N: put (N+20) bytes from '$-(X+1)'
        p = *pak++ + 1;
        n = *pak++ + 20;
        while (n--) {
          *raw = *(raw - p); raw++;
        }
        break;

      case 0xFE: // FE+XN: put (N+3) bytes from '$-8*(X+1)'
        p = ((*pak >> 4) + 1) << 3;
        n = (*pak++ & 0xF) + 3;
        while (n--) {
          *raw = *(raw - p); raw++;
        }
        break;

      case 0xFF: // FF: end of compressed data
        break;

      default: // N+{list}: put (N+1) times {byte}
        n = code + 1;
        while (n--) {
          *raw++ = *pak++;
        }
        break;
    }
  } while ((code != 0xFF) && (pak - pak_buffer < pak_length));

  //if (code != 0xFF) printf("WARNING: No end code found!\n\n");
  //if (pak - pak_buffer != pak_length) printf("WARNING: Bad coded length!\n\n");

  return raw - raw_buffer;
}




// by ffgriever
// http://www.romhacking.net/utilities/533/
int dizzy(u8 *in, int count, u8 *out) {
    u8 *inl = in + count;
    u8 *bck = out;
	char tile16dec[16], tile16[32];
    u32   adr_cnt;
    u32   cmprline_len, unc_bytes, run_bytes;
    u32 i;
		for ( i = 0; i < count; i++)
		{
            if(in >= inl) break;
			memset(tile16, 0, 32);
			memset(tile16dec, 0, 32);
            tile16[0] = *in++;
			unc_bytes = (((tile16[0]>>4) & 0x0F) + 1);
			run_bytes = (tile16[0] & 0x0F);
			if (((run_bytes + unc_bytes) > 16))
			{
				//printf("Mamy problem: dlugosc linii wieksza od 16!\nNumer linii: %d, adres: 0x%08x\n", i+1, adr_cnt);
				//break;
                return -1;
			}
			//printf("tile16[0] = 0x%02x\n", tile16[0]);
			cmprline_len = 17 - run_bytes;
			//printf("Line Len: %d, address: 0x%08x\n", cmprline_len, adr_cnt);
			tile16[1] = *in++;
			adr_cnt += cmprline_len;

			memcpy(tile16dec, &tile16[1], unc_bytes);
			memset(&tile16dec[unc_bytes], tile16[unc_bytes], run_bytes);
			memcpy(&tile16dec[unc_bytes+run_bytes], &tile16[unc_bytes+1], 16-unc_bytes-run_bytes);

            memcpy(out, tile16, cmprline_len);  //fwrite(tile16dec, 16, 1, fdout);
            out += cmprline_len;
		}
    return out - bck;
}



// c/o Noah 'Zoinkity' Granath (nefariousdogooder@yahoo.com) Oct. 2008
// RomHacking
unsigned long EDL_byteswap(unsigned long w)
{return (w >> 24) | ((w >> 8) & 0x0000ff00) | ((w << 8) & 0x00ff0000) | (w << 24);
}   
unsigned long EDL_helper(unsigned long long int *data,unsigned long bitcount,unsigned char *in,unsigned long *pos,unsigned long max,int endian)
{unsigned long x,y,z;

if(bitcount>32) return bitcount;   /*essentially, do nothing!*/
z=*data;
y=0;
x=max-*pos;
if(x>4) x=4;   /*#bytes to retrieve from file*/
//fseek(in,*pos,SEEK_SET);
//fread(&y,x,1,in);
memcpy(&y, in + (*pos), x);
if(endian) y=EDL_byteswap(y);
*pos+=x;

*data=y;       /*tack old data on the end of new data for a continuous bitstream*/
*data=*data<<bitcount;
*data|=z;

x*=8;          /*revise bitcount with number of bits retrieved*/
return bitcount+x;}

/*generate tables*/
int EDL_FillBuffer(unsigned short *large,unsigned char *what,long total,long num,char bufsize)
{unsigned char *buf;
unsigned short *when,*samp;
unsigned long *number;
long x,y,z,back;

       /*my implementation is stupid and alays copies the block, so this uses even more memory than it should
       if(!(what=realloc(what,num))
           {printf("\nVirtual memory exhausted.\nCan not continue.\n\tPress ENTER to quit.");
           getchar();
           return 0;
           }*/
       if(!(when=calloc(num,2)))
         {printf("\nVirtual memory exhausted.\nCan not continue.\n\tPress ENTER to quit.");
         getchar();
         return 0;
         }/*end calloc*/
       if(!(samp=calloc(num,2)))
         {printf("\nVirtual memory exhausted.\nCan not continue.\n\tPress ENTER to quit.");
         getchar();
         return 0;
         }/*end calloc*/
       if(!(number=calloc(16,4)))
         {printf("\nVirtual memory exhausted.\nCan not continue.\n\tPress ENTER to quit.");
         getchar();
         return 0;
         }/*end calloc*/
       memset(large,0,0xC00);         /*both buffers have 0x600 entries each*/

       /*build an occurance table*/
       back=0;  /*back will act as a counter here*/
       for(y=1;y<16;y++)/*sort occurance*/
          {for(x=0;x<total;x++)/*peek at list*/
                {if(what[x]==y)
                   {when[back]=x;
                   back++;
                   number[y]++;
                   }
                }/*end peek*/
          }/*end occurance*/

       x=0;
       for(y=1;y<16;y++)/*sort nibbles*/
          {for(z=number[y];z>0;z--) 
              {what[x]=y; x++;}
          }/*end sort*/
       free(number);

       /*generate bitsample table*/
       z=what[0];           /*first sample, so counting goes right*/
       back=0;              /*back will act as the increment counter*/
       for(x=0;x<num;x++)
          {y=what[x];
          if(y!=z) {z=y-z; back*=(1<<z); z=y;}
          y=(1<<y)|back;
          back++;
          do{samp[x]=samp[x]<<1;
             samp[x]+=(y&1);
             y=y>>1;
             }while(y!=1);
          }/*end bitsample table*/

       if(!(buf=calloc(1<<bufsize,1)))
         {printf("\nVirtual memory exhausted.\nCan not continue.\n\tPress ENTER to quit.");
         getchar();
         return 0;
         }/*end calloc      80013918*/
       
       for(x=0;x<num;x++)  /*fill buffer    8001392C*/
          {back=what[x];      /*#bits in sample*/
          if(back<bufsize)         /*normal entries*/
            {y=1<<back;
             z=samp[x];       /*offset within buffer*/
            do{
              large[z]=(when[x]<<7) + what[x];
              z+=y;
              }while(!(z>>bufsize));
            }/*end normal*/
          else
            {y=(1<<bufsize)-1; /*this corrects bitmask for buffer entries*/
            z=samp[x]&y;
            buf[z]=what[x];
            }/*end copies*/
          }/*end fill*/
       
       /*read coded types > bufsize    80013AA8*/
       z=0;      /*value*/
       for(x=0;!(x>>bufsize);x++)/*read buf*/
          {y=buf[x];
          if(y)
            {y-=bufsize;
            if(y>8) return -8;
            back=(z<<7) + (y<<4);  /*value*0x80 + bits<<4*/
            large[x]=back;
            z+=(1<<y);
            }/*end if(y)*/
          }/*end buf reading*/
       free(buf);
       if(z>0x1FF) return -9;

       /*do something tricky with the special entries    80013B3C*/
       back=1<<bufsize;
       for(x=0;x<num;x++)
          {if(what[x]<bufsize) continue;
          z=samp[x] & (back-1);
          z=large[z];     /*in dASM, this is labelled 'short'*/
          y=samp[x]>>bufsize;
          /*80013BEC*/
          do{large[y+(z>>7)+(1<<bufsize)]=(when[x]<<7)+what[x];
             y=y+(1<<(what[x]-bufsize));
             }while((y>>((z>>4)&7))==0);
          }
       free(when);
       free(samp);

return 0;}


/*cool bitwise table type*/
unsigned long EDLdec1(unsigned long pos,unsigned char *in,unsigned char *out,unsigned long size,unsigned long max,int endian)
{unsigned char bits[9];  /*what=p->list of slots*/
long x,y,z,stack=0;
unsigned long count=0,num,back;  /*count=#bits in register, num=#to copy, back=#to backtrack*/
unsigned short small[0x600],large[0x600];   /*when=p->occurance in list*/
unsigned char  table1[]={0,1,2,3,4,5,6,7,8,0xA,0xC,0xE,0x10,0x14,0x18,0x1C,0x20,0x28,0x30,0x38,0x40,0x50,0x60,0x70,0x80,0xA0,0xC0,0xE0,0xFF,0,0,0};
unsigned char  table2[]={0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0,0};
unsigned short table3[]={0,1,2,3,4,6,8,0xC,0x10,0x18,0x20,0x30,0x40,0x60,0x80,0xC0,0x100,0x180,0x200,0x300,0x400,0x600,0x800,0xC00,0x1000,0x1800,0x2000,0x3000,0x4000,0x6000};
unsigned char  table4[]={0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,0xA,0xA,0xB,0xB,0xC,0xC,0xD,0xD,0,0};
unsigned char what[0x400];
unsigned long long data=0;       /*64bit datatable container*/

int ftell_out = 0;
size+=pos;

for(/*pos+=12*/;pos<=size;back=0)
   {memset(bits,0,8); /*clear bits between... stuff*/
   count=EDL_helper(&data,count,in,&pos,size,endian);
   x=data&1; data=data>>1; count--;
   
   if(x)     /*mode 1 - tables*/
     {count=EDL_helper(&data,count,in,&pos,size,endian);/*build large table*/
     x=data&0x1FF; data=data>>9; count-=9;
     //if(flagrant.message) printf("\nmode1\tpos: %X\tout: %X\tdata: %X",pos,ftell_out,data);
     if(x) /*construct tables*/
       {
       memset(what,0,0x400);
       num=0;    /*true # entries, since 0 entries are not counted!*/
       for(y=0;y<x;y++)/*fill table with nibbles*/
          {count=EDL_helper(&data,count,in,&pos,size,endian);
          back=data&1; data=data>>1; count--;
          if(back)/*grab nibble*/
            {count=EDL_helper(&data,count,in,&pos,size,endian);
            stack=data&0xF; data=data>>4; count-=4;
            }/*end grab*/
          what[y]=stack;
          if(stack) num++;   /*count nonzero entries*/
          }/*end fill*/
       x=EDL_FillBuffer(large,what,x,num,10);
       }/*end construction*/
     if(x<0) {if(x < 0) return -1;
             if(x) return x;}

     count=EDL_helper(&data,count,in,&pos,size,endian);/*build smaller table*/
     x=data&0x1FF; data=data>>9; count-=9;
     if(x) /*construct tables*/
       {
       memset(what,0,0x400);
       num=0;    /*true # entries, since 0 entries are not counted!*/
       for(y=0;y<x;y++)/*fill table with nibbles*/
          {count=EDL_helper(&data,count,in,&pos,size,endian);
          back=data&1; data=data>>1; count--;
          if(back)/*grab nibble*/
            {count=EDL_helper(&data,count,in,&pos,size,endian);
            stack=data&0xF; data=data>>4; count-=4;
            }/*end grab*/
          what[y]=stack;
          if(stack) num++;   /*count nonzero entries*/
          }/*end fill*/
       x=EDL_FillBuffer(small,what,x,num,8);
       }/*end construction*/
     if(x<0) {if(x < 0) return -1;
             if(x) return x;}
     
     /*write data*/
    do{
     count=EDL_helper(&data,count,in,&pos,size,endian);/*build smaller table*/
     x=data&0x3FF;
     x=large[x];          /*x=short from thingy*/
     y=x&0xF;             /*y=normal bitcount*/
     z=(x>>4)&7;       /*z=backtrack bitcount*/
     //if(flagrant.message) printf("\n\tout: %X\tsample: %04X\tvalue: %X\tdata: %X",ftell_out,x,x>>7,data);
     if(y==0)  /*backtrack entry*/
       {x=x>>7; /*short's data*/
        y=(1<<z)-1;       /*bitmask*/
        count=EDL_helper(&data,count,in,&pos,size,endian);
        y=(data>>10)&y;
        x+=y;
        x=large[x+0x400];
        y=x&0xF;
        }/*end backtrack entry*/
     
     data=data>>y; count-=y;
     y=0;
     x=x>>7;       /*data only*/
     if(x<0x100) 
       {out[ftell_out++] = x;
       if(ftell_out>max) return ftell_out;}
     else if(x>0x100)/*copy previous*/
        {z=table2[x-0x101];
        if(z)        /*segment*/
          {count=EDL_helper(&data,count,in,&pos,size,endian);
          y=(1<<z)-1;  /*mask*/
          y=data&y; data=data>>z; count-=z;
          }        /*end segment*/
        z=table1[x-0x101];
        num=z+y+3;
        count=EDL_helper(&data,count,in,&pos,size,endian);
        x=data&0xFF; x=small[x];

        y=x&0xF;             /*y=normal bitcount*/
        z=(x&0x70)>>4;       /*z=backtrack bitcount*/
        if(y==0)  /*backtrack entry*/
          {x=x>>7; /*short's data*/
          y=(1<<z)-1;       /*bitmask*/
          count=EDL_helper(&data,count,in,&pos,size,endian);
          y=(data>>8)&y;
          x+=y;
          x=small[x+0x100];
          y=x&0xF;
          }/*end backtrack entry*/
        data=data>>y; count-=y;
        
        /*pull number of bits*/
        y=0;
        x=x>>7;
        z=table4[x];
        if(z)        /*segment*/
          {count=EDL_helper(&data,count,in,&pos,size,endian);
          y=data&((1<<z)-1); data=data>>z; count-=z;
          }        /*end segment*/
        z=table3[x];
        back=z+y+1;

        /*copy run*/
        for(x=0;num>0;num--)
           {z=ftell_out-back;
           if(z<0 || z>=ftell_out) x=0;
           else{//fseek(out,0-back,SEEK_END);     /*backward position*/
               //x=fgetc(out);
               x = out[ftell_out - back];
               }
           //fseek(out,0,SEEK_END);
           out[ftell_out++] = x;
           if(ftell_out>max) return ftell_out;     /*failsafe*/
           }/*end copy run*/
/*        for(x=0;num>0;num-=x)      this is faster but would need a catch
           {x=num;                   to keep it from copying bytes that have
           if(x>8) x=8;              not yet been written
           fseek(out,0-back,SEEK_END);
           fread(bits,1,x,out);
           fseek(out,0,SEEK_END);
           fwrite(bits,1,x,out);
           if(ftell_out>max) return ftell_out;
           }end debug-sometime-later*/
        }/*end copy previous*/
    }while(x!=0x100);     
   }/*mode 1*/
   else      /*mode 0 - */
     {count=EDL_helper(&data,count,in,&pos,size,endian);
     num=data&0x7FFF; data=data>>15; count-=15;
     //if(flagrant.message) printf("\nmode0\tpos: %X\tout: %X",pos,ftell_out);
     if(num) 
       {for(/*fseek(out,0,SEEK_END)*/;num>0;num--)
           {count=EDL_helper(&data,count,in,&pos,size,endian);
           x=data&0xFF; data=data>>8; count-=8;
           out[ftell_out++] = x;
           }/*end for()*/
       }/*write bytes*/
     }/*mode 0*/

   /*test EOF*/
   count=EDL_helper(&data,count,in,&pos,size,endian);
   x=data&1; data=data>>1; count--;
   if(x) return ftell_out;        /*1=EOF marker*/
   }

return ftell_out;}

/*boring RLE magic*/
unsigned long EDLdec2(unsigned long pos,unsigned char *in,unsigned char *out,unsigned long size,unsigned long max,int endian)
{unsigned char bits[9];
long x;
unsigned long count=0,num,back;  /*count=#bits in register, num=#to copy, back=#to backtrack*/
unsigned long long int data=0;       /*64bit datatable container*/
int ftell_out = 0;
/*set up data and count*/
size+=pos;

for(/*pos+=12*/;pos<=size;back=0)
   {memset(bits,0,9); /*clear bits between... stuff*/
   count=EDL_helper(&data,count,in,&pos,size,endian);
   x=data&1; data=data>>1; count--;
   if(x)     /*mode 1 - copy*/
     {count=EDL_helper(&data,count,in,&pos,size,endian);
     bits[0]=data&1; bits[1]=(data&2)>>1; bits[2]=(data&4)>>2; bits[3]=(data&8)>>3;
     //if(flagrant.message) {printf("\nmode1\tpos: %X\tout: %X\tdata: %X",pos,ftell_out,data);
     //                      printf("\n\t%X%X%X%X",bits[0],bits[1],bits[2],bits[3]);}
     if(bits[0]) {/*bit1:1*/
           num=2;
           data=data>>2; count-=2;
           if(bits[1]) 
             {data=data>>1; count--;
             num++;
             bits[8]=3;
             if(bits[2])
               {bits[8]=11;
               count=EDL_helper(&data,count,in,&pos,size,endian);
               num=data&0xFF; data=data>>8; count-=8;
               if(num==0) return ftell_out;   /*this implies #bytes=0, signifying EOF*/
               num+=8;
               }/*bits[2]*/
             }/*bits[1]*/
           }/*bits[0]=1*/
     else{
         bits[8]=3;
         num=4;
         data=data>>3; count-=3;     /*minimum shift*/
         if(bits[1]) num++;
         if(bits[2])
           {bits[8]=4;
           data=data>>1; count--;
           num=2*(num-1)+bits[3];
           if(num==9)          /*special case write mode*/
             {count=EDL_helper(&data,count,in,&pos,size,endian);
             num=data&0xF; data=data>>4; count-=4;
             num*=4;
             for(num+=12;num>0;num--)
                {count=EDL_helper(&data,count,in,&pos,size,endian);
                 x=data&0xFF; data=data>>8; count-=8;
                 out[ftell_out++] = x;
                 if(ftell_out>max) return ftell_out;     /*failsafe*/
                }
             continue;
             }/*num==9*/
           }/*bits[2]*/
          }/*bits[0]=0*/

     if(bits[8])        /*handle those backward offset types*/
       {count=EDL_helper(&data,count,in,&pos,size,endian);  /*copy next 6, then work out size*/
       bits[0]=data&1; bits[1]=(data&2)>>1; 
       bits[2]=(data&4)>>2; bits[3]=(data&8)>>3;
       bits[4]=(data&0x10)>>4; bits[5]=(data&0x20)>>5;
       data=data>>1; count--;
       //if(flagrant.message) printf("\t%X\t%X%X%X%X%X%X",bits[8],bits[0],bits[1],bits[2],bits[3],bits[4],bits[5]);
       
       if(bits[0])
         {if(bits[2])
            {if(bits[4])       /*10101 10111 11101 11111*/
               {data=data>>4; count-=4;
               back=0x400;
               if(bits[1]) back+=0x200;
               if(bits[3]) back+=0x100;
               }/*end bits[4]*/
             else              /*101000 101001 101100 101101 111000 111001 111100 111101*/
               {data=data>>5; count-=5;
               back=0x800;
               if(bits[1]) back+=0x400;
               if(bits[3]) back+=0x200;
               if(bits[5]) back+=0x100;
               }/*end bits[4]==0*/
            }/*end bits[2]*/
         else        /*bits[2]==0*/
            {if(bits[1])           /*110*/
               {back=0x100;
               data=data>>2; count-=2;
               }
            else                   /*1000 1001*/
               {data=data>>3; count-=3;
               back=0x200;
               if(bits[3]) back+=0x100;
               }
            }/*end bits[2]==0*/
         }/*end bits[0]*/  
       }/*bits[8]*/
     
     /*get the backward offset*/
     count=EDL_helper(&data,count,in,&pos,size,endian);
     back=(data&0xFF)+back+1;        /*assured to copy at least 1 byte*/
     data=data>>8; count-=8;
     //if(flagrant.message) printf("\n\tnum: %X\tback: %X",num,back);
     /*copy data from source*/
        for(x=0;num>0;num--)
           {x=ftell_out-back;
           if(x<0 || x>=ftell_out) x=0;
           else{//fseek(out,0-back,SEEK_END);     /*backward position*/
               //x=fgetc(out);
                x = out[ftell_out - back];
               }
           //fseek(out,0,SEEK_END);
           out[ftell_out++] = x;
           if(ftell_out>max) return ftell_out;     /*failsafe*/
           }/*end copy run*/
/*        for(x=0;num>0;num-=x)      this is faster but would need a catch
           {x=num;                   to keep it from copying bytes that have
           if(x>8) x=8;              not yet been written
           fseek(out,0-back,SEEK_END);
           fread(bits,1,x,out);
           fseek(out,0,SEEK_END);
           fwrite(bits,1,x,out);
           if(ftell_out>max) return ftell_out;
           }end debug-sometime-later*/    
     }/*if()*/
   else{     /*mode 0 - push one byte to output*/
        count=EDL_helper(&data,count,in,&pos,size,endian);
        //if(flagrant.message) printf("\nmode0\tpos: %X\tout: %X\tdata: %X",pos,ftell_out,data);
        x=data&0xFF; data=data>>8; count-=8;
        out[ftell_out++] = x;
        if(ftell_out>max) return ftell_out;     /*failsafe*/
        }
   }

return ftell_out;}



int dungeon_kid(u8 *ROM, u8 *log) {
    int readbyte, repeatval, reps, output = 0;
    for(;;) {
     readbyte=*ROM++;
     if(readbyte==0xDD)
     {
        //Read repeated bytes.
        repeatval=*ROM++;
        reps=*ROM++;
        while(reps>0)
        {
           log[output] = repeatval;
           output++;
           reps--;
        }
     }
     else if(readbyte==0xCC)
     {
        //Repeat Colored Lines.
        reps=*ROM++;
        readbyte=0xFF;
        while(reps>0)
        {
           log[output] = readbyte;
           output++;
           reps--;
        }
     }
     else if(readbyte==0xBB)
     {
        //Repeat Blank Lines
        reps=*ROM++;
        readbyte=0x00;
        while(reps>0)
        {
           log[output] = readbyte;
           output++;
           reps--;
        }
     }
     else if(readbyte==0xAA)
     {
        //cout<<"????\n";
     }
     else if(readbyte==0x99)
     {
        //Avoid next control code.
        readbyte=*ROM++;
        log[output] = readbyte;
        output++;
     }
     else if(readbyte==0xEE)
     {
        break; //cout<<"End compression.\n";
     }
     else
     {
        log[output] = readbyte;
        output++;
     }
     readbyte=*ROM++;
  }
    return output;
}



// original code by AID_X, Dr. MefistO - http://lab313.ru
int frontmission2(u8 *pFile, int PBsize, u8 *extrbuf) {
    int     i, CC, RR, RepCount, z = 0;
    u16     RRRR;
    u8      *pFilel = pFile + PBsize;
    while(pFile < pFilel) {
        CC = *pFile++;

        if((CC >= 0x00) && (CC <= 0x3f)) {
            RepCount = CC + 1;

            for(i = 1; i <= RepCount; i++) {
              RR = *pFile++;
              extrbuf[z++] = RR;
            }
        } else if((CC >= 0x40) && (CC <= 0x7f)) {
            RepCount = CC - 0x40 + 3;
            RR = *pFile++;
            for(i = 1; i <= RepCount; i++) {
              extrbuf[z++] = RR;
            }
        } else if((CC >= 0x80) && (CC <= 0xbf)) {
            RepCount = CC - 0x80 + 2;
            RR = *pFile++;
            for(i = 1; i <= RepCount; i++) {
              extrbuf[z] = extrbuf[z - RR];
              z++;
            }
        } else if((CC >= 0xc0) && (CC <= 0xff)) {
            RepCount = CC - 0xC0 + 2;
            RRRR = pFile[0] | (pFile[1] << 8);
            pFile += 2;
            for(i = 1; i <= RepCount; i++) {
              extrbuf[z] = extrbuf[z - RRRR];
              z++;
            }
        }
    }
    return z;
}



// coverted to C from:
//  CompressTools (c) 2012 by Bregalad
//  RLEINC is (c) 2012 by Joel Yliluoma, http://iki.fi/bisqwit/

int rleinc1(u8 *encoded, int encoded_size, u8 *result) {
    u8 *bck = result;
        //int end_where = -1;
        int i, b, n;
        for( i=0; i < encoded_size; )
        {
            int c = encoded[i++] & 0xFF;
            if((c & 0x80) != 0) // RUN
            {
                for( b = encoded[i++], n = 0x101-c; n > 0; --n)
                    *result++ = ( (byte)b );
            }
            else
            {
                if((c & 0x40) != 0) // SEQ
                {
                    if(c == 0x40)
                    {
                        //end_where = i;
                        break;
                    }
                    for( b = encoded[i++], n = c-0x3F; n > 0; --n)
                        *result++ = ( (byte)(b++ & 0xFF) );
                }
                else // LIT
                {
                    for( n = c; n >= 0; --n)
                        *result++ = ( encoded[i + n] );
                    i += (c + 1);
                }
            }
        }
    return result - bck;
}



int rleinc2(u8 *encoded, int encoded_size, u8 *result) {
    u8 *bck = result;
    int i,b,n;
        //int end_where = -1;
        for( i=0; i < encoded_size; )
        {
            int c = encoded[i++] & 0xFF;
            if((c & 0x80) != 0)
            {
                if(c >= 0xA0) // RUN
                    for( b = encoded[i++], n = 0x101-c; n > 0; --n)
                        *result++ = ( (byte)b );
                else // DBL
                {
                    byte b1 = encoded[i++];
                    byte b2 = encoded[i++];
                    for( n = c-0x7D; n > 0; --n)
                    {
                        *result++ = (b1);
                        byte tmp=b1;
                        b1=b2;
                        b2=tmp;
                    }
                }
            }
            else
            {
                if((c & 0x40) != 0) // SEQ
                {
                    if(c == 0x40)
                    {
                        //end_where = i;
                        break;
                    }
                    for( b = encoded[i++], n = c-0x3F; n > 0; --n)
                        *result++ = ( (byte)(b++ & 0xFF) );
                }
                else // LIT
                {
                    for( n = c; n >= 0; --n)
                        *result++ = ( encoded[i + n] );
                    i += (c + 1);
                }
            }
        }
    return result - bck;
}



// original code from GMMan Evolution Engine Cache Extractor http://forum.xentax.com/viewtopic.php?f=32&t=10782
int evolution_unpack(unsigned char *compressedData, int compressedData_Length, unsigned char *decompressedData, int decompressedData_Length)
		{
            int i;
			int compPos = 0;
			int decompPos = 0;
			int compLen = compressedData_Length;
			int decompLen = decompressedData_Length;

			while (compPos < compLen)
			{
				unsigned char codeWord = compressedData[compPos++];
				if (codeWord <= 0x1f)
				{
					// Encode literal
					if (decompPos + codeWord + 1 > decompLen) quickbms_unz_output_overflow; //throw new IndexOutOfRangeException("Attempting to index past decompression buffer.");
					if (compPos + codeWord + 1 > compLen) return -1; //throw new IndexOutOfRangeException("Attempting to index past compression buffer.");
					for ( i = codeWord; i >= 0; --i)
					{
						decompressedData[decompPos] = compressedData[compPos];
						++decompPos;
						++compPos;
					}

				}
				else
				{
					// Encode dictionary
					int copyLen = codeWord >> 5; // High 3 bits are copy length
					if (copyLen == 7) // If those three make 7, then there are more bytes to copy (maybe)
					{
						if (compPos >= compLen) return -1; //throw new IndexOutOfRangeException("Attempting to index past compression buffer.");
						copyLen += compressedData[compPos++]; // Grab next byte and add 7 to it
					}
					if (compPos >= compLen) return -1; //throw new IndexOutOfRangeException("Attempting to index past compression buffer.");
					int dictDist = ((codeWord & 0x1f) << 8) | compressedData[compPos]; // 13 bits code lookback offset
					++compPos;
					copyLen += 2; // Add 2 to copy length
					if (decompPos + copyLen > decompLen) quickbms_unz_output_overflow; //throw new IndexOutOfRangeException("Attempting to index past decompression buffer.");
					int decompDistBeginPos = decompPos - 1 - dictDist;
					if (decompDistBeginPos < 0) return -1; //throw new IndexOutOfRangeException("Attempting to index below decompression buffer.");
					for ( i = 0; i < copyLen; ++i, ++decompPos)
					{
						decompressedData[decompPos] = decompressedData[decompDistBeginPos + i];
					}
				}
			}
    return decompPos;
}



int nislzs(u8 *binaryReader, u8 *binaryWriter, int num3) {
    u8  *bck = binaryWriter;

	int num5 = 256;
	byte g_array[num5];
    int i;
	for ( i = 0; i < num5; i++)
	{
		g_array[i] = 255;
	}
	int j = 0;
	int num6 = 0;
	byte b = *binaryReader++;
	if (*binaryReader++ != 0 || *binaryReader++ != 0 || *binaryReader++ != 0)
	{
		return -1; //throw new Exception("padding bytes are not 0");
	}
	while (j < num3)
	{
		byte b2 = *binaryReader++;
		if (b2 == b)
		{
			byte b3 = *binaryReader++;
			if (b3 == b)
			{
				*binaryWriter++ = (b3);
				g_array[num6++] = b3;
				num6 %= num5;
				j++;
			}
			else
			{
				byte b4 = *binaryReader++;
				byte b5 = b4;
				byte b6 = b3;
				if (b6 >= b)
				{
					b6 -= 1;
				}
                int k;
				for ( k = 0; k < (int)b5; k++)
				{
					b2 = g_array[(num6 + num5 - (int)b6) & (num5 - 1)];
					*binaryWriter++ = (b2);
					g_array[num6++] = b2;
					num6 %= num5;
					j++;
				}
			}
		}
		else
		{
			*binaryWriter++ = (b2);
			g_array[num6++] = b2;
			num6 %= num5;
			j++;
		}
	}

    return binaryWriter - bck;
}



int mybase64_encode(u8 *data, int len, u8 *buff, int buffsz) {
    u8      *p,
            a,
            b,
            c;
    static const u8 base[64] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
    };

    if(len < 0) len = strlen(data);
    if((((len / 3) << 2) + 6) > buffsz) return -1;

    p = buff;
    do {
        a     = data[0];
        b     = data[1];
        c     = data[2];
        *p++  = base[(a >> 2) & 63];
        *p++  = base[(((a &  3) << 4) | ((b >> 4) & 15)) & 63];
        *p++  = base[(((b & 15) << 2) | ((c >> 6) &  3)) & 63];
        *p++  = base[c & 63];
        data += 3;
        len  -= 3;
    } while(len > 0);
    *p = 0;

    for(; len < 0; len++) *(p + len) = '=';

    return p - buff;
}



#ifdef WIN32
#else
    void *_malloc(int size) {
        return malloc(size);
    }
    void _free(void *p) {
        return free(p);
    }
#endif
        #if defined(__i386__) || defined(__x86_64__)
        #ifndef __APPLE__
extern int UnSquash(unsigned char *, int);// __asm__("UnSquash");
int amiga_unsquash(unsigned char *in, int insz, unsigned char *out) {
    int     i;
    
    // copy to out setting the correct endianess
    for(i = 0; i <= (insz - 4); i += 4) {
        *(u32 *)(out + i) = ntohl(*(u32 *)(in + i));
    }

    return UnSquash(out, insz);
}
        #endif
        #endif
extern void BYTUNP(int, int, int, int, int, unsigned char *, unsigned char *, int);
extern int UFLSP(unsigned char *out, unsigned char *in, int);
extern void IAMICE(unsigned char *in_out);
extern void IAMATM(unsigned char *in_out);
extern int ISC1P(unsigned char *in, unsigned char *out, int count, int blah);
extern int ISC2P(unsigned char *in, unsigned char *out, int count, int blah);
extern int ISC3P(unsigned char *in, unsigned char *out, int count, int blah, int insz);
extern int UPCOMP(unsigned char *out, unsigned char *in, int insz, int outsz);
extern void UPHD(unsigned char *in, unsigned char *out, unsigned char *work);
extern void DeCr00(unsigned char *in, unsigned char *out, unsigned char *work);
extern void ByteKiller2(unsigned char *in, unsigned char *out, unsigned char *work);
extern int crunchmania_17b(unsigned char *out, int outsz, unsigned char *in, int insz);
extern void pp_DecrunchBuffer(unsigned char *inl, unsigned char *out, int efficiency);
extern void stonecracker2(unsigned char *in, unsigned char *out);
extern void stonecracker3(unsigned char *in, unsigned char *out, unsigned char *work);
extern int stonecracker403(unsigned char *out, unsigned char *in);
extern int UCRMAS(unsigned char *in, unsigned char *out, int outsz);
extern int crunchmania_FastDecruncher(unsigned char *out, int outsz, unsigned char *in, int insz);
extern int crunchmania_FastDecruncherHuff(unsigned char *out, int outsz, unsigned char *in, int insz);
extern int UCMAT(unsigned char *in_out, int outsz, unsigned char *len_addr);
extern int UNDIMP(unsigned char *in_out);
extern int LIGHT15(unsigned char *in, unsigned char *out, int outsz);
extern int UMAST31(unsigned char *out, unsigned char *in);
extern int MAX12(unsigned char *out, unsigned char *in);
extern int UMEGA(unsigned char *inl, int outsz, unsigned char *out);
extern void PACIT(unsigned char *in, unsigned char *inl, unsigned char *out);
extern void USPIKE(unsigned char *in, unsigned char *out, unsigned char *outl);
extern void UTETR(unsigned char *in, unsigned char *inl, unsigned char *out, int outsz);
extern void time_decrunch(unsigned char *in, unsigned char *out);
extern void TRY101(unsigned char *in, unsigned char *out);
extern int UTUC(unsigned char *in, unsigned char *out, int outsz);
extern void UTSQ61(unsigned char *inl, unsigned char *outl, unsigned char *out);
extern void UTSQ80(unsigned char *inl, unsigned char *outl, unsigned char *out);
extern int LhDecode(int insz, unsigned char *in, unsigned char *out, int mark);
extern int DMSUNP(unsigned char *in, unsigned char *out);
extern void packfire(unsigned char *in, unsigned char *out, unsigned char *work_15980);




/*	Alba v0.8 - File compressor.
(C)2014.	xezz
This program is free software.
Algorithm: Byte Pair Encoding.
*/
// http://encode.ru/threads/1874-Alba?p=36612&viewfull=1#post36612

/*****************************************************
	decompress
*******************************************************/
// single mode
int alba_BPD(u8 *If, u32 len, u8 *Of){
 u8 *Ifl = If + len;
 u32 a=0,b,c,d,e,f,i,l,n,p=0,r,s=0,u,v=len/100,w;if(!v)v=len;w=v;
 u8*A=(u8*)malloc(1<<20),B[256],*O=A+(1<<19),*L,*R,X[16][256],Y[16][256],*T;
 for(;;memcpy(Of, A, l), Of += l){
    if(If >= Ifl) break;
    l=*If++;
	l|=*If++<<8;e=0;
	if(u=l>>15)s++,b=*If++,l=l&32767|b/16<<15,u+=(b&15)-1;
 	for(n=++u;n;){	// read header
	 L=X[--n];R=Y[n];
	 f=(b=*If++)>>(c=7);s++;
	 for(i=0;i<256;f^=1){
		for(r=0;!(c?b>>--c&1:(s++,b=*If++)>>(c=7)&1)&&r<9;)r++;d=1<<r-(r>8);
		if(r<9){for(;r>c;c=8)d|=((1<<c)-1&b)<<(r-=c),b=*If++,s++;d|=(1<<r)-1&b>>(c-=r);}
		for(;d--;)B[i++]=f;}
	 for(;i;)if(B[--i])L[i]=*If++,R[i]=*If++,e++;else R[L[i]=i]=0;}
	s+=++l+2*e+2;{memcpy(A, If, l); If += l;}
	if(e)for(;n<u;l=f){	// if e=0, no pair in this block
	 L=X[n],R=Y[n++];
	 for(f=r=i=0;r<l||i;O[f++]=c)
		for(c=i?B[--i]:A[r++];c!=L[c];c=L[c])
		 B[i++]=R[c];
	 T=A,A=O,O=T;}
	if(s>=v)printf("%d %%\r",p++),v+=w;a+=l;}
 //printf("100 %%\nsize: %d to %d\n",len,a);
 free(A);
 return a;
 }

u8*alba_mreduce(u32 m){u8*A;
 for(;A=(u8*)malloc(m-=m>>2),!A&&m>32768;);
 return A;}

// double decode
int alba_BPD2(u8 *If, u32 len, u8 *Of){
 u8 *Ifl = If + len;
 u32 a=0,b=(1<<19)*256+2560,c,d,e,f,g,i,l,n,o,p=0,r,s=0,u,v=len/100,w;if(!v)v=len;w=v;
 u8*A=(u8*)malloc(b*2),B[256],*O,*L,*R,X[16][256],Y[16][256],P[262144],*T,*U=(u8*)malloc(b),*V=U,*W;
 for(;(!A||!V)&&b>2100000;b-=b>>2)
	A=alba_mreduce(b*2),
	V=alba_mreduce(b);
 if(!A||!V)goto end;
 if(b<16777216)puts("Not enough memory, but start decoding...");
 for(O=A+b;;){
    if(If >= Ifl) break;
    l=*If++;
	l|=*If++<<8|*If++<<16;if(l>262143){puts("decoding error");goto end;}
	g=*If++|*If++<<8;
	o=0;{memcpy(P, If, l); If += l;}s+=3+l;
 // 1st decode
bpe1:	e=0;l=*If++|*If++<<8;
	if(u=l>>15)s++,b=*If++,l=l&32767|b/16<<15,u+=(b&15)-1;
 	for(n=++u;n;){
	 L=X[--n];R=Y[n];
	 f=(b=*If++)>>(c=7);s++;
	 for(i=0;i<256;f^=1){
		for(r=0;!(c?b>>--c&1:(s++,b=*If++)>>(c=7)&1)&&r<9;)r++;d=1<<r-(r>8);
		if(r<9){for(;r>c;c=8)d|=((1<<c)-1&b)<<(r-=c),b=*If++,s++;d|=(1<<r)-1&b>>(c-=r);}
		for(;d--;)B[i++]=f;}
	 for(;i;)if(B[--i])L[i]=*If++,R[i]=*If++,e++;else R[L[i]=i]=0;}
	s+=++l+2*e+2;{memcpy(A, If, l); If += l;}
	if(s>=v)printf("%d %%\r",p++),v+=w;
	if(e)for(;n<u;l=f){
	 L=X[n],R=Y[n++];
	 for(f=r=i=0;r<l||i;O[f++]=c)
		for(c=i?B[--i]:A[r++];c!=L[c];c=L[c])
		 B[i++]=R[c];
	 T=A,A=O,O=T;}
	memcpy(U,A,l);U+=l;
	if(g--)goto bpe1;W=U;U=V;
// 2nd decode
bpe2:	e=0;l=*U++;l|=*U++<<8;
	if(u=l>>15)b=*U++,l=l&32767|b/16<<15,u+=(b&15)-1;
	for(n=++u;n;){
	 L=X[--n];R=Y[n];
	 f=(b=*U++)>>(c=7);
	 for(i=0;i<256;f^=1){
		for(r=0;!(c?b>>--c&1:(b=*U++)>>(c=7)&1)&&r<9;)r++;d=1<<r-(r>8);
		if(r<9){for(;r>c;c=8)d|=((1<<c)-1&b)<<(r-=c),b=*U++;d|=(1<<r)-1&b>>(c-=r);}
		for(;d--;)B[i++]=f;}
	 for(;i;)if(B[--i])L[i]=P[o++],R[i]=P[o++],e++;else R[L[i]=i]=0;}
	memcpy(A,U,++l);U+=l;
	if(e)for(;n<u;l=f){
	 L=X[n],R=Y[n++];
	 for(f=r=i=0;r<l||i;O[f++]=c)
		for(c=i?B[--i]:A[r++];c!=L[c];c=L[c])
		 B[i++]=R[c];
	 T=A,A=O,O=T;}
	memcpy(Of, A, l), Of += l;a+=l;
	if(U<W)goto bpe2;U=V;}
 //printf("100 %%\nsize: %d to %d\n",len,a);
 end:if(A)free(A);if(V)free(V);
 return a;
 }
 

 
int bpe2_decompress(unsigned char *srcf, int srcf_size, unsigned char *destf) {
#define bpe2_CHAR_BIT 8
enum {
	bpe2_BLOCK_SIZE = 0x2800,
	bpe2_BUF_BYTES = 2,
	bpe2_MIN_FREQ = 4,
	bpe2_BYTE = (1<<bpe2_CHAR_BIT),
};

    unsigned char   src[bpe2_BLOCK_SIZE],
                    dest[bpe2_BLOCK_SIZE],
                    tmpx[bpe2_BLOCK_SIZE];

		// decompress
		size_t read = 0, written = 0;
		size_t block_num = 0;
		for(; ; block_num++) {
			size_t block_len = 0;
			int eof = 0;
            int i;
			for( i=0; i<bpe2_BUF_BYTES; i++) {
				block_len <<= 8;
                if(read >= srcf_size) {
                    eof = 1;
                    break;
                }
				const int r = srcf[read];
				block_len |= r;
				read++;
			}
			if(eof)
				break;
			if(block_len > bpe2_BLOCK_SIZE) {
				//fprintf(stderr,"illegal block_len %zu\n",block_len);
				return -1;
			}
			const size_t cycles = srcf[read];
			read ++;
#if BPE_DEBUG>=1
			printf("%zu = %zu, %zu\n",block_num,block_len,cycles);
#endif
            int t = srcf_size - read;
            if(block_len > t) block_len = t;
            memcpy(src, srcf + read, block_len);
			read += block_len;
            size_t cycle;
			for( cycle=0; cycle<cycles; cycle++) {
				size_t in = 0;
				const uint8_t hi = src[in++], lo = src[in++], replace = src[in++];
#if BPE_DEBUG>=2
				printf("%3zu %2zu [",block_num,cycle);
				print_char(hi);
				putchar(':');
				print_char(lo);
				printf("] = ");
				print_char(replace);
#endif
				size_t out = 0;
				for(; in < block_len; in++)
					if(src[in]==replace) {
						dest[out++] = hi;
						dest[out++] = lo;
					} else
						dest[out++] = src[in];
#if BPE_DEBUG>=2
				printf(" = %zu saved, %zu left\n",out-block_len,out);
#endif
				block_len = out;
				//std::swap(src,dest);
                memcpy(tmpx, src, bpe2_BLOCK_SIZE);
                memcpy(src, dest, bpe2_BLOCK_SIZE);
                memcpy(dest, tmpx, bpe2_BLOCK_SIZE);
                
			}
            memcpy(destf + written, src, block_len);
			written += block_len;
		}
        return written;
}



// http://blog-imgs-17.fc2.com/m/u/s/musyozoku211/bpe.txt
int bpe_alt1_decode_buf(int bfs, int isize, unsigned char *workbuf, unsigned char *srcbuf, int typ)
{
    int i, ch, c2, pts;

	int wpos = 0, spos = 0;
	unsigned char stackbuf[256], stackhead = 0;  /* ÉfÉRÅ[ÉhópÉXÉ^ÉbÉN */

        unsigned char  pairtable1[256];
        unsigned char  pairtable2[256];
		/* ÉyÉAï\Çèâä˙âª */
		for (i = 0; i < 256; i++) {
			pairtable1[i] = i;
		}
		if (typ) {
			/* ÉyÉAï\ÇÃì«çû */
			if ((pts = workbuf[wpos++]) < 0)  return -1; //error("Input data error 2");
			for (i = 0; i < pts; i++) {
				if ((ch = workbuf[wpos++]) < 0)  return -1; //error("Input data error 2");
				if ((c2 = workbuf[wpos++]) < 0)  return -1; //error("Input data error 2");
				pairtable1[ch] = c2;
				if ((c2 = workbuf[wpos++]) < 0)  return -1; //error("Input data error 2");
				pairtable2[ch] = c2;
			}
		}
	
	while (wpos < isize || stackhead > 0)
	{
		unsigned char ch;
		if (!stackhead) {
			/* ÉXÉ^ÉbÉNÇ™ãÛÇÃéûÅAÉfÅ[É^Ç©ÇÁ1Byteì«çû */
			ch = workbuf[wpos++];
		} else {
			/* ÉXÉ^ÉbÉNÇ©ÇÁ1Byteì«çû */
			ch = stackbuf[--stackhead];
		}

		while (1) {
			/* ÉyÉAï\Ç©ÇÁï∂éöÇìæÇÈ */
			if (ch == pairtable1[ch]) {
				/* ÉfÅ[É^ÇÇªÇÃÇ‹Ç‹1Byteèëçû */
				if (spos >= bfs)  return -1; //error("Buffer overflow");
				srcbuf[spos++] = ch;
				break;
			}
			/* ÉfÅ[É^ÇÉXÉ^ÉbÉNÇ÷ì¸ÇÍÇÈ */
			stackbuf[stackhead++] = pairtable2[ch];
			ch = pairtable1[ch];
		}
	}
	return spos;
}



// http://izaya.blog38.fc2.com/blog-entry-374.html
/**
  @file   CBPE.cpp
  @brief  BPEà≥èké¿ëïÉtÉ@ÉCÉã
  @author IZAYA
  @data   090825 1st Release
*/
unsigned long CBPE__Decode( void *pDest, void *pSrc, unsigned long SrcSize )
{
  unsigned char *SrcAddr = (unsigned char*)pSrc;
  unsigned char *DestAddr = (unsigned char*)pDest;

  int i = 0, c1, c2, c3, c4, size, rpos, DestPos = 0;
  unsigned int SrcPos = 0;
  unsigned char stackBuf[256], stackHead = 0x00, pair1[256], pair2[256];

  while( SrcPos < SrcSize ){
    c1 = SrcAddr[SrcPos++];
    c2 = SrcAddr[SrcPos++];
    c3 = SrcAddr[SrcPos++];
    size = c2 | (c3 << 8);
    rpos = 0;

    if( c1 == 0x00 ){
      while( rpos < size ){
        rpos++;
        DestAddr ? DestAddr[ DestPos++ ] = /*static_cast<unsigned char>*/(c1) : DestPos++;
      }
      continue;
    } // if( c1 == 0x00 )

    for( i = 0; i < 256; i++ ){
      pair1[i] = /*static_cast<unsigned char>*/(i);
      pair2[i] = 0x00;
    } // for( i = 0; i < 256; i++ )

    c1 = SrcAddr[ SrcPos++ ];
    for( i = 0; i < c1; i++ ){
      c2 = SrcAddr[ SrcPos++ ];
      c3 = SrcAddr[ SrcPos++ ];
      c4 = SrcAddr[ SrcPos++ ];
      pair1[c2] = /*static_cast<unsigned char>*/(c3);
      pair2[c2] = /*static_cast<unsigned char>*/(c4);
    } // for( i = 0; i < c1; i++ )

    while( rpos < size || stackHead > 0 ){
      if( !stackHead ){
        c1 = SrcAddr[ SrcPos++ ];
        rpos++;
      }
      else{
        c1 = stackBuf[ --stackHead ];
      }

      for(;;){
        if( pair1[c1] == c1 ){
          DestAddr ? DestAddr[ DestPos++ ] = /*static_cast<unsigned char>*/(c1) : DestPos++;
          break;
        }
        stackBuf[ stackHead++ ] = pair2[c1];
        c1 = pair1[c1];
      } // for(;;)
    } // while( rpos < size || stackHead > 0 )
  } // while( SrcPos < SrcSize )

  return DestPos;
}



int LZOvl_Decompress(u8 *instream, long inLength, u8 *outstream)
{
    //#region Format description
    // Overlay LZ compression is basically just LZ-0x10 compression.
    // however the order if reading is reversed: the compression starts at the end of the file.
    // Assuming we start reading at the end towards the beginning, the format is:
    /*
     * u32 extraSize; // decompressed data size = file length (including header) + this value
     * u8 headerSize;
     * u24 compressedLength; // can be less than file size (w/o header). If so, the rest of the file is uncompressed.
     *                       // may also be the file size
     * u8[headerSize-8] padding; // 0xFF-s
     * 
     * 0x10-like-compressed data follows (without the usual 4-byte header).
     * The only difference is that 2 should be added to the DISP value in compressed blocks
     * to get the proper value.
     * the u32 and u24 are read most significant byte first.
     * if extraSize is 0, there is no headerSize, decompressedLength or padding.
     * the data starts immediately, and is uncompressed.
     * 
     * arm9.bin has 3 extra u32 values at the 'start' (ie: end of the file),
     * which may be ignored. (and are ignored here) These 12 bytes also should not
     * be included in the computation of the output size.
     */
    //#endregion

    //#region First read the last 4 bytes of the stream (the 'extraSize')

    // first go to the end of the stream, since we're reading from back to front
    // read the last 4 bytes, the 'extraSize'
    instream += inLength - 4;

    uint extraSize = QUICK_GETi32(instream, 0);
    instream += 4;

    //#endregion

    // if the extra size is 0, there is no compressed part, and the header ends there.
    if (extraSize == 0)
    {
        //#region just copy the input to the output

        // first go back to the start of the file. the current location is after the 'extraSize',
        // and thus at the end of the file.
        instream -= inLength;
        // no buffering -> slow
        memcpy(outstream, instream, (int)(inLength - 4));

        return inLength - 4;

        //#endregion
    }
    else
    {
        // get the size of the compression header first.
        instream -= 5;
        int headerSize = *instream++;

        // then the compressed data size.
        instream -= 4;
        int compressedSize = instream[0] | (instream[1] << 8) | (instream[2] << 16);
        instream += 3;

        // the compressed size sometimes is the file size.
        if (compressedSize + headerSize >= inLength)
            compressedSize = (int)(inLength - headerSize);

        //#region copy the non-compressed data

        // copy the non-compressed data first.
        int buffer_Length = inLength - headerSize - compressedSize;
        instream -= (inLength - 5);
        memcpy(outstream, instream, buffer_Length);
        instream += buffer_Length;
        outstream += buffer_Length;

        //#endregion

        // buffer the compressed data, such that we don't need to keep
        // moving the input stream position back and forth
        //buffer = new byte[compressedSize];
        //instream.Read(buffer, 0, compressedSize);
        u8 *buffer = instream;

        // we're filling the output from end to start, so we can't directly write the data.
        // buffer it instead (also use this data as buffer instead of a ring-buffer for
        // decompression)
        //byte[] outbuffer = new byte[compressedSize + headerSize + extraSize];
        int outbuffer_Length = compressedSize + headerSize + extraSize;
        u8 *outbuffer = outstream;

        int currentOutSize = 0;
        int decompressedLength = outbuffer_Length;
        int readBytes = 0;
        byte flags = 0, mask = 1;
        while (currentOutSize < decompressedLength)
        {
            // (throws when requested new flags byte is not available)
            //#region Update the mask. If all flag bits have been read, get a new set.
            // the current mask is the mask used in the previous run. So if it masks the
            // last flag bit, get a new flags byte.
            if (mask == 1)
            {
                if (readBytes >= compressedSize)
                    return -1; //throw new NotEnoughDataException(currentOutSize, decompressedLength);
                flags = buffer[buffer_Length - 1 - readBytes]; readBytes++;
                mask = 0x80;
            }
            else
            {
                mask >>= 1;
            }
            //#endregion

            // bit = 1 <=> compressed.
            if ((flags & mask) > 0)
            {
                // (throws when < 2 bytes are available)
                //#region Get length and displacement('disp') values from next 2 bytes
                // there are < 2 bytes available when the end is at most 1 byte away
                if (readBytes + 1 >= inLength)
                {
                    return -1; //throw new NotEnoughDataException(currentOutSize, decompressedLength);
                }
                int byte1 = buffer[compressedSize - 1 - readBytes]; readBytes++;
                int byte2 = buffer[compressedSize - 1 - readBytes]; readBytes++;

                // the number of bytes to copy
                int length = byte1 >> 4;
                length += 3;

                // from where the bytes should be copied (relatively)
                int disp = ((byte1 & 0x0F) << 8) | byte2;
                disp += 3;

                if (disp > currentOutSize)
                {
                    if (currentOutSize < 2)
                        return -1; /*throw new InvalidDataException("Cannot go back more than already written; "
                            + "attempt to go back 0x" + disp.ToString("X") + " when only 0x"
                            + currentOutSize.ToString("X") + " bytes have been written."); */
                    // HACK. this seems to produce valid files, but isn't the most elegant solution.
                    // although this _could_ be the actual way to use a disp of 2 in this format,
                    // as otherwise the minimum would be 3 (and 0 is undefined, and 1 is less useful).
                    disp = 2;
                }
                //#endregion

                int bufIdx = currentOutSize - disp;
                int i;
                for (i = 0; i < length; i++)
                {
                    byte next = outbuffer[outbuffer_Length - 1 - bufIdx];
                    bufIdx++;
                    outbuffer[outbuffer_Length - 1 - currentOutSize] = next;
                    currentOutSize++;
                }
            }
            else
            {
                if (readBytes >= inLength)
                    return -1; //throw new NotEnoughDataException(currentOutSize, decompressedLength);
                byte next = buffer[buffer_Length - 1 - readBytes]; readBytes++;

                outbuffer[outbuffer_Length - 1 - currentOutSize] = next;
                currentOutSize++;
            }
        }

        // write the decompressed data
        //outstream.Write(outbuffer, 0, outbuffer.Length);

        // make sure the input is positioned at the end of the file; the stream is currently
        // at the compression header.
        //instream.Position += headerSize;

        return decompressedLength + (inLength - headerSize - compressedSize);
    }
}



int qcmp_unpack(u8 *in, int insz, u8 *out) {
    struct {
        int backref_len;
        int backref_dist;
    } cached_sections[32];
    int     len,
            curr_cached_section = 0;
    u8      *inl = in + insz,
            *o = out,
            *tmp;

    while(in < inl) {
        int control_byte = *in++;
        int backref_len = control_byte >> 5;
        int backref_dist = control_byte & 31;
        if(backref_len == 0) {
            for(len = 0; len < (backref_dist+1); len++) {
                *o++ = *in++;
            }
        } else {
            if(backref_len == 1) {
                backref_len = cached_sections[backref_dist].backref_len;
                backref_dist = cached_sections[backref_dist].backref_dist;
            } else {
                backref_dist <<= 8;
                backref_dist |= *in++;
                if(backref_len==7) {
                    backref_len = *in++;
                }
                backref_len += 1;
                cached_sections[curr_cached_section].backref_len = backref_len;
                cached_sections[curr_cached_section].backref_dist = backref_dist;
                curr_cached_section += 1;
                curr_cached_section &= 31;
            }
            tmp = o-backref_dist;
            for(len = 0; len < backref_len; len++) {
                *o++ = tmp[len % backref_dist];
            }
        }
    }
    return o - out;
}



// https://raw.githubusercontent.com/ladislav-zezula/StormLib/master/src/sparse/sparse.cpp
int DecompressSparse(u8 *in, int insz, u8 *out, int outsz) {
    u8      *inl = in + insz,
            *o   = out;

    unsigned int cbChunkSize;
    unsigned int OneByte;

    while(in < inl) {
        OneByte = *in++;

        if(OneByte & 0x80)
        {
            cbChunkSize = (OneByte & 0x7F) + 1;
            cbChunkSize = (cbChunkSize < outsz) ? cbChunkSize : outsz;
            memcpy(o, in, cbChunkSize);
            in += cbChunkSize;
        }
        else
        {
            cbChunkSize = (OneByte & 0x7F) + 3;
            cbChunkSize = (cbChunkSize < outsz) ? cbChunkSize : outsz;
            memset(o, 0, cbChunkSize);
        }

        o += cbChunkSize;
        outsz -= cbChunkSize;
    }

    return o - out;
}



int ungrc(u8 *in, int insz, u8 *out) {
    u8  *inl = in + insz;
    u8  *o = out;
    u8  c, back;
    while(in < inl) {
        c = *in++;
        if(c < 0xc0) {
            *o++ = c;
        } else if(c == 0xc0) {
            break;
        } else if(c == 0xc1) {
            *o++ = *in++;
        } else if(c > 0xc1) {
            back = *in++;
            for(c -= 0xc0; c > 0; c--) {
                *o = *(o - back);
                o++;
            }
        }
    }
    return o - out;
}



int lz4f_decompress(u8 *in, int insz, u8 *out, int outsz) {
    LZ4F_decompressionContext_t ctx;
    LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);
    size_t  dstSize = outsz,
            srcSize = insz;
    LZ4F_decompress(ctx, out, &dstSize, in, &srcSize, NULL);
    LZ4F_freeDecompressionContext(ctx);
    return dstSize;
}



int lz5f_decompress(u8 *in, int insz, u8 *out, int outsz) {
    LZ5F_decompressionContext_t ctx;
    LZ5F_createDecompressionContext(&ctx, LZ5F_VERSION);
    size_t  dstSize = outsz,
            srcSize = insz;
    LZ5F_decompress(ctx, out, &dstSize, in, &srcSize, NULL);
    LZ5F_freeDecompressionContext(ctx);
    return dstSize;
}



//http://www.embedded-os.de/en/pclzfg.shtml
int unpclzfg(unsigned char *source, int source_l, unsigned char *Decdata_p) {
    #define LZFG_W          4096        // windowsize
    u8          bf;
    u8          LZFG_Win[LZFG_W];
    int         len, off, t;
    int         ibyte=0, obyte=0;

        for(t=0; t<LZFG_W; t++) {                          // init window
            LZFG_Win[t] = 0;
        }
        t = 0;
        while(ibyte < source_l) {                          // up to end of compressed file
            bf = source[ibyte++];
            if(bf & 0xF0) {
                len = 1 + (int)(bf >> 4);
                off = t - (((int)(bf & 0x0F) << 8) + (int)(source[ibyte++])) - 1;
                while(len--) {
                    off &= (LZFG_W - 1);
                    LZFG_Win[t++]      = LZFG_Win[off];
                    Decdata_p[obyte++] = LZFG_Win[off++];
                    t   &= (LZFG_W - 1);
                }
            } else {
                len = 1 + bf;
                while(len--) {
                    LZFG_Win[t++]      = source[ibyte];
                    Decdata_p[obyte++] = source[ibyte++];
                    t   &= (LZFG_W - 1);
                }
            }
        }

    return obyte;
}



// outsz must be +1 or heatshrink_decoder_poll will return an error... mah
// use <0 instead of !=0 for handling errors, it's easier and better!

int heatshrink_decompress(u8 *in, int insz, u8 *out, int outsz) {
    heatshrink_decoder *hs = NULL;
    size_t  input_size  = 0;
    size_t  output_size = 0;
    int     ret = -1;

    if(!hs) hs = heatshrink_decoder_alloc(insz, HEATSHRINK_MAX_WINDOW_BITS, HEATSHRINK_MAX_WINDOW_BITS);
    if(!hs) hs = heatshrink_decoder_alloc(insz, 11, 4);
    if(!hs) return -1;
    if(heatshrink_decoder_sink(hs, in, insz, &input_size) < 0) goto quit;
    if(heatshrink_decoder_finish(hs) < 0) goto quit;
    if(heatshrink_decoder_poll(hs, out, outsz, &output_size) < 0) goto quit;
    ret = output_size;
quit:
    heatshrink_decoder_free(hs);
    return ret;
}

int heatshrink_compress(u8 *in, int insz, u8 *out, int outsz) {
    heatshrink_encoder *hs = NULL;
    size_t  input_size  = 0;
    size_t  output_size = 0;
    int     ret = -1;

    if(!hs) hs = heatshrink_encoder_alloc(HEATSHRINK_MAX_WINDOW_BITS, HEATSHRINK_MAX_WINDOW_BITS);
    if(!hs) hs = heatshrink_encoder_alloc(11, 4);
    if(!hs) return -1;
    if(heatshrink_encoder_sink(hs, in, insz, &input_size) < 0) goto quit;
    if(heatshrink_encoder_finish(hs) < 0) goto quit;
    if(heatshrink_encoder_poll(hs, out, outsz, &output_size) < 0) goto quit;
    ret = output_size;
quit:
    heatshrink_encoder_free(hs);
    return ret;
}



// by Gerald Tamayo
int rle32_decode (u8 *in, int insz, u8 *out)
{
    u8  *inl = in + insz;
    u8  *o = out;
	int curr, rle_cnt = 0;

	while (in < inl) {
        curr=*in++;
		/* write curr if no runs. */
		if (curr < 128) *o++ = curr;
		else {               /* there's a run! */
			curr -= 128;		/* set off bit 128. */

			/* output the character. */
			*o++ = curr;

			/* output the run of bytes. */
			rle_cnt=*in++;
            for(; rle_cnt > 0; rle_cnt--){
                *o++ = curr;
            }
		}
	}
    return o - out;
}



// by Gerald Tamayo
int rle35_decode (u8 *in, int insz, u8 *out)
{
    u8  *inl = in + insz;
    u8  *o = out;
	int c, prev, rle_cnt;

	/* get first byte and assign it as the *previous* byte. */
	c = *in++;
		prev = c;
		*o++ = c;

	while (in < inl) {
        c=*in++;
		if (c == prev) {
			*o++ = prev;
			/*	output the next "run" of bytes, as
				stored in the rle_cnt variable.
			*/
			rle_cnt = *in++;
            while(rle_cnt--) {
                *o++ = prev;
            }
		}
		else {
			*o++ = c;
			prev = c;
		}
	}
    return o - out;
}



int rle_orcom(u8 *in, int insz, u8 *out) {
    int RLE_OFFSET = 2;
	int cnt = 0;
	int c;
    u8 *inl = in + insz;
    u8 *o = out;
	while (in < inl)
	{
        c = *in++;
		if (c == '.')
		{
			cnt++;
			if(cnt == 255 - RLE_OFFSET)
			{
				*o++ = cnt + RLE_OFFSET;
				cnt = 0;
			}
		}
		else
		{
			int must_be_mis = (cnt > 0) && (cnt < 255 - RLE_OFFSET);
			if (cnt > 0)
			{
				*o++ = cnt + RLE_OFFSET;
				cnt = 0;
			}
			if (!must_be_mis)
				*o++ = 0;
		}	
	}
	if (cnt > 0)
		*o++ = cnt + RLE_OFFSET;

    return o - out;
}



int jch_decompress(u8 *in, int insz, u8 *out, int outsz) {
    u8  *o = out;
    int i;

    u8 compressByte = 0;
    //if(has_header) {
				compressByte = *in++;
				if(*(u32 *)in != insz) in += 4;
    //}

			while ((o - out) < outsz)
			{
				u8 b = *in++;
				if (b == compressByte)
				{
					u8 distance = *in++;
					if (distance == compressByte)
					{
						*o++ = (distance);
					}
					else
					{
						if (distance == 0)
						{
							distance = compressByte;
						}
						u8 blockSize = *in++;
						u8 numBlocks = *in++;
                        for(i = 0; i < numBlocks; i++) {
                            memmove(o, o - distance, blockSize);
                        }
					}
				}
				else
				{
					*o++ = (b);
				}
			}

    return o - out;
}



/*
	{ "-lz4-", &lha_null_decoder },
	{ "-lz5-", &lha_lz5_decoder },
	{ "-lzs-", &lha_lzs_decoder },
	{ "-lh0-", &lha_null_decoder },
	{ "-lh1-", &lha_lh1_decoder },
	{ "-lh4-", &lha_lh4_decoder },
	{ "-lh5-", &lha_lh5_decoder },
	{ "-lh6-", &lha_lh6_decoder },
	{ "-lh7-", &lha_lh7_decoder },
	{ "-lhx-", &lha_lhx_decoder },
	{ "-pm0-", &lha_null_decoder },
	{ "-pm1-", &lha_pm1_decoder },
	{ "-pm2-", &lha_pm2_decoder },
*/

int lha_decoder(u8 *in, int insz, u8 *out, int outsz, u8 *type) {
    u8      *inl = in + insz;
    u8      *o = out,
            *ol = out + outsz;

    size_t myLHADecoderCallback(void *buf, size_t buf_len, void *user_data) {
        if(buf_len > (inl - in)) buf_len = (inl - in);
        memcpy(buf, in, buf_len);
        in += buf_len;
        return buf_len;
    }

    LHADecoder *ctx;
    LHADecoderType  *lha_type;

    if(!type) type = "-lh1-";
    lha_type = lha_decoder_for_name(type);
    if(!lha_type) return -1;

    ctx = lha_decoder_new(lha_type, myLHADecoderCallback, NULL, outsz);
    if(!ctx) return -2;

    int     len;
    for(;;) {
        len = lha_decoder_read(ctx, o, ol - o);
        if(!len) break;
        o += len;
    }

    lha_decoder_free(ctx);

    return o - out;
}



int mypithy_Compress(u8 *in, int insz, u8 *out, int outsz) {
    return pithy_Compress  (in, insz, out, outsz, 9);
}
int mypithy_Decompress(u8 *in, int insz, u8 *out, int outsz) {
    size_t  ret;
    if(!pithy_GetDecompressedLength(in, insz, &ret)) return -1;
    if(ret > outsz) return -2;
    if(!pithy_Decompress(in, insz, out, outsz)) return -3;
    return ret;
}



int LZHUFXR_compress(u8 *in, int insz, u8 *out, int outsz) {
            u8 *p = NULL;
            int t32 = outsz;
            _compressLZ(&p, &t32, in, insz);
            if(p) {
                outsz = t32;
                //myalloc(&out, outsz, outsize);
                memcpy(out, p, outsz);
                free(p);
                return outsz;
            }
    return -1;
}
int LZHUFXR_decompress(u8 *in, int insz, u8 *out, int outsz) {
            u8 *p = NULL;
            int t32 = outsz;
            _decompressLZ(&p, &t32, in, insz);
            if(p) {
                outsz = t32;
                //myalloc(&out, outsz, outsize);
                memcpy(out, p, outsz);
                free(p);
                return outsz;
            }
    return -1;
}



u8 *myzopfli(u8 *in, int insz, int *ret_outsz, int type) {
    size_t  outsz   = 0;
    u8      *out    = NULL;

    // the zopli options are a pain because the results (ratio and time) depends by the input file
    // the following are just the best I found on multiple tests
    ZopfliOptions   opt;
    memset(&opt, 0, sizeof(opt));
    ZopfliInitOptions(&opt);
         if(insz < (10 * 1024 * 1024))  opt.numiterations = 15; // this is
    else if(insz < (50 * 1024 * 1024))  opt.numiterations = 10; // just for
    else                                opt.numiterations = 5;  // speed
    opt.blocksplitting      = 1;
    opt.blocksplittinglast  = 0;
    opt.blocksplittingmax   = 0;
    ZopfliCompress(&opt, type, in, insz, &out, &outsz);

    if(ret_outsz) *ret_outsz = outsz;
    return out;
}



int UFG__qDecompressLZ(void *input, int input_length, void *output, int output_length, const char *data_source)
{
  void *v5; // r14@1
  void *v6; // rsi@1
  //__int128 v7; // ST30_16@1
  //int v8; // eax@1
  //__int128 v9; // ST40_16@1
  //__int128 v10; // xmm0@1
  int result; // rax@3
  u32 *v12; // rdi@4
  signed int v13; // rcx@4
  int v14; // ebp@4
  void *v15; // rdi@7
  char *v16; // rbx@7
  unsigned int v17; // r9@7
  unsigned char v18; // al@8
  int j; // ecx@9
  unsigned char v20; // r8@12
  unsigned int v21; // edx@12
  unsigned int v22; // ecx@13
  int v23; // er8@13
  int v24; // edx@13
  int v25; // eax@14
  int v26; // eax@16
  char *i; // rcx@17
  int v28[32]; // [sp+60h] [bp-98h]@4
  int v29; // [sp+E0h] [bp-18h]@7

  v5 = output;
  v6 = input;
/*
  v7 = *((_OWORD *)input + 1);
  v8 = _mm_cvtsi128_si32(*(__m128i *)input);
  v9 = *((_OWORD *)input + 2);
  v10 = *((_OWORD *)input + 3);
  if ( v8 == 1347240785 || v8 == 1363365200 )
  {
    UFG::qCompressHeader::EndianSwap((UFG::qCompressHeader *)input);
*/
    v12 = v28;
    v13 = 32;
    v14 = 0;
    while ( v13 )
    {
      *v12 = 0;
      ++v12;
      --v13;
    }
    v29 = 0;
    v15 = v5;
    //UFG::qCompressHeader::EndianSwap((UFG::qCompressHeader *)v6);
    v16 = (char *)v6 + ntohl(*((u32 *)v6 + 2));
    //UFG::qCompressHeader::EndianSwap((UFG::qCompressHeader *)v6);
    v17 = (unsigned int)&v16[*((u64 *)v6 + 2) - *((u32 *)v6 + 2)];
    while ( (unsigned int)v16 < v17 )
    {
      v18 = *v16++;
      if ( v18 >= 0x20u )
      {
        v20 = v18;
        v21 = (unsigned int)v18 >> 5;
        if ( v21 == 1 )
        {
          v22 = v28[(unsigned int)(v18 & 0x1F)];
          v23 = (unsigned short)v22;
          v24 = v22 >> 16;
        }
        else
        {
          v25 = (unsigned char)*v16++;
          v23 = v25 | ((v20 & 0x1F) << 8);
          if ( v21 == 7 )
            v21 = (unsigned char)*v16++;
          v24 = v21 + 1;
          v28[v14] = (unsigned short)v23 | (v24 << 16);
          v26 = v29 + 1;
          v14 = v26 & ~((v26 != 32) - 1);
          v29 = v26 & ~((v26 != 32) - 1);
        }
        for ( i = (char *)v15 - v23; v24 > 0; ++i )
        {
          --v24;
          v15 = (char *)v15 + 1;
          *((char *)v15 - 1) = *i;
        }
      }
      else
      {
        for ( j = v18 + 1; j > 0; ++v16 )
        {
          --j;
          v15 = (char *)v15 + 1;
          *((char *)v15 - 1) = *v16;
        }
      }
    }
    result = (u8 *)v15 - (u8 *)v5;
/*
  }
  else
  {
    result = -1;
  }
*/
  return result;
}



int uclpack(unsigned char *in, int insz, unsigned char *out, int outsz) {
    u8      *o   = out,
            *inl = in + insz;

    if(insz < 22) return -1;
    if(memcmp(in, "\x00\xe9\x55\x43\x4c\xff\x01\x1a", 8)) return -2;
    in += 8;
    u32 flags       = QUICK_GETb32(in,0);   in += 4;
    u8  method      = *in++;
    u8  level       = *in++;
    u32 block_size  = QUICK_GETb32(in,0);   in += 4;

    while((in + 4) <= inl) {
        u32 size    = QUICK_GETb32(in,0);   in += 4;
        if(!size) break;
        if((in + 4) > inl) return -3;
        u32 zsize   = QUICK_GETb32(in,0);   in += 4;
        if(size < 0) return -4;
        if(zsize < 0) return -5;
        if(zsize < size) {
            if((o + size) > (out + outsz)) return -6;
            switch(method) {
                case 0x2b: size = ucl_decompress(in, zsize, o, size, COMP_NRV2b);   break;
                case 0x2d: size = ucl_decompress(in, zsize, o, size, COMP_NRV2d);   break;
                case 0x2e: size = ucl_decompress(in, zsize, o, size, COMP_NRV2e);   break;
                default:   size = -1; break;
            }
            if(size < 0) return -7;
            o += size;
        } else {
            if((o + zsize) > (out + outsz)) return -8;
            memcpy(o, in, zsize);
            o += zsize;
        }
        in += zsize;
    }

    return o - out;
}



int lbalzss(unsigned char *in, int insz, unsigned char *out, int outsz, int add, int use_neg_slide) {
    unsigned char   *inl = in + insz;
    unsigned char   *o = out;
    unsigned char   *outl = out + outsz;

    int     i,
            length,
            slide;
    u16     c;
    u8      cnt,
            flag,
            *s;

    while((in < inl) && (o < outl)) {
        flag = *in++;
        for(cnt = 0; cnt < 8; cnt++) {
            if(flag & 1) {
                if(in >= inl) goto quit;
                if(o >= outl) goto quit;
                *o++ = *in++;
            } else {
                if((in + 2) > inl) goto quit;
                c = in[0] | (in[1] << 8);
                in += 2;
                length = (c & 0xf) + add;
                slide = (c ^ -1) >> 4;
                s = o + slide;
                if(use_neg_slide && (slide == -1)) {
                    c = *s;
                    if((o - out) & 1) length++;
                    for(i = 0; i <= length; i++) {
                        if(o >= outl) goto quit;
                        *o++ = c;
                    }
                } else {
                    for(i = 0; i <= length; i++) {
                        if(o >= outl) goto quit;
                        *o++ = *s++;
                    }
                }
            }
            flag >>= 1;
        }
    }
quit:
    return o - out;
}



// SimPE http://sourceforge.net/p/simpe/code/HEAD/tree/
int maxis_dbpf_uncompress(unsigned char *data, int data_Length, unsigned char *uncdata, int uncdata_Length) {
    int index = 0;
    int uncindex = 0;
    int plaincount = 0;
    int copycount = 0;
    int copyoffset = 0;
    unsigned char cc = 0;
    unsigned char cc1 = 0;
    unsigned char cc2 = 0;
    unsigned char cc3 = 0;
    int source;
    int i;

    while ((index < data_Length) && (data[index] < 0xfc))
    {
        cc = data[index++];

        if ((cc & 0x80) == 0)
        {
            cc1 = data[index++];
            plaincount = (cc & 0x03);
            copycount = ((cc & 0x1C) >> 2) + 3;
            copyoffset = ((cc & 0x60) << 3) + cc1 + 1;
        }
        else if ((cc & 0x40) == 0)
        {
            cc1 = data[index++];
            cc2 = data[index++];
            plaincount = (cc1 & 0xC0) >> 6;
            copycount = (cc & 0x3F) + 4;
            copyoffset = ((cc1 & 0x3F) << 8) + cc2 + 1;
        }
        else if ((cc & 0x20) == 0)
        {
            cc1 = data[index++];
            cc2 = data[index++];
            cc3 = data[index++];
            plaincount = (cc & 0x03);
            copycount = ((cc & 0x0C) << 6) + cc3 + 5;
            copyoffset = ((cc & 0x10) << 12) + (cc1 << 8) + cc2 + 1;
        }
        else
        {
            plaincount = (cc - 0xDF) << 2;
            copycount = 0;
            copyoffset = 0;
        }

        for ( i = 0; i < plaincount; i++) uncdata[uncindex++] = data[index++];

        source = uncindex - copyoffset;
        for ( i = 0; i < copycount; i++) uncdata[uncindex++] = uncdata[source++];
    }//while


    if (index < data_Length)
    {
        plaincount = (data[index++] & 0x03);
        for ( i = 0; i < plaincount; i++)
        {
            if (uncindex >= uncdata_Length) break;
            uncdata[uncindex++] = data[index++];
        }
    }
    return uncindex;
}



int CAL_CarmackExpand (unsigned char *source, unsigned char *dest, int length)
{
static const unsigned char NEARTAG =	0xa7;
static const unsigned char FARTAG =	0xa8;

	unsigned short	ch,chhigh,count,offset;
	unsigned short	far *copyptr, far *inptr, far *outptr;

	length/=2;

	inptr = (unsigned short *)source;
	outptr = (unsigned short *)dest;

	while (length)
	{
		ch = *inptr++;
		chhigh = ch>>8;
		if (chhigh == NEARTAG)
		{
			count = ch&0xff;
			if (!count)
			{				// have to insert a word containing the tag byte
				ch |= *(unsigned char *)(inptr); inptr = (unsigned short *)(((unsigned char *)inptr) + 1); //*((unsigned char far *)inptr)++;
				*outptr++ = ch;
				length--;
			}
			else
			{
				offset = *(unsigned char *)(inptr); inptr = (unsigned short *)(((unsigned char *)inptr) + 1); //*((unsigned char far *)inptr)++;
				copyptr = outptr - offset;
				length -= count;
				while (count--)
					*outptr++ = *copyptr++;
			}
		}
		else if (chhigh == FARTAG)
		{
			count = ch&0xff;
			if (!count)
			{				// have to insert a word containing the tag byte
				ch |= *(unsigned char *)(inptr); inptr = (unsigned short *)(((unsigned char *)inptr) + 1); //*((unsigned char far *)inptr)++;
				*outptr++ = ch;
				length --;
			}
			else
			{
				offset = *inptr++;
				copyptr = (unsigned short *)(dest + offset);
				length -= count;
				while (count--)
					*outptr++ = *copyptr++;
			}
		}
		else
		{
			*outptr++ = ch;
			length --;
		}
	}
    return (unsigned char *)outptr - dest;
}



/*
 * UNEXEPACK -- An upacker for EXE files packed with "Microsoft EXEPACK".
 *
 * To the extent possible under law, Vitaly Driedfruit has waived all copyright
 * and related or neighboring rights to UNEXEPACK.
 *
 * See http://creativecommons.org/publicdomain/zero/1.0/
 *
 * Unpacking algorithm fetched from 
 * http://cvs.z88dk.org/cgi-bin/viewvc.cgi/xu4/doc/avatarExepacked.txt?revision=1.1&root=zxu4&view=markup
 * by $Id: avatarExepacked.txt,v 1.1 2009/05/04 18:08:58 aowen Exp $ 
 *
 */
int exepack_unpack(unsigned char *dstPos, unsigned char *srcPos/*, int *res*/) {
  int i, n = 0;
  unsigned char *lastPos = srcPos;

  int commandByte, lengthWord, fillByte;

  /* skip all 0xff bytes (they're just padding to make the packed exe's size a multiple of 16 */
  while (*srcPos == 0xff) {
    srcPos--;
  }
  /* unpack */
  do {
    commandByte = *(srcPos--);
    switch (commandByte & 0xFE) {
      /* (byte)value (word)length (byte)0xb0 */
      /* writes a run of <length> bytes with a value of <value> */
      case 0xb0:
        lengthWord = (*(srcPos--))*0x100;
        lengthWord += *(srcPos--);
        fillByte = *(srcPos--);
        for (i = 0; i < lengthWord; i++) {
          *(dstPos--) = fillByte;
        }
        n += lengthWord;
        break;
      /* (word)length (byte)0xb2 */
      /* copies the next <length> bytes */
      case 0xb2:
        lengthWord = (*(srcPos--))*0x100;
        lengthWord += *(srcPos--);
        for (i = 0; i < lengthWord; i++) {
          *(dstPos--) = *(srcPos--);
        }
        n += lengthWord;
        break;
      /* unknown command */
      default:
        fprintf(stderr, "Unknown command %2x at position %d\n", commandByte, lastPos - srcPos);
        n = -1;
        break;
    }
  } while ((commandByte & 1) != 1); /* lowest bit set => last block */
  //*res = lastPos - srcPos;
  return n;
}



// http://www.metroid2002.com/retromodding/wiki/LZSS_Compression
int tropical_freeze_DecompressLZSS(u8 *src, u32 src_len, u8 *dst, u32 dst_len)
{
    u32 b, byte;
    u8 *dst_backup = dst;
    u8 *src_end = src + src_len;
    u8 *dst_end = dst + dst_len;

    // Read compressed buffer header
    u8 mode = *src++;
    src += 3; // Skipping unused bytes

    // Check for invalid mode set:
    if (mode > 3) return -1; //false;

    // If mode is 0, then we have uncompressed data.
    if (mode == 0) {
        memcpy(dst, src, dst_len);
        return dst_len; //true;
    }

    // Otherwise, start preparing for decompression.
    u8 header_byte = 0;
    u8 group = 0;

    while ((src < src_end) && (dst < dst_end))
    {
        // group will start at 8 and decrease by 1 with each data chunk read.
        // When group reaches 0, we read a new header byte and reset it to 8.
        if (!group)
        {
            header_byte = *src++;
            group = 8;
        }

        // header_byte will be shifted left one bit for every data group read, so 0x80 always corresponds to the current data group.
        // If 0x80 is set, then we read back from the decompressed buffer.
        if (header_byte & 0x80)
        {
            u8 bytes[2] = { *src++, *src++ };
            u32 count, length;

            // The exact way to calculate count and length varies depending on which mode is set:
            switch (mode) {
            case 1:
                count = (bytes[0] >> 4) + 3;
                length = ((bytes[0] & 0xF) << 0x8) | bytes[1];
                break;
            case 2:
                count = (bytes[0] >> 4) + 2;
                length = (((bytes[0] & 0xF) << 0x8) | bytes[1]) << 1;
                break;
            case 3:
                count = (bytes[0] >> 4) + 1;
                length = (((bytes[0] & 0xF) << 0x8) | bytes[1]) << 2;
                break;
            }

            // With the count and length calculated, we'll set a pointer to where we want to read back data from:
            u8 *seek = dst - length;

            // count refers to how many byte groups to read back; the size of one byte group varies depending on mode
            for (byte = 0; byte < count; byte++)
            {
                switch (mode) {
                case 1:
                    *dst++ = *seek++;
                    break;
                case 2:
                    for (b = 0; b < 2; b++)
                        *dst++ = *seek++;
                    break;
                case 3:
                    for (b = 0; b < 4; b++)
                        *dst++ = *seek++;
                    break;
                }
            }
        }

        // If 0x80 is not set, then we read one byte group directly from the compressed buffer.
        else
        {
            switch (mode) {
            case 1:
                *dst++ = *src++;
                break;
            case 2:
                for (b = 0; b < 2; b++)
                    *dst++ = *src++;
                break;
            case 3:
                for (b = 0; b < 4; b++)
                    *dst++ = *src++;
                break;
            }
        }

        header_byte <<= 1;
        group--;
    }

    // We've finished decompressing; the last thing to do is check that we've reached the end of both buffers, to verify everything has decompressed correctly.
    //return ((src == src_end) && (dst == dst_end));
    return dst - dst_backup;
}



#include "libs/synlz/synlz_dll.c"
static int __stdcall (*SynLZcompressdestlen)(int in_len) = NULL;
static int __stdcall (*SynLZdecompressdestlen)(unsigned char *in_p) = NULL;
static int __stdcall (*SynLZcompress1pas)(unsigned char *src, int size, unsigned char *dst) = NULL;
static int __stdcall (*SynLZdecompress1b)(unsigned char *src, int size, unsigned char *dst) = NULL;
static int __stdcall (*SynLZdecompress1pas)(unsigned char *src, int size, unsigned char *dst) = NULL;
static int __stdcall (*SynLZdecompress1partial)(unsigned char *src, int size, unsigned char *dst, int maxDst) = NULL;
static int __stdcall (*SynLZcompress2)(unsigned char *src, int size, unsigned char *dst) = NULL;
static int __stdcall (*SynLZdecompress2)(unsigned char *src, int size, unsigned char *dst) = NULL;
void SynLZ_Init(void) {
    #ifdef WIN32
    static void *hlib = NULL;
    if(!hlib) {
        hlib = (void *)MemoryLoadLibrary((void *)synlz_dll, sizeof(synlz_dll));
        if(!hlib) return;
        SynLZcompressdestlen = (void *)MemoryGetProcAddress(hlib, "SynLZcompressdestlen");
        SynLZdecompressdestlen = (void *)MemoryGetProcAddress(hlib, "SynLZdecompressdestlen");
        SynLZcompress1pas = (void *)MemoryGetProcAddress(hlib, "SynLZcompress1pas");
        SynLZdecompress1b = (void *)MemoryGetProcAddress(hlib, "SynLZdecompress1b");
        SynLZdecompress1pas = (void *)MemoryGetProcAddress(hlib, "SynLZdecompress1pas");
        SynLZdecompress1partial = (void *)MemoryGetProcAddress(hlib, "SynLZdecompress1partial");
        SynLZcompress2 = (void *)MemoryGetProcAddress(hlib, "SynLZcompress2");
        SynLZdecompress2 = (void *)MemoryGetProcAddress(hlib, "SynLZdecompress2");
    }
    #endif
}



// derived from DarkSeed game
int dslzss(unsigned char *in, int insz, unsigned char *out, int outsz) {
    unsigned short  flags   = 0,
                    ebp2    = 0,
                    c;
    int             eax     = 0;
    unsigned char   *inl    = in + insz,
                    *o      = out,
                    *outl   = out + outsz,
                    *p;

    while((in < inl) && (o < outl)) {
        if(!(flags & 0xff00)) {
            flags = 0xff00 | *in++;
        }
        c = in[0] | (in[1] << 8);
        in += 2;
        if(flags & 1) {
            *o++ = c;
            *o++ = c >> 8;
        } else {
            p = o - ((c >> 4) + 1);
            if(p < out) p = out;
            c = (c & 0xf) + 3;
            while(c--) *o++ = *p++;
        }
        flags >>= 1;
    }
    return o - out;
}



// made by zombie28
// http://encode.ru/threads/2417-Creating-A-Compressor-for-JDLZ?p=46247&viewfull=1#post46247
int jdlz_compress(byte *input, int input_Length, byte *output)
{
    //const int HeaderSize = 16;
    const int MinMatchLength = 3;
    const int MaxSearchDepth = 16;

    int inputBytes = input_Length;
    //byte[] output = new byte[inputBytes + ((inputBytes + 7) / 8 ) + HeaderSize + 1];
    int hashPos[0x2000];
    memset(hashPos, 0, sizeof(hashPos));
    int hashChain[inputBytes];
    memset(hashChain, 0, sizeof(hashChain));

    int outPos = 0;
    int inPos = 0;
    byte flags1bit = 1;
    byte flags2bit = 1;
    byte flags1 = 0;
    byte flags2 = 0;

    output[outPos++] = 0x4A; // 'J'
    output[outPos++] = 0x44; // 'D'
    output[outPos++] = 0x4C; // 'L'
    output[outPos++] = 0x5A; // 'Z'
    output[outPos++] = 0x02;
    output[outPos++] = 0x10;
    output[outPos++] = 0x00;
    output[outPos++] = 0x00;
    output[outPos++] = (byte)inputBytes;
    output[outPos++] = (byte)(inputBytes >> 8 );
    output[outPos++] = (byte)(inputBytes >> 16);
    output[outPos++] = (byte)(inputBytes >> 24);
    outPos += 4;

    int flags1Pos = outPos++;
    int flags2Pos = outPos++;

    flags1bit <<= 1;
    output[outPos++] = input[inPos++];
    inputBytes--;

    while (inputBytes > 0)
    {
        int bestMachLength = MinMatchLength - 1;
        int bestMatchDist = 0;

        if (inputBytes >= MinMatchLength)
        {
            int hash = (-0x1A1 * (input[inPos] ^ ((input[inPos + 1] ^ (input[inPos + 2] << 4)) << 4))) & 0x1FFF;
            int matchPos = hashPos[hash];
            hashPos[hash] = inPos;
            hashChain[inPos] = matchPos;
            int prevMatchPos = inPos;

            int i;
            for (i = 0; i < MaxSearchDepth; i++)
            {
                int matchDist = inPos - matchPos;
                if (matchDist > 2064 || matchPos >= prevMatchPos) break;

                int matchLengthLimit = matchDist <= 16 ? 4098 : 34;
                int maxMatchLength = inputBytes;
                if (maxMatchLength > matchLengthLimit) maxMatchLength = matchLengthLimit;
                if (bestMachLength >= maxMatchLength) break;

                int matchLength = 0;
                while (matchLength < maxMatchLength && input[inPos + matchLength] == input[matchPos + matchLength])
                    matchLength++;

                if (matchLength > bestMachLength)
                {
                    bestMachLength = matchLength;
                    bestMatchDist = matchDist;
                }

                prevMatchPos = matchPos;
                matchPos = hashChain[matchPos];
            }
        }

        if (bestMachLength >= MinMatchLength)
        {
            flags1 |= flags1bit;
            inPos += bestMachLength;
            inputBytes -= bestMachLength;
            bestMachLength -= MinMatchLength;

            if (bestMatchDist < 17)
            {
                flags2 |= flags2bit;
                output[outPos++] = (byte)((bestMatchDist - 1) | ((bestMachLength >> 4) & 0xf0));
                output[outPos++] = (byte)bestMachLength;
            }
            else
            {
                bestMatchDist -= 17;
                output[outPos++] = (byte)(bestMachLength | ((bestMatchDist >> 3) & 0xe0));
                output[outPos++] = (byte)bestMatchDist;
            }

            flags2bit <<= 1;
        }
        else
        {
            output[outPos++] = input[inPos++];
            inputBytes--;
        }

        flags1bit <<= 1;

        if (flags1bit == 0)
        {
            output[flags1Pos] = flags1;
            flags1 = 0;
            flags1Pos = outPos++;
            flags1bit = 1;
        }

        if (flags2bit == 0)
        {
            output[flags2Pos] = flags2;
            flags2 = 0;
            flags2Pos = outPos++;
            flags2bit = 1;
        }
    }

    if (flags2bit > 1)
        output[flags2Pos] = flags2;
    else if (flags2Pos == outPos - 1)
        outPos = flags2Pos;

    if (flags1bit > 1)
        output[flags1Pos] = flags1;
    else if (flags1Pos == outPos - 1)
        outPos = flags1Pos;

    output[12] = (byte)outPos;
    output[13] = (byte)(outPos >> 8 );
    output[14] = (byte)(outPos >> 16);
    output[15] = (byte)(outPos >> 24);

    //Array.Resize(ref output, outPos);
    //return output;
    return outPos;
}



// http://aluigi.org/bms/segs.bms
int segs_decompress(unsigned char *in, int insz, unsigned char **ret_out, int *ret_outsz) {
    unsigned char   *inl = in + insz;
    int     i, len;

    u8  *xOFFSET    = NULL;
    u8  *BASE_OFF   = in;
    if(memcmp(in, "segs", 4)) return -1;
    in += 4;
    int FLAGS       = QUICK_GETb16(in,0); in += 2;
    int CHUNKS      = QUICK_GETb16(in,0); in += 2;
    int FULL_SIZE   = QUICK_GETb32(in,0); in += 4;
    int FULL_ZSIZE  = QUICK_GETb32(in,0); in += 4;
    u8  *BASE2_OFF  = in + (CHUNKS * (2 + 2 + 4));
    int WORKAROUND  = 0;

    int outsz = FULL_SIZE;
    len = CHUNKS * 0x00010000;
    if(outsz < len) outsz = len;
    if(outsz < 0) return -1;
    myalloc(ret_out, outsz, ret_outsz);
    unsigned char   *o = *ret_out;

    for(i = 0; i < CHUNKS; i++) {
        if(in >= inl) return -1;
        int ZSIZE   = QUICK_GETb16(in,0); in += 2;
        int SIZE    = QUICK_GETb16(in,0); in += 2;
        int OFFSET  = QUICK_GETb32(in,0); in += 4;
        OFFSET -= 1;
        if((i == 0) && (OFFSET == 0)) {
            WORKAROUND = 1;
        }
        if(WORKAROUND != 0) {
            xOFFSET = OFFSET + BASE2_OFF;
        } else {
            xOFFSET = OFFSET + BASE_OFF;
        }
        if((xOFFSET < in) || ((xOFFSET + ZSIZE) > inl)) return -1;
        if(SIZE == 0) {
            SIZE = 0x00010000;
        }
        if((o + SIZE) > (*ret_out + outsz)) return -1;
        len = unzip_deflate(xOFFSET, ZSIZE, o, SIZE, 0);
        if(len < 0) return -1;
        o += len;
    }
    return o - *ret_out;
}



// bms code by TheUkrainianBard
// http://zenhax.com/viewtopic.php?p=14313#p14313
int ps_lz77_decompress(unsigned char *inf, unsigned char *in, int insz, unsigned char **ret_out, int *ret_outsz) {
    unsigned char   *infl = in + insz;
    int     outsz = *ret_outsz;

    if(!memcmp(in, "LZ77", 4)) {
        in += 4;
        int new_outsz       = (g_endian == MYLITTLE_ENDIAN) ? QUICK_GETi32(in,0) : QUICK_GETb32(in,0);  in += 4;
        int LZ77STEPCOUNT   = (g_endian == MYLITTLE_ENDIAN) ? QUICK_GETi32(in,0) : QUICK_GETb32(in,0);  in += 4;
        int new_off         = (g_endian == MYLITTLE_ENDIAN) ? QUICK_GETi32(in,0) : QUICK_GETb32(in,0);  in += 4;
        if(new_outsz < 0) return -1;
        if(LZ77STEPCOUNT < 0) return -1;
        if(new_off < 0) return -1;
        inf = in;
        in = (in - 16) + new_off;
        infl = in;
        outsz = new_outsz;
        myalloc(ret_out, outsz, ret_outsz);
    }

    unsigned char   *inl  = in + insz,
                    *outl = *ret_out + outsz,
                    *o    = *ret_out;

    int FlagBufferBitCount = 0;
    int FLAGS = 0;
    for(;;) {
        if(!FlagBufferBitCount) {
            if(inf >= infl) break;
            if(inf == in) in++;
            FLAGS = *inf++;
            FlagBufferBitCount = 8;
        }
        if(FLAGS & 0x80) {
            if((in + 2) > inl) break;
            int BACKSTEP = *in++;
            int COPYAMOUNT = *in++;
            for(COPYAMOUNT += 3; COPYAMOUNT--; o++) {
                if(o >= outl) break;
                *o = o[-BACKSTEP];
            }
        } else {
            if(o >= outl) break;
            *o++ = *in++;
        }
        FLAGS <<= 1;
        FlagBufferBitCount -= 1;
    }
    return o - *ret_out;
}



// https://raw.githubusercontent.com/zfsonlinux/zfs/master/module/zfs/zle.c
int
zle_decompress(void *s_start, void *d_start, size_t s_len, size_t d_len, int n)
{
	unsigned char *src = s_start;
	unsigned char *dst = d_start;
	unsigned char *s_end = src + s_len;
	unsigned char *d_end = dst + d_len;

	while (src < s_end && dst < d_end) {
		int len = 1 + *src++;
		if (len <= n) {
			while (len-- != 0)
				*dst++ = *src++;
		} else {
			len -= n;
			while (len-- != 0)
				*dst++ = 0;
		}
	}
    return (void *)dst - d_start;
	//return (dst == d_end ? 0 : -1);
}



// modified by Luigi Auriemma
// Author: bigs (probably based on hsq by "stsp")
// https://sourceforge.net/p/dunerevival/code/HEAD/tree/tools/hsq/hsq_by_bigs/unhsq.c
int unhsq_getbit(int *q, byte** src)
{
	//int b;
	//printf("q1=%d ",*q);
       if (*q == 1) {
				
               *q = 0x10000 | (**((unsigned short **)src));
               *src += 2;
			   printf("q2=%d ",*q);
       }
       if (*q & 1) {			// q impair
               *q >>= 1;
               return 1;
       }
       else {				// q paire
               *q >>= 1;
               return 0;
       }
}
int unhsq(unsigned char *src, unsigned char *dst)
{
		
       if (((src[0] + src[1] + src[2] + src[3] + src[4] + src[5]) & 0xff) != 171) {
            //return 0;
       } else {
            src += 6;
       }
       int q = 1;

        unsigned char *dst_bck = dst;

       while (1) {	
				if (unhsq_getbit(&q, &src)) {

					*dst++ = *src++;
				}
               else {
                       int count;
                       int offset;

                       if (unhsq_getbit(&q, &src)) {
	
                               count = *src & 7;
					
                               offset = (~0x1fff) | ((*(unsigned short *) src) >> 3);

                               src += 2;

                               if (!count) count = *src++;
                               

                               if (!count) break; //return 1;
                       }
                       else {
                               count = unhsq_getbit(&q, &src) << 1;
                               count |= unhsq_getbit(&q, &src);

                               offset = (~0xff) | *src++;
                       }

                       count += 2;

                       byte *dm = dst + offset;

					   while (count--) {
						   *dst++ = *dm++;
					   }
               }
       }
       return dst - dst_bck;
}



// http://zenhax.com/viewtopic.php?p=18646#p18646
unsigned ghiren_decompress(unsigned char *input, unsigned char *output, int size)
{
    //unsigned size=((unsigned*)(&input[8]))[0];
    unsigned char op1,op2;
    unsigned input_pos,output_pos;
    int i;
    
    for(input_pos=0/*12*/,output_pos=0,op1=0,op2=0; output_pos<size; op1--,op2>>=1)
    {
        if(op1==0)
        {
            op1=8;
            op2=input[input_pos++];
        }
        if(!(op2 & 1))  // uncompressed data, only copies input (seems to be at most8 bytes long)
        {
            output[output_pos++]=input[input_pos++];                
        }
        else
        {
            unsigned char low=input[input_pos++];  // these vars are used to calculate block size 
            unsigned char high=input[input_pos++]; // and data to be repeated
            switch(low & 0x0F)
            {
            case 0:
                for(i=0; i<(input[input_pos]+16); i++)  // reuses a previous block of data, 
                                                            // seems to be able to handle bigger sizes than the 
                                                            // default switch case
                {
                    output[output_pos]=output[output_pos-((high<<4) + (low>>4))];
                    output_pos++;
                }
                input_pos++;                                       
                break;
            case 1:                                   // repeated data, high=data to repeat, low/16+3= times
                for(i=0; i<((low>>4) + 3); i++) 
                {
                    output[output_pos++]=high;
                }
                break;
            case 2:
                for(i=0; i<((high<<4) + (low>>4) + 18); i++)    // uncompressed data, it seems that it copies 
                {                                                   // data blocks with bigger sizes than line 17
                    output[output_pos++]=input[input_pos++];                       
                }
                break;
            default:                                 // reuse a previous block of data of size at most 15
                for(i=0; i<(low & 0xF); i++)
                {
                    output[output_pos]=output[output_pos-((high<<4) + (low>>4))];
                    output_pos++;
                }
                break;
            }
        }           
    }      
    return output_pos;    
}



// converted to C by Luigi Auriemma
// https://github.com/solaris573/taikotools
int taiko_decompress(unsigned char *reader, int Length, unsigned char *output) {
    int     Position = 0;
    int     Count = 0;
    int     i;
    while (Position < Length)
    {
        unsigned char c = reader[Position++];

        if (c > 0xbf)
        {
            int len = (c - 0xbe) * 2;
            int flag = reader[Position++];
            int back = ((flag & 0x7f) << 8) + reader[Position++] + 1;

            if ((flag & 0x80) != 0)
            {
                len += 1;
            }

            int end = Count;
            for (i = 0; i < len; i++)
            {
                output[Count++] = output[end - back + i];
            }
        }
        else if (c > 0x7f)
        {
            int len = ((c >> 2) & 0x1f);
            int back = ((c & 0x3) << 8) + reader[Position++] + 1;

            if ((c & 0x80) != 0)
            {
                len += 3;
            }

            int end = Count;
            for (i = 0; i < len; i++)
            {
                if (i > end)
                {
                    output[Count++] = output[end - 1];
                }
                else
                {
                    output[Count++] = output[end - back + i];
                }
            }
        }
        else if (c > 0x3f)
        {
            int len = (c >> 4) - 2;
            int back = (c & 0x0f) + 1;

            int end = Count;
            for (i = 0; i < len; i++)
            {
                if (i > end)
                {
                    output[Count++] = output[end - 1];
                }
                else
                {
                    output[Count++] = output[end - back + i];
                }
            }
        }
        else if (c == 0x00)
        {
            //int offset = Position - 1;

            // Wat?
            int flag = reader[Position++];
            int flag2 = 0;
            int len = 0x40;

            if ((flag & 0x80) == 0)
            {
                flag2 = reader[Position++];

                len = 0xbf + flag2 + (flag << 8);

                if (flag == 0 && flag2 == 0 && reader[Position] /*.PeekChar()*/ == 0x00)
                {
                    break;
                }
            }
            else
            {
                len += (flag & 0x7f);
            }

            for(i = 0; i < len; i++) output[Count++] = reader[Position++];
        }
        else
        {
            for(i = 0; i < c;   i++) output[Count++] = reader[Position++];
        }

    }
    return Count;
}



// http://pastebin.com/rGpBFwAV
int lz77ea_970_readNum(u8 **in) {
    int     total = 0,
            t;
    do {
        t = **in;
        (*in)++;
        total += t;
    } while(t == 0xff);
    return total;
}
int lz77ea_970(u8 *in, int insz, u8 *decompressedStream) {
    u8      *inl = in + insz;
    int     i,
            ret = 0;
    while(in < inl) {
        int lengthByte = *in++;
        int proceedSize = lengthByte>>4;
        int copySize = lengthByte&0xf;

        if(proceedSize==0xf) proceedSize+=lz77ea_970_readNum(&in);

        for(i = 0; i < proceedSize; i++) {
            decompressedStream[ret++] = *in++;
        }
        if(in >= inl) break;

        int offset = in[0] | (in[1]<<8);
        in += 2;

        if(copySize==0xf) copySize+=lz77ea_970_readNum(&in);
        copySize+=4;

        for(i = 0; i < copySize; i++) {
            decompressedStream[ret] = decompressedStream[ret - offset];
            ret++;
        }
    }
    return ret;
}



// https://github.com/BlackDragonHunt/Danganronpa-Tools/blob/master/drv3/drv3_dec.py
// converted by Luigi Auriemma
int drv3_srd_get(unsigned char **in) {
    unsigned char   *t = *in;
    (*in) += 4;
    return (t[0]<<24)|(t[1]<<16)|(t[2]<<8)|(t[3]<<0);
}
int drv3_srd_dec_chunk(unsigned char *mode, unsigned char *data, int data_len, unsigned char *res) {
  //int flag = 1;
  int p = 0;
  int r = 0;
  
  int shift = 6;    // $CL0 uses 6
  if(!memcmp(mode, "$CLN", 4)) shift = 8;
  else if(!memcmp(mode, "$CL1", 4)) shift = 7;
  else if(!memcmp(mode, "$CL2", 4)) shift = 6;
  
  int mask = (1 << shift) - 1;
  int count;
  int i;
  while(p < data_len) {
    int b = data[p];
    p++;
    
    if(b & 1) {
      count = (b & mask) >> 1;
      int offset = ((b >> shift) << 8) | data[p];
      p++;
      
      for(i = 0; i < count; i++) {
        res[r] = res[r-offset];
        r++;
      }
    
    } else {
      count = b >> 1;
      for(i = 0; i < count; i++) {
        res[r++] = data[p++];
      }
    }
  }
  return r;
}
int drv3_srd_dec(unsigned char *in, int insz, unsigned char *res) {
    unsigned char   *o = res;
    unsigned char   *inl = in + insz;
    if(!memcmp(in, "$CMP", 4)) {
        in += 4;
        int cmp_size  = drv3_srd_get(&in);
        in += 8;
        int dec_size  = drv3_srd_get(&in);
        int cmp_size2 = drv3_srd_get(&in);
        in += 4;
        int unk       = drv3_srd_get(&in);
    }
    while((in + 0x10) <= inl) {
        unsigned char cmp_mode[4];
        memcpy(cmp_mode, in, 4);    in += 4;
        int chunk_dec_size = drv3_srd_get(&in);
        int chunk_cmp_size = drv3_srd_get(&in);
        in += 4;
        chunk_cmp_size -= 0x10;
        if(!memcmp(cmp_mode, "$CR0", 4)) {
          memcpy(o, in, chunk_cmp_size);
          o += chunk_cmp_size;
        } else {
          o += drv3_srd_dec_chunk(cmp_mode, in, chunk_cmp_size, o);
        }
        in += chunk_cmp_size;
    }
    return o - res;
}



// https://github.com/nekomiko/recetunpack/blob/master/data_ext.c
int recetunpack(unsigned char *in, int insz, unsigned char *out, int outsz) {
    unsigned char   *o = out;
    unsigned char   *ol = out + outsz;
    unsigned char   *inl = in + insz;
    while (in < inl) {
      char flag = *in++;
      int w;
      for (w = 0; w < 8 && (o < ol); w++) {
        if ((flag & (1 << (7 - w))) == 0) {
          *o++ = *in++;
          continue;
        }
        int recover = *in++;
        int jump = *in++;
        if (recover >= 0x10) {
          jump += (recover >> 4) * 0x100;
          recover &= 0xf;
        }
        if (recover == 0)
          recover = *in++ + 0x10;
        recover++;

        int z;
        for (z = 0; z < recover; z++) {
          o[0] = o[(-jump) % 0x1000];
          o++;
        }
      }
    }
    return o - out;
}



int my_rnc_decompress(u8 *in, int zsize, u8 *out, int size) {
    u8      *inl = in + zsize;
    if(!memcmp(in, "RNC", 3)) {
        in += 3;
        int VER = *in++;
        int SIZE    = QUICK_GETb32(in,0);   in += 4;    // get SIZE long
        int ZSIZE   = QUICK_GETb32(in,0);   in += 4;    // get ZSIZE long
                                            in += 2;    // get CRC short
                                            in += 2;    // get CRC short
                                            in += 2;    // get DUMMY short

        zsize = inl - in;
        if(zsize < 0) return -1;
        if((SIZE > 0) && (SIZE < size)) size = SIZE;
        if((ZSIZE > 0) && (ZSIZE < zsize)) zsize = ZSIZE;
        switch(VER) {
            case 1:  size = _rnc_unpack(in, zsize, out, 0); break;
            case 2:  size = RncDecoder__unpackM2(in, zsize, out, size); break;
            default: size = RncDecoder__unpackM1(in, zsize, out, size);  /* auto guess */ break;
        }
    } else {
        // this is the original function used by "comtype rnc"
        size = _rnc_unpack(in, zsize, out, 0);
    }
    return size;
}


