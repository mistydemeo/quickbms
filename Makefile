EXE		= quickbms
# -m32 because QuickBMS has been tested only on 32bit systems and gives problems using 64bit native code
CFLAGS	+= -m32 -s -O0 -fstack-protector-all -fno-unit-at-a-time -fno-omit-frame-pointer -w
# Add -DQUICKBMS64 to CDEFS for compiling quickbms_4gb_files
CDEFS	+= -DDISABLE_UCL -DDISABLE_MCRYPT -DDISABLE_TOMCRYPT
CLIBS	+= -static-libgcc -static-libstdc++ -lstdc++ -ldl -lz -lbz2 -lm -lpthread $(LDFLAGS)
PREFIX	= /usr/local
BINDIR	= $(PREFIX)/bin
SRC		= $(EXE).c

ifeq ($(shell uname -s), Darwin)
CDEFS	+= -DDISABLE_LZO
CFLAGS	+= -Dunix
else
CLIBS   += -llzo2
EXTRA_TARGETS = libs/amiga/*
endif

ifndef USE_OPENSSL
CDEFS	+= -DDISABLE_SSL
else
CLIBS	+= -lssl -lcrypto
endif

# MacOSX steps:
# - > xcode-select install
# - > /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
# - > brew install gcc
# - uncomment the following lines:

#CC		= /usr/local/Cellar/gcc/6.2.0/bin/gcc-6
#CXX		= /usr/local/Cellar/gcc/6.2.0/bin/g++-6

# If using OpenSSL, also do:
# - > export CFLAGS=-I$(brew --prefix openssl)/include
# - > export LDFLAGS=-L$(brew --prefix openssl)/lib
# - > export USE_OPENSSL=1

all:
	$(CC) $(SRC) $(CFLAGS) -o $(EXE) \
	\
	-D_7ZIP_ST \
	\
	compression/*.c* encryption/*.c* extra/mem2mem.c libs/lzma/LzmaDec.c libs/lzma/Lzma2Dec.c libs/lzma/Bra86.c libs/lzma/LzFind.c libs/lzma/LzmaEnc.c libs/lzma/Lzma2Enc.c libs/mspack/*.c libs/ppmd/*.cpp libs/aplib/depacks.c libs/brieflz/depacks.c libs/brieflz/brieflz.c compression/jcalg1_static.lib libs/zziplib/*.c libs/bcl/*.c libs/szip/*.c libs/lzhl/*.cpp libs/tdcb/*.c libs/libkirk/*.c libs/7z_advancecomp/*.cc libs/iris/*.cpp libs/old_cabextract/lzx.c libs/mrci/*.cpp libs/lz4/*.c libs/snappy/snappy.cc libs/snappy/snappy-c.cc libs/snappy/snappy-stubs-internal.cc libs/snappy/snappy-sinksource.cc libs/mmini/mmini_huffman.c libs/mmini/mmini_lzl.c libs/clzw/lzw-dec.c libs/clzw/lzw-enc.c libs/lzlib/lzlib.c libs/blosc/blosclz.c libs/gipfeli/*.cc libs/liblzg/src/lib/decode.c libs/liblzg/src/lib/encode.c libs/liblzg/src/lib/checksum.c libs/doboz/*.cpp libs/sphlib/c/*.c libs/shadowforce/*.cpp libs/zstd/common/*.c libs/zstd/compress/*.c libs/zstd/decompress/*.c libs/zstd/dictBuilder/*.c libs/zstd/legacy/*.c -Ilibs/zstd -Ilibs/zstd/common -Ilibs/zstd/legacy libs/azo/unAZO.cpp libs/azo/Decoder/MainCodeD.cpp libs/azo/Common/x86Filter.cpp libs/nintendo_ds/*.c libs/ctw/*.c libs/grzip/libgrzip.c libs/heatshrink/heatshrink_decoder.c libs/heatshrink/heatshrink_encoder.c libs/libzling/*.cpp  -Ilibs/ecrypt/include -Ilibs/libcsc -D_7Z_TYPES_ libs/libcsc/csc_dec.cpp libs/libcsc/csc_default_alloc.cpp libs/libcsc/csc_filters.cpp libs/libcsc/csc_memio.cpp -DDENSITY_FORCE_INLINE=inline -Drestrict=__restrict__ libs/density/src/*.c libs/density/src/spookyhash/src/*.c libs/brotli/dec/*.c libs/brotli/common/*.c libs/libbsc/adler32/adler32.cpp libs/libbsc/bwt/bwt.cpp libs/libbsc/coder/coder.cpp libs/libbsc/coder/qlfc/qlfc.cpp libs/libbsc/coder/qlfc/qlfc_model.cpp libs/libbsc/filters/detectors.cpp libs/libbsc/filters/preprocessing.cpp libs/libbsc/libbsc/libbsc.cpp libs/libbsc/lzp/lzp.cpp libs/libbsc/platform/platform.cpp libs/libbsc/st/st.cpp libs/shoco/shoco.c libs/ms-compress/src/*.cpp libs/lzjody/lzjody.c libs/lzjody/byteplane_xfrm.c disasm/disasm.c disasm/cmdlist.c disasm/assembl/assembl.c libs/mydownlib/mydownlib.c libs/TurboRLE/trlec.c libs/TurboRLE/trled.c libs/TurboRLE/ext/mrle.c libs/lhasa/lib/*_decoder.c libs/lhasa/lib/crc16.c libs/dipperstein/*.c libs/liblzf/lzf_d.c libs/liblzf/lzf_c_best.c libs/zopfli/*.c libs/lzham_codec/lzhamcomp/*.cpp libs/lzham_codec/lzhamdecomp/*.cpp libs/lzham_codec/lzhamlib/*.cpp -Ilibs/lzham_codec/include -Ilibs/lzham_codec/lzhamcomp -Ilibs/lzham_codec/lzhamdecomp -DLZHAM_ANSI_CPLUSPLUS libs/dmsdos/*.c libs/tornado/Tornado.cpp libs/tornado/Common.cpp libs/PKLib/*.c extra/mybits.c libs/lz5/lz5*.c libs/lizard/*.c libs/ppmz2/*.c* libs/libdivsufsort/*.c libs/xxhash/*.c extra/xalloc.c libs/lzfse/src/*.c  libs/hsel/myhsel.cpp libs/hsel/HSEL.cpp libs/glza/GLZAmodel.c libs/minilzo/minilzo.c $(EXTRA_TARGETS)  \
	\
	$(CLIBS) $(CDEFS)

install:
	install -m 755 -d $(BINDIR)
	install -m 755 $(EXE) $(BINDIR)/$(EXE)

.PHONY:
	install
