static u8 Yappy_maps[32][16];
static size_t Yappy_infos[256];
 
void Yappy_FillTables() {
    static int Yappy_init = 0;
    if(Yappy_init) return;
    Yappy_init = 1;

    memset(&Yappy_maps[0][0], 0, sizeof(Yappy_maps));
    u64 step = 1 << 16;
 
    size_t i, j;
    for (i = 0; i < 16; ++i) {
        u64 value = 65535;
        step = (step * 67537) >> 16;
        while(value < (29UL << 16)) {
           Yappy_maps[value >> 16][i] = 1;
           value = (value * step) >> 16;
        }
    }
 
    int cntr = 0;
    for (i = 0; i < 29; ++i) {
        for (j = 0; j < 16; ++j) {
            if (Yappy_maps[i][j]) {
                Yappy_infos[32 + cntr] = i + 4 + (j << 8);
                Yappy_maps[i][j] = 32 + cntr;
                ++cntr;
            } else {
                if (i == 0)
                   exit(1); //throw("i == 0");
                Yappy_maps[i][j] = Yappy_maps[i - 1][j];
            }
        }
    }
    if (cntr != 256 - 32) {
        exit(1); //throw("init error");
    }
}
int Yappy_UnCompress(const u8 *data, const u8 *end, u8 *to) {
    Yappy_FillTables();
    u8 *start = to;
    while(data < end) {
        size_t index = data[0];
        if (index < 32) {
            memmove(to, data + 1, index + 1);
            to += index + 1;
            data += index + 2;
        } else {
            size_t info = Yappy_infos[index];
            size_t length = info & 0x00ff;
            size_t offset = (info & 0xff00) + (size_t)(data[1]);
 
            memmove(to, to - offset, length);
            to += length;
            data += 2;
        }
   }
   return to - start;
}

static int inline Yappy_Match(const u8 *data, size_t i, size_t j, size_t size) {
    if (*(u32 *)(data + i) != *(u32 *)(data + j))
        return 0;
    size_t k = 4;
    size_t bound = i - j;
    bound = bound > size ? size : bound;
    bound = bound > 32 ? 32 : bound;
    for (;k < bound && data[i + k] == data[j + k]; ++k);
    return k < bound ? k : bound;
}
 
 
static u64 inline Yappy_Hash(u64 value) {
    return ((value * 912367421UL) >> 24) & 4095;
}
 
 
static void inline Yappy_Link(size_t *Yappy_Hashes, size_t *nodes, size_t i, const u8 *data) {
   size_t Yappy_HashValue = Yappy_Hashes[Yappy_Hash(*(const u32 *)(data + i))];
   nodes[i & 4095] = Yappy_HashValue;
   Yappy_HashValue = i;
}
 
 
int Yappy_Compress(const u8 *data, u8 *to, size_t len, int level) {
    Yappy_FillTables();

    size_t Yappy_Hashes[4096];
    size_t nodes[4096];
    u8 end = 0xff;
    u8 *optr = &end;
    u8 *start = to;
    size_t i;
    
    for (i = 0; i < 4096; ++i) {
        Yappy_Hashes[i] = (size_t)(-1);
    }
 
    for (i = 0; i < len;) {
        u8 coded = data[i];
        Yappy_Link(Yappy_Hashes, nodes, i, data);
 
        size_t bestYappy_Match = 3;
        u16 bestCode = 0;
 
        size_t ptr = i;
        int tries = 0;
 
        while(1) {
            size_t newPtr = nodes[ptr & 4095];
            if (newPtr >= ptr || i - newPtr >= 4095 || tries > level) {
                break;
            }
            ptr = newPtr;
            size_t Match = Yappy_Match(data, i, ptr, len - i);
 
            if (bestYappy_Match < Match) {
                u8 code = Yappy_maps[Match - 4][(i - ptr) >> 8];
                Match = Yappy_infos[code] & 0xff;
 
                if (bestYappy_Match < Match) {
                    bestYappy_Match = Match;
                    bestCode = code + (((i - ptr) & 0xff) << 8);
                    if (bestYappy_Match == 32)
                        break;
                }
            }
 
            tries += Match > 3;
        }
 
        if (optr[0] > 30) {
            optr = &end;
        }
 
        if (bestYappy_Match > 3) {
            *(u16 *)to = bestCode;
 
            size_t k;
            for (k = 1; k < bestYappy_Match; ++k)
               Yappy_Link(Yappy_Hashes, nodes, i + k, data);
 
            i += bestYappy_Match;
            to += 2;
            optr = &end;
        } else {
            if (optr[0] == 0xff) {
               optr = to;
               optr[0] = 0xff;
               ++to;
            }
            ++optr[0];
            to[0] = coded;
            ++to;
            ++i;
        }
    }
    return to - start;
}
