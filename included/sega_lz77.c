// this is an untested Delphi to C conversion made by Luigi Auriemma
// I don't know who was the original author of the Delphi code because
// no name was available in the whole source code (unit1, *.pas, projects, nothing, mah...)



int sega_lz77(unsigned char *Buf, int File_Size, unsigned char *Buf2) {
    int             /*CurBit,*/ SrcPos;
    unsigned char   CurByte;
    int             BitCounter;

    unsigned char GetByte_00E1F580(void) {
        unsigned char   RESULT;
        if(SrcPos >= File_Size) return(0);
        RESULT = Buf[SrcPos];   // xor 0x95 (I don't make the xor because this is a compression
        SrcPos++;
        return(RESULT);
    }

    unsigned char GetBit_00E1F5D0(void) {
        unsigned char   RESULT;

        BitCounter--;
        if(!BitCounter) {
            CurByte = GetByte_00E1F580();
            BitCounter = 8;
        }
        RESULT  = CurByte & 1;
        CurByte >>= 1;
        return(RESULT);
    }

    unsigned int    _EBP_m_4=0, _EBP_m_8=0;
    int             DstPos;
    unsigned char   _EAX;

    //CurBit=0;
    SrcPos=0;
    DstPos=0;
    BitCounter = 1;

	while(SrcPos < File_Size) {
		for(;;) {
			_EAX = GetBit_00E1F5D0();
            if(!_EAX) break;
            Buf2[DstPos++] = GetByte_00E1F580();
		}
        if(GetBit_00E1F5D0()) {
            _EBP_m_4 = GetByte_00E1F580();
            _EBP_m_8 = GetByte_00E1F580();
            _EAX = _EBP_m_8 | _EBP_m_4;
            if(!_EAX) break;

            _EBP_m_8 = (_EBP_m_8 << 5) + (_EBP_m_4 >> 3) - 0x2000;
            _EBP_m_4 &= 7;

            if(_EBP_m_4) {
                _EBP_m_4 += 2;
            } else {
                _EBP_m_4 = GetByte_00E1F580() + 0x0A;
            }
        } else {
            _EBP_m_4 = GetBit_00E1F5D0() * 2;
            _EBP_m_4 += GetBit_00E1F5D0() + 2;
            _EBP_m_8 = GetByte_00E1F580() - 0x100;
        }
    }
    while(_EBP_m_4 > 0) {
        Buf2[DstPos] = Buf2[DstPos + _EBP_m_8];
        DstPos++;
        _EBP_m_4--;
    }
    return(DstPos);
}
