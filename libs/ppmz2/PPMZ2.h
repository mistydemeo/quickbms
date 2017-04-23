#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include <excpt.h>
#include <exception>

#include <string>
#include <iostream>
#include "CodingMetrics.h"
#include "LocalOrderEstimation.h"

const unsigned int PPMZ2_MaxContextLen	=32;
const unsigned int PPMZ2_SeedBytes		=8;
const unsigned int PPMZ2_SeedByte		=214;

const unsigned int PPMZ2_DetMegs		=4;
const unsigned int PPMZ2_TrieMegs		=72;

#define PPMZ2_Order 8

namespace Ppmz2
{
	// Forward defs to reduce header dependencies
	class ContextTrie;
	class ArithInfo;
	class See;
	class PpmDet;
	class Exclude;

#define CodingOptions__Default 0
#define CodingOptions__NoUpdate 1
#define CodingOptions__TextMode 2
/*
	enum CodingOptions 
	{
		Default = 0,
		NoUpdate = 1,
		TextMode = 2
	};
*/
typedef int CodingOptions;

    class Ppmz
    {
    private:
        Ppmz() {}

        ContextTrie* _contextTrie;
	    ArithInfo* _arithInfo;
        Exclude* _exclude;
        See* _see;
        PpmDet* _det;
        int _order;
        int _trieMegs;
        int _detMegs;
        CodingOptions _options;
        /*LocalOrderEstimation::LOEType*/ int _loeType;		
		void (*_loggingCallback)(const std::string&);

    public:
		EXPORT static Ppmz* Create(int order, int trieMegs, int detMegs, CodingOptions options, /*LocalOrderEstimation::LOEType*/ int loeType, void (*loggingCallback)(const std::string&));

        static Ppmz* Create(CodingOptions options, void (*loggingCallback)(const std::string&))
        {
			return Create(8, 72, 4, options, LocalOrderEstimation__LOEType__LOETYPE_MPS, loggingCallback);
        }

        ~Ppmz()
        {
	        delete _exclude;
            delete _arithInfo;
            delete _see;
            delete _contextTrie;
	        delete _det;
        }

        EXPORT unsigned int EncodeArraySub(unsigned char* rawBuf, unsigned int rawLen, unsigned char* compBuf);
		EXPORT __int64 EncodeOrderMinusOne(int sym);
		EXPORT __int64 Update(Context** contexts, int sym, unsigned long cntx, int order);
		EXPORT int EncodeFromOrder(Context** contexts, int sym, unsigned long cntx, bool* useFull, CodingMetrics* metrics);
		EXPORT bool DetEncode(unsigned char* rawPtr, unsigned char* rawBuf, int sym, Context** contexts, bool* useFull, __int64* codingTime);
		EXPORT __int64 DetUpdate(unsigned char* rawPtr, unsigned char* rawBuf, int sym);		
		EXPORT int DecodeOrderMinusOne(__int64* minusOneOrderTime);
		EXPORT int DecodeFromOrder(Context** contexts, unsigned long cntx, bool* useFull, CodingMetrics* metrics, int* codedOrder);
		EXPORT bool DetDecode(unsigned char* rawPtr, unsigned char* rawBuf, int* sym, Context** contexts, bool* useFull, __int64* codingTime);
		EXPORT bool DecodeArraySub(unsigned char* rawBuf, unsigned int rawLength, unsigned char* compBuf);        
        EXPORT void ReInitCoder();
		EXPORT unsigned int DecodeOrderMinusOneText();
		EXPORT void EncodeOrderMinusOne(unsigned int sym, unsigned int numChars);
		EXPORT void EncodeOrderMinusOneText(unsigned int sym);
		EXPORT unsigned int DecodeOrderMinusOne(unsigned int numChars);
		EXPORT bool EncodeFromContext(Context* cntx, unsigned long index, int sym, bool* pUseFull);
		EXPORT bool DecodeFromContext(Context* cntx, unsigned long index, int *psym, bool * pUseFull);

		EXPORT void SafeLog(const std::string& message)
		{
			if (_loggingCallback)
				_loggingCallback(message);
		}

		EXPORT void SafeLog(const std::string& message, const CodingMetrics& metrics)
		{
			if (_loggingCallback)
			{
				std::ostringstream stream;
				stream << message << " " << metrics.ToString() << std::endl;

				_loggingCallback(stream.str());
			}
		}
    };
}