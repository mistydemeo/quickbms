#ifndef STDAFX_H
#define STDAFX_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
//#define NULL (0)
#if defined(_MSC_VER)
    //  Microsoft 
    #define EXPORT __declspec(dllexport)
    #define IMPORT __declspec(dllimport)
#elif defined(_GCC)
    //  GCC
    #define EXPORT __attribute__((visibility("default")))
    #define IMPORT
#else
    //  do nothing and hope for the best?
    #define EXPORT
    #define IMPORT
    #pragma warning Unknown dynamic link import/export semantics.
#endif

#ifdef WIN32
#else
    typedef uint32_t    DWORD;
    typedef uint32_t    LONG;
    typedef uint64_t    LONGLONG;
    typedef int64_t __int64;
    typedef union _LARGE_INTEGER {
      struct {
        DWORD LowPart;
        LONG  HighPart;
      };
      struct {
        DWORD LowPart;
        LONG  HighPart;
      } u;
      LONGLONG QuadPart;
    } LARGE_INTEGER, *PLARGE_INTEGER;
#endif

#endif
