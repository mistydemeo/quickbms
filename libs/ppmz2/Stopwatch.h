#pragma once

#ifdef WIN32
#include <windows.h>
#else
#endif

class Stopwatch
{
public:
	EXPORT Stopwatch();

	EXPORT void Start();

	EXPORT __int64 Elapsed() const;

private:
	LARGE_INTEGER m_liPerfFreq;
	LARGE_INTEGER m_liPerfStart;
};