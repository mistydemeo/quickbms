#include "stdafx.h"

#include "Stopwatch.h"

Stopwatch::Stopwatch()
{
	//QueryPerformanceFrequency(&m_liPerfFreq);
	//Start();
}

void Stopwatch::Start()
{
	//QueryPerformanceCounter(&m_liPerfStart);
}

__int64 Stopwatch::Elapsed() const
{
	//LARGE_INTEGER liPerfNow;
	//QueryPerformanceCounter(&liPerfNow);
	//return liPerfNow.QuadPart - m_liPerfStart.QuadPart;
    return 0;
}