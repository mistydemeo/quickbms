#pragma once

#include <sstream>
#include "stdafx.h"

namespace Ppmz2
{
	class CodingMetrics
	{

	public:
		__int64 UpdatingTime;
		__int64 LOETime;
		__int64 DetCodingTime;
		__int64 DetUpdatingTime;
		__int64 MinusOneOrderTime;
		__int64 CodeFromOrderTime;
		int BytesDetEncoded;

		const std::string ToString() const
		{
			std::ostringstream stream;
			stream << "UpdatingTime: " << UpdatingTime << " LOETime: " << LOETime
			<< " DetCodingTime: " << DetCodingTime << " DetUpdatingTime " << DetUpdatingTime
			<< " MinusOneOrderTime: " << MinusOneOrderTime << " CodeFromOrderTime: " << CodeFromOrderTime
			<< " BytesDetEncoded: " << BytesDetEncoded;
			return stream.str();
		}
	};
}