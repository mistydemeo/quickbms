#pragma once

#define DO_LOE_PENALIZE_NONDET // yep this helps; it's freaky

namespace Ppmz2
{
	// Forward defs to reduce header file dependencies
	class Context;
	class Exclude;
	class See;

    class LocalOrderEstimation
    {
    public:
/*
        typedef enum
        {
	        LOETYPE_NONE = 0,
	        LOETYPE_MPS,
	        LOETYPE_ND1,
	        LOETYPE_COUNT
        }*/ typedef int LOEType;

        EXPORT static int ChooseOrder(LOEType loeType, Context ** contexts, unsigned long cntx, int maxOrder, Exclude* exc, See* see, bool useFull);		
    };
}



#define LocalOrderEstimation__LOEType__LOETYPE_NONE 0
#define LocalOrderEstimation__LOEType__LOETYPE_MPS 1
#define LocalOrderEstimation__LOEType__LOETYPE_ND1 2
#define LocalOrderEstimation__LOEType__LOETYPE_COUNT 3

#define LOETYPE_NONE LocalOrderEstimation__LOEType__LOETYPE_NONE
#define LOETYPE_MPS LocalOrderEstimation__LOEType__LOETYPE_MPS
#define LOETYPE_ND1 LocalOrderEstimation__LOEType__LOETYPE_ND1
#define LOETYPE_COUNT LocalOrderEstimation__LOEType__LOETYPE_COUNT
