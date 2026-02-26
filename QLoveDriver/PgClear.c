#include "PgClear.h"



#include <defs.h>
#include <devicedefs.h>

//#include "Shark.h"


#include "Shark/Except.h"

//#include "Except.h"
#include "Shark/Guard.h"
#include "Shark/Reload.h"
#include "Shark/PatchGuard.h"
#include "Shark/Space.h"

#pragma section( ".block", read, write, execute )

__declspec(allocate(".block")) RTB RtBlock = { 0 };
__declspec(allocate(".block")) PGBLOCK PgBlock = { 0 };