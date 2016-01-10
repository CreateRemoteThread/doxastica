#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "ptrscan.h"

/*

// base off dword search

static int cs_search_new(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	SYSTEM_INFO si;       // for dwPageSize

	GetSystemInfo(&si);

	char mbuf[1024];

	DWORD valueToSearch_dword = 0;
	WORD valueToSearch_word = 0;
	BYTE valueToSearch_byte = 0;
	UINT_PTR start = 0;
	#if ARCHI == 64
		UINT_PTR hardMax = 0x7FFFFFFFFFFFFFFF;
	#else
		UINT_PTR hardMax = 0x7FFFFFFF;
	#endif

	int searchType = 0;

	if (lua_gettop(L) >= 2 && lua_gettop(L) <= 4)
	{
		searchType = lua_tonumber(L,1);
		switch(searchType)
		{
			case SEARCH_DWORD:
				valueToSearch_dword = (DWORD )lua_tonumber(L,2);
				break;
			case SEARCH_WORD:
				valueToSearch_word = (WORD )lua_tonumber(L,2);
				break;
			case SEARCH_BYTE:
				valueToSearch_byte = (BYTE )lua_tonumber(L,2);
				break;
			default:
				outString(hPipe," [ERR] search_new(searchtype,searchdata,startAddress,endAddress) requires SEARCH_DWORD, SEARCH_WORD, SEARCH_BYTE or SEARCH_QWORD as first arg\n");
				return 0;
		}
	}

	if (lua_gettop(L) == 3)
	{
		start = (UINT_PTR )lua_tonumber(L,2);
	}
	else if (lua_gettop(L) == 4)
	{
		start = (UINT_PTR )lua_tonumber(L,2);
		hardMax = (UINT_PTR )lua_tonumber(L,3);
	}
	else if(lua_gettop(L) != 2)
	{
		outString(hPipe," [ERR] search_new(searchtype,searchdata,startAddress,endAddress) requires 2 arguments\n");
		return 0;
	}

	sprintf(mbuf," [NFO] scanning from 0x%0x to 0x%0x (pagesize=%d)\n", 0, hardMax, si.dwPageSize);	
	outString(hPipe,mbuf);

	// allow for 1024 instances at once.
	int chunkAllocatorSize = 1024;
	UINT_PTR readStart = 0;
	int skippedPages = 0;

	int totalSolutionCount = 0;

	searchResult *results = NULL;

	for( readStart ; readStart < hardMax ; readStart += si.dwPageSize )
	{
		int solutionCount = 0;
		UINT_PTR *solutions = (UINT_PTR *)malloc(sizeof(UINT_PTR) * (si.dwPageSize / 4));

		int retVal = 0;
		switch(searchType)
		{
			case SEARCH_DWORD:
				retVal = page_search_dword(readStart,si.dwPageSize,&solutionCount,solutions,valueToSearch_dword);
				break;
			case SEARCH_WORD:
				retVal = page_search_word(readStart,si.dwPageSize,&solutionCount,solutions,valueToSearch_word);
				break;
			case SEARCH_BYTE:
				retVal = page_search_byte(readStart,si.dwPageSize,&solutionCount,solutions,valueToSearch_byte);
				break;
			default:
				outString(hPipe," [ERR] search: invalid search type\n");
				return 0;
		}

		if( retVal )
		{
			if(solutionCount != 0)
			{
				totalSolutionCount += solutionCount;
				results = mergeResults(results,solutionCount,solutions);
			}
		}
		else
		{
			skippedPages += 1;
		}

		
		free(solutions);
	}

	results->signature = SEARCH_SIG;
	results->searchType = searchType;
	sprintf(mbuf," [NFO] %d instances found, %d pages skipped\n",totalSolutionCount, skippedPages);
	outString(hPipe,mbuf);
	
	lua_pushlightuserdata(L,(void *)results);
	return 1;
}
*/

static int cs_ptrscan(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);


	return 0;
}

int validatePtrResult(ptrResult *p)
{
	__try{
		if (p->signature == PTRSCAN_SIG)
		{
			return 1;
		}
	}
	__except(true)
	{
		return 0;
	}
	return 0;
}
