#include <stdio.h>
#include <windows.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "shackle.h"
#include "search.h"

int page_search_dword(UINT_PTR d,int pageSize,int *solutionCount, UINT_PTR *solutions, DWORD valueToSearch)
{
	DWORD *readHead = (DWORD *)d;
	int i = 0;
	int max = pageSize / sizeof(DWORD);
	for( ; i < max; i++)
	{
		__try
		{
			// needs to be inside the try statement :)
			// herpaderp
			if(readHead[i] == valueToSearch)
			{
				solutions[solutionCount[0]] = (UINT_PTR )&(readHead[i]);
				solutionCount[0] += 1;
			}
		}
		__except(true)
		{
			return 0;
		}
	}

	return 1;
}

int page_search_word(UINT_PTR d,int pageSize,int *solutionCount, UINT_PTR *solutions, WORD valueToSearch)
{
	WORD *readHead = (WORD *)d;
	int i = 0;
	int max = pageSize / sizeof(WORD);
	for( ; i < max; i++)
	{
		__try
		{
			// needs to be inside the try statement :)
			// herpaderp
			if(readHead[i] == valueToSearch)
			{
				solutions[solutionCount[0]] = (UINT_PTR )&(readHead[i]);
				solutionCount[0] += 1;
			}
		}
		__except(true)
		{
			return 0;
		}
	}

	return 1;
}

int page_search_byte(UINT_PTR d,int pageSize,int *solutionCount, UINT_PTR *solutions, BYTE valueToSearch)
{
	BYTE *readHead = (BYTE *)d;
	int i = 0;
	int max = pageSize / sizeof(BYTE);
	for( ; i < max; i++)
	{
		__try
		{
			// needs to be inside the try statement :)
			// herpaderp
			if(readHead[i] == valueToSearch)
			{
				solutions[solutionCount[0]] = (UINT_PTR )&(readHead[i]);
				solutionCount[0] += 1;
			}
		}
		__except(true)
		{
			return 0;
		}
	}

	return 1;
}

// a = search_dword(X,Y,Z)
// search_filter(a,123123)
// etc
// a contains search type.

int search_filter_dword(searchResult *m, DWORD newvalue)
{
	int i = 0;
	int remainingSolutions = 0;
	int max = m->numSolutions;
	UINT_PTR *newSolutions = (UINT_PTR *)malloc(sizeof(UINT_PTR) * max);
	for( ; i < max ; i++)
	{
		__try
		{
			if( *((DWORD *)(m->arraySolutions[i])) == newvalue)
			{
				newSolutions[remainingSolutions] = m->arraySolutions[i];
				remainingSolutions += 1;
			}
		}
		__except(true)
		{
			// nothing happens here.
		}
	}

	free(m->arraySolutions);
	m->numSolutions = remainingSolutions;
	m->arraySolutions = newSolutions;
	return remainingSolutions;
}

int search_filter_word(searchResult *m, WORD newvalue)
{
	int i = 0;
	int remainingSolutions = 0;
	int max = m->numSolutions;
	UINT_PTR *newSolutions = (UINT_PTR *)malloc(sizeof(UINT_PTR) * max);
	for( ; i < max ; i++)
	{
		__try
		{
			if( *((WORD *)(m->arraySolutions[i])) == newvalue)
			{
				newSolutions[remainingSolutions] = m->arraySolutions[i];
				remainingSolutions += 1;
			}
		}
		__except(true)
		{
			// nothing happens here.
		}
	}

	free(m->arraySolutions);
	m->numSolutions = remainingSolutions;
	m->arraySolutions = newSolutions;
	return remainingSolutions;
}

int search_filter_byte(searchResult *m, BYTE newvalue)
{
	int i = 0;
	int remainingSolutions = 0;
	int max = m->numSolutions;
	UINT_PTR *newSolutions = (UINT_PTR *)malloc(sizeof(UINT_PTR) * max);
	for( ; i < max ; i++)
	{
		__try
		{
			if( *((BYTE *)(m->arraySolutions[i])) == newvalue)
			{
				newSolutions[remainingSolutions] = m->arraySolutions[i];
				remainingSolutions += 1;
			}
		}
		__except(true)
		{
			// nothing happens here.
		}
	}

	free(m->arraySolutions);
	m->numSolutions = remainingSolutions;
	m->arraySolutions = newSolutions;
	return remainingSolutions;
}

// fast check, we can call it twice. 
int validateSearchResult(searchResult *m)
{
	__try
	{
		if(m->signature == SEARCH_SIG)
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
	__except(true){
		return 0;
	}
}

searchResult *mergeResults(searchResult *m, int solutionCount, UINT_PTR *solns)
{
	searchResult *newResult = NULL;
	if (m == NULL)
	{
		// new result
		newResult = (searchResult *)malloc(sizeof(searchResult));\
		newResult->signature = SEARCH_SIG;
		newResult->numSolutions = solutionCount;
		int chunksToAllocate = (solutionCount / 1024) + 1;
		newResult->numSolutionsMaximum = chunksToAllocate * 1024;
		newResult->arraySolutions = (UINT_PTR *)malloc(chunksToAllocate * 1024 * sizeof(UINT_PTR));
		int i = 0;
		for ( ; i < solutionCount ; i++)
		{
			newResult->arraySolutions[i] = solns[i];
		}
		return newResult;
	}
	else if(solutionCount + m->numSolutions < m->numSolutionsMaximum)
	{
		// use existing result;
		newResult = m;
		int i = 0;
		int currentHead = newResult->numSolutions;
		for(; i < solutionCount;i++)
		{
			newResult->arraySolutions[currentHead + i] = solns[i];
		}
		newResult->numSolutions += solutionCount;
		return newResult;
	}
	else
	{
		// reallocate results array
		UINT_PTR *oldResultArray = m->arraySolutions;
		
		int newSolutionCount = m->numSolutions + solutionCount;
		int chunksToAllocate = (newSolutionCount / 1024) + 1;
		int newSolutionsMaximum = chunksToAllocate * 1024;

		UINT_PTR *newSolutions = (UINT_PTR *)malloc(chunksToAllocate * 1024 * sizeof(UINT_PTR));
		int i = 0;
		int oldSolutionCount = m->numSolutions;
		for ( ; i < oldSolutionCount; i++)
		{
			newSolutions[i] = oldResultArray[i];
		}

		int writeHead = i;

		for(i = 0; i < solutionCount;i++)
		{
			newSolutions[writeHead + i] = solns[i];
		}

		m->numSolutions = newSolutionCount;
		m->numSolutionsMaximum = newSolutionsMaximum;
		m->arraySolutions = newSolutions;

		free(oldResultArray);
		return m;
	}
	return NULL;
}


int cs_search_fetch(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);
	if (lua_gettop(L) == 2)
	{
		searchResult *oldResults = (searchResult *)lua_touserdata(L,1);

		if(validateSearchResult(oldResults) == 0)
		{
			outString(hPipe," [ERR] argument 1 was not a valid search result\n");
			return 0;
		}
		int searchIndex = lua_tonumber(L,2);
		
		if(searchIndex >= oldResults->numSolutions)
		{
			char mbuf[1024];
			sprintf(mbuf," [ERR] index too big, this search result set only has %d solutions\n",oldResults->numSolutions);
			outString(hPipe,mbuf);
			outString(hPipe," [NFO] this command indexes from 0, search_fetch(result,0) fetches the first result");
			return 0;
		}

		lua_pushnumber(L,oldResults->arraySolutions[searchIndex]);
		return 1;
	}
	else
	{
		outString(hPipe," [ERR] search_fetch(results,index) needs 2 args\n");
		return 0;
	}
	return 0;
}

int cs_search_free(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);
	if (lua_gettop(L) == 1)
	{
		searchResult *oldResults = (searchResult *)lua_touserdata(L,1);

		if(validateSearchResult(oldResults) == 0)
		{
			outString(hPipe," [ERR] argument 1 was not a valid search result\n");
			return 0;
		}

		oldResults->signature = 0;
		free(oldResults->arraySolutions);
		free(oldResults);
		return 0;
	}
	else
	{
		outString(hPipe," [ERR] search_free(results) takes one argument\n");
		return 0;
	}
	return 0;
}

int cs_search_filter(lua_State *L)
{
	lua_getglobal(L,"__hpipe");
	HANDLE hPipe = (HANDLE )(int )lua_tonumber(L,-1);
	lua_pop(L,1);

	if (lua_gettop(L) == 2)
	{
		searchResult *oldResults = (searchResult *)lua_touserdata(L,1);
		if(validateSearchResult(oldResults) == 0)
		{
			outString(hPipe," [ERR] argument 1 was not a valid search result\n");
			return 0;
		}

		int t = oldResults->searchType;
		int newResults = 0;

		DWORD newFilter_dw;
		WORD newFilter_w;
		BYTE newFilter_b;
		switch(t)
		{
			case SEARCH_DWORD:
				newFilter_dw = (DWORD )lua_tonumber(L,2);
				newResults = search_filter_dword(oldResults, newFilter_dw);
				break;
			case SEARCH_WORD:
				newFilter_w = (WORD )lua_tonumber(L,2);
				newResults = search_filter_word(oldResults, newFilter_w);
				break;
			case SEARCH_BYTE:
				newFilter_b = (BYTE )lua_tonumber(L,2);
				newResults = search_filter_byte(oldResults, newFilter_b);
				break;
			default:
				outString(hPipe," [ERR] search_filter(results,new_value) tried to filter a search result with an invalid searchtype\n");
				return 0;
				break;
		}
		printShortResults(hPipe,L,oldResults);
		lua_pushnumber(L,newResults);
		return 1;
	}
	else
	{
		outString(hPipe," [ERR] search_filter(results,new_value) requires 2 arguments\n");
		return 0;
	}
	return 0;
}

int cs_search_new(lua_State *L)
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
		UINT_PTR hardMax = (UINT_PTR )si.lpMaximumApplicationAddress;
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

	//int priority = GetThreadPriority(GetCurrentThread());
	//SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_HIGHEST);

	int totalSolutionCount = 0;

	searchResult *results = NULL;

	MEMORY_BASIC_INFORMATION mbi;
	for( readStart ; readStart < hardMax ; readStart += si.dwPageSize )
	{
		int solutionCount = 0;
		UINT_PTR *solutions = (UINT_PTR *)malloc(sizeof(UINT_PTR) * (si.dwPageSize / 4));
		int vqresult = VirtualQuery((LPCVOID )readStart,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
		if(vqresult == 0)
		{
			readStart = (UINT_PTR )((UINT_PTR )mbi.BaseAddress + mbi.RegionSize);
			continue;
		}
		else if(mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
		{
			readStart = (UINT_PTR )((UINT_PTR )mbi.BaseAddress + mbi.RegionSize);
			continue;
		}

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

	//SetThreadPriority(GetCurrentThread(),priority);

	results->signature = SEARCH_SIG;
	results->searchType = searchType;
	sprintf(mbuf," [NFO] %d instances found, %d pages skipped\n",totalSolutionCount, skippedPages);
	outString(hPipe,mbuf);
	
	lua_pushlightuserdata(L,(void *)results);
	return 1;
}
