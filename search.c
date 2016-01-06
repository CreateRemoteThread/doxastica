#include <stdio.h>
#include <windows.h>
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