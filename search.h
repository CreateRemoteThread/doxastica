
// store "a set" of search results

#define CHUNK_ALLOC_SIZE 1024

struct searchResult
{
	int numSolutions;
	int numSolutionsMaximum;
	UINT_PTR *arraySolutions;
};

int page_search_dword(UINT_PTR d,int pageSize,int *solutionCount, UINT_PTR *solutions, DWORD valueToSearch);
int search_filter_dword(searchResult *m, DWORD newvalue);
searchResult *mergeResults(searchResult *m, int solutionCount, UINT_PTR *solns);