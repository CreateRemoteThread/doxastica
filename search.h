
// store "a set" of search results

#define SEARCH_SIG 0x45464748
#define CHUNK_ALLOC_SIZE 1024

// fireball!
#define SEARCH_DWORD 4
#define SEARCH_WORD 2
#define SEARCH_BYTE 1

struct searchResult
{
	DWORD signature;
	int searchType;
	int numSolutions;
	int numSolutionsMaximum;
	UINT_PTR *arraySolutions;
};

int page_search_dword(UINT_PTR d,int pageSize,int *solutionCount, UINT_PTR *solutions, DWORD valueToSearch);
int page_search_word(UINT_PTR d,int pageSize,int *solutionCount, UINT_PTR *solutions, WORD valueToSearch);
int page_search_byte(UINT_PTR d,int pageSize,int *solutionCount, UINT_PTR *solutions, BYTE valueToSearch);
int search_filter_dword(searchResult *m, DWORD newvalue);
int search_filter_word(searchResult *m, WORD newvalue);
int search_filter_byte(searchResult *m, BYTE newvalue);
searchResult *mergeResults(searchResult *m, int solutionCount, UINT_PTR *solns);
int validateSearchResult(searchResult *m);