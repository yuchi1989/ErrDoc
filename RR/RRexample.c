#include <stdio.h>

int start_malloc(){
	int *p = malloc(sizeof(int));
	if(p == NULL) {
		return -1;
	}

	int *q = malloc(sizeof(int));
	if(q == NULL) {
		return -1;
	}
	int *k = malloc(sizeof(int));
	if(k == NULL) {
		return -1;
	}
	free(p);
	free(q);
	free(k);

	return 0;
}

int main(){
	start_malloc();	
	return 0;
}

