#include <stdio.h>

int f1(){
	return 0;
}

int f2(){
	return 0;
}
int test_path(){
	int *p = malloc(sizeof(int));
	if(p == NULL) {
		f1();
		f2();
		return -1;
	}
	free(p);
	return 0;
}

int main(){
	test_path();
	return 0;
}

