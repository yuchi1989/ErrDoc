int bar(){
	return 0;//error: <=0
}
int foo(){
	int r = bar();
	if(r <= 0){
		return -1;
	}
	return 0;
}

int main(){
	foo();
	return 0;
}

