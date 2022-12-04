#include <iostream>
#include <stdlib.h>
#include <cstdio>
#define RESET "\033[0m"
#define BOLDCYAN "\033[1m\033[36m"
#define BOLDYELLOW "\033[1m\033[33m"


using namespace std;

int main(){

	//cout << "hello world!\n";

	//system("Color E4");

	//printf("\033[0;31m"); // red
	printf("\033[1m\033[36m"); // red
	printf("hello world\n");
	printf("\033[0m");

	printf( BOLDYELLOW "HELLOW WORLD!!!" RESET);




	return 0;
}
