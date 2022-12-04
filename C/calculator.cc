#include <iostream>
using namespace std;


class Calculator
{
	int num1;
	int num2;
	int answer;
}


int addNum(int x, int y)
{
	return x + y;
}

int main()
{
	cout << "Enter a number to add --> ";
	cin >> num1;
	cout << "Enter another number to add --> ";
	cin >> num2;
	
	cout << "The answer is : " << addNum(num1, num2) << "\n";
	return 0;
}
