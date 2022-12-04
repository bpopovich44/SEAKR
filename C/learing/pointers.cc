#include <iostream>
//#include <string>

using namespace std;
// References
int main(){

	string food = "Pizza";
	string &meal = food;
	cout << "Food is " << food << "\n";
	cout << "memory address for food is " << &food << "\n";
	cout << "&meal referenceing food is " << meal << "\n";
	cout << "\n\n\n";

	string car = "mustang";
	string* ptr = &car;

	cout << "Variable car--> " << car << "\n";
	cout << "Address of variable car--> " << &car << "\n";
	cout << "Referencing memory address of ptr is--> " << ptr << "\n";
	cout << "Dereference ptr--> " << *ptr << "\n";

	*ptr = "corvette";
	cout << "Change value of car to corvette--> " << *ptr << "\n";

	return 0;
}
