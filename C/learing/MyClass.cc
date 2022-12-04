#include <iostream>

using namespace std;

// Create class
class MyClass {
	public:

/*		string brand;
		string model;
		string color;
		int year;
*/		
		// for constructor
		string transmission;
		string convertable;

		MyClass(string x, string c){
			transmission = x;
			convertable = c;
		}
		
		void BMW(){
			cout << "First Car is BMW" << "\n";
		}

		void Mustang(){
			cout << "Second Car is Mustang" << "\n";
		}
};


int main() {

	// Create object of MyClass
/*	MyClass carObj1;
	MyClass carObj2;

	// Access attributes of my class and set values
	carObj1.brand = "BMW";
	carObj1.model = "M3";
	carObj1.color = "Black";
	carObj1.year = 2006;
	
	carObj2.brand = "Ford";
	carObj2.model = "Mustang";
	carObj2.color = "Black";
	carObj2.year = 1965;


	carObj1.BMW();
	cout << "Brand: " << carObj1.brand << " Model: " << carObj1.model << " Color: " << carObj1.color << " Year: " << carObj1.year << "\n";
	// call constructor

	carObj2.Mustang();
*/	cout << "Brand: " << carObj2.brand << " Model: " << carObj2.model << " Color: " << carObj2.color << " Year: " << carObj2.year << "\n";


	cout << "Transmission: " << carObj3.transmission << "Convertable: " << carObj3.convertable << "\n";
	cout << "Transmission: " << carObj4.transmission << "Convertable: " << carObj4.convertable << "\n";
	
	// Create car objects and call constructor with values
	MyClass carObj3("manual", "yes");
	MyClass carObj4("manual", "no");
	return 0;
}
