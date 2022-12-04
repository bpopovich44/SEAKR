#include <iostream> // Header file library for input/output objects
#include <string>

using namespace std; // can use names for objects and variables from standard library.

int integer_value = 5.99;
double double_value = 2.99;
char char_value = 'a';
string string_value = "reaper";
string string_value2 = "team";
string total_length = string_value.append(string_value2).length();
bool boolean_value = false;



int main()
{
	cout << "hello world! \n";
	//std:: cout << "Hello World!" << "\n";
	cout << "int value is--> " << integer_value << "\n";
	cout << "char value is--> " << char_value << "\n";
	cout << "double value is--> " << double_value << "\n";
	cout << "string value is--> " << string_value << "\n";
	cout << "string concatonated is--> " << string_value.append(string_value2) << "\n";
	cout << "string size of reaperteam is--> " << total_length << "\n";
	cout << "bool value is--> " << boolean_value << "\n";
	
	
	struct {			// Structure declaration
		int myNum;		// Member (int variable)
		string myString;	// Member (String Variable)
	} myStructure;			// Structure variable name

	// Assign values to member os myStructure
	myStructure.myNum = 1;
	myStructure.myString = "hello world";

	// Print member values of myStructure
	cout << myStructure.myNum << "\n";
	cout << myStructure.myString << "\n";
	
	
	
	
	
	
	
	
	return 0;
}
