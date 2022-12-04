#include <iostream> // header files
#include <string>
#include <stdlib.h>
#include <cstdlib> // for rand()
#include <ctime> // for srand()
#include <cstdio> // need for printf()
#define RESET "\033[0m" // preprocessing or directives
#define BOLDCYAN "\033[1m\033[36m"
#define BOLDYELLOW "\033[1m\033[33m"
#define BOLDGREEN "\033[1m\033[32m"
#define BOLDMAGENTA "\033[1m\033[35m"
#define BOLDWHITE "\033[1m\033[37m"
#define BOLDBLUE "\033[1m\033[34m"
#define BOLDRED "\033[1m\033[31m"
#define BOLDBLACK "\033[1m\033[30m"

using namespace std;

/////////////////////////////////////////////////////////////
//
//   Battleship game written for Dominic
//
/////////////////////////////////////////////////////////////


class Games{
	public:

	// Battleship variables
	int hit;
	int numOfTurn;

	// Guess number variables
	int num;



	// Constructor
	Games(int n){
		num = n;

	}
};


void guess_a_number(){

	// Variables
	int num, guess, tries = 0;
	char welcome_banner[] = "Welcome to the number guessing game.\n";
	char welcome_line[] = "====================================\n";
	int low = 0; // low number
	int high = 20; // high number

	// Pointers
	

	srand(time(0));  // seed random number generator
	num = rand() % 20 + 1;  // random number between 1 and 20
	
	system("clear");

	printf(BOLDCYAN "%s" RESET, welcome_banner);
	printf(BOLDWHITE "%s" RESET, welcome_line);
	do{
	  	printf(BOLDYELLOW "\nEnter a guess between " RESET BOLDWHITE "%d " RESET BOLDYELLOW "and " RESET\
			       	BOLDWHITE "%d " RESET BOLDYELLOW "--> " RESET, low, high);
		cin >> guess;
		tries++;

		if (guess > num)
			printf(BOLDYELLOW "\nYou guessed too " RESET BOLDRED "HIGH! " RESET);
		else if (guess < num)
			printf(BOLDYELLOW "\nYou guessed too " RESET BOLDBLUE "LOW! " RESET);
		else
			printf(BOLDGREEN "\nCORRECT!  You guessed in " RESET BOLDCYAN "%d " RESET BOLDGREEN "tries.\n\n" RESET , tries);
	}while (guess != num);
}






// variables
int hits = 0;
int numOfTurns = 0;

// pointers
int* h = &hits;
int* n = &numOfTurns;

// Multidimensional array of ship layout: 1 indicates where ship is
bool ships[4][5] = {
	{ 0, 0, 1, 1, 0 },  // dont put ship in 1st column
	{ 0, 0, 0, 0, 0 },
	{ 0, 0, 0, 1, 0 },
	{ 0, 0, 0, 1, 0 }
};

// Board size multi-dimentional array
string board_grid[4][5];

int board_layout(int x, int y, int i){

	// Variables
	int row = x;
	int column = y;
	string M = BOLDRED "M  " RESET;
	string H = BOLDGREEN "H  " RESET;

	// Pointers
	int* r = &row;
	int* c = &column;
	string* m = &M;
	string* h = &H;

	switch(i) {
		case 1:
			board_grid[*r][*c] = *h;
			break;
		case 2:
			board_grid[*r][*c] = *m;
			break;
	}

	printf("\t\t\t\t\t\t\t\t\t\t" BOLDWHITE"1          2          3          4     " RESET "\n");
	printf("\t\t\t\t\t\t\t\t\t" BOLDYELLOW "  ---------------------------------------------" RESET "\n");
	
	for(int i = 0; i < 4; i++){
		cout << "\t\t\t\t\t\t\t\t";
		for(int j = 0; j < 5; j++){
			string k = board_grid[i][j];
			cout << "     " << BOLDWHITE << k << RESET  << BOLDYELLOW "  |" RESET;
		}
		printf("\n\t\t\t\t\t\t\t\t\t" BOLDYELLOW "  ---------------------------------------------" RESET);
		cout << "\n";
			}
	return 0;
	}

// Banners
void game_banner(){
	printf("\t\t\t\t" BOLDYELLOW "=======================================================  " RESET BOLDCYAN "BATTLESHIP" \
			RESET BOLDYELLOW "  ========================================================" RESET "\n\n");
}


void start_banner(){
	system("clear");
	game_banner();	
	printf("\n\n\t\t\t\t\t\t\t\t\t   " BOLDCYAN "Hello Dominic, ready to play Battleship!" RESET "\n");
	printf("\t\t\t\t\t\t\t\t" BOLDCYAN "Here is your grid. There are " RESET BOLDYELLOW "4" RESET BOLDCYAN\
		       	" ships... Select coordinates..." RESET "\n\n");
}


void end_banner(){
	printf("\n\n\n\t\t\t\t\t\t\t\t\t\t\t     " BOLDGREEN "Victory!\n " RESET BOLDYELLOW\
		       	"\t\t\t\t\t\t\t\t\t\t    You SUNK MY BATTLESHIP!!!" RESET "\n");
	printf("\t\t\t\t\t\t\t\t\t\t\t" BOLDYELLOW "You won in " RESET BOLDWHITE  "%d " RESET BOLDYELLOW "turns" RESET "\n\n\n", *n);
}





/*
// Number Guessing Game
void guess_a_number(){

	int num, guess, tries = 0;
	srand(time(0));  // seed random number generator
	num = rand() % 20 + 1;  // random number between 1 and 20
	
	system("clear");

	cout << "Welcome to the number guessing game.\n";
	cout << "====================================\n";
	do{
		cout << "\nEnter a guess between 0 and 20--> ";
		cin >> guess;
		tries++;

		if (guess > num)
			cout << "\nYou guessed too high!";
		else if (guess < num)
			cout << "\nYou guessed to low...";
		else
			cout << "\nCorrect!  You guessed correct in " << tries << " tries.\n";
	}while (guess != num);

}
*/
void battleship(){

	// Variables
	int row, column;
	char rowin;
	int one = 1; // hit
	int two = 2; // miss
	int three = 3; // default layout

	// Pointers
	int* r = &row;
	int* co = &column; // have to do a plus on input to skip first column
	char* ro = &rowin;
	int* on = &one;
	int* tw = &two;
	int* th = &three;

	// Board layout
	board_grid[0][0] = "A  ";
	board_grid[0][1] = "*  ";
	board_grid[0][2] = "*  ";
	board_grid[0][3] = "*  ";
	board_grid[0][4] = "*  ";
	board_grid[1][0] = "B  ";
	board_grid[1][1] = "*  ";
	board_grid[1][2] = "*  ";
	board_grid[1][3] = "*  ";
	board_grid[1][4] = "*  ";
	board_grid[2][0] = "C  ";
	board_grid[2][1] = "*  ";
	board_grid[2][2] = "*  ";
	board_grid[2][3] = "*  ";
	board_grid[2][4] = "*  ";
	board_grid[3][0] = "D  ";
	board_grid[3][1] = "*  ";
	board_grid[3][2] = "*  ";
	board_grid[3][3] = "*  ";
	board_grid[3][4] = "*  ";

	start_banner();

	// Print initial board layout
	board_layout(*r, *co, *th);
	
	// Begin game
	while (*h < 4){

		// Ask for a row
		printf("\n\t\t\t\t\t\t\t\t\t" BOLDCYAN "   Choose a row number between " RESET BOLDWHITE "A " RESET BOLDCYAN "and "\
			       	RESET BOLDWHITE "D --> "RESET);
		cin >> *ro;
		if (*ro == 'a' or *ro == 'A'){
			*r = 0;
		}else if (*ro == 'b' or *ro =='B'){
			*r = 1;
		}else if (*ro == 'c' or *ro == 'C'){
			*r = 2;
		}else if (*ro == 'd' or *ro == 'D'){
			*r = 3;
		}

		
		// Ask for a column
		printf("\t\t\t\t\t\t\t\t\t   " RESET BOLDCYAN "Choose a column number between " RESET BOLDWHITE "1 " RESET BOLDCYAN "and "\
			       	RESET BOLDWHITE "4 --> " RESET);;
		cin >> *co;
		


		while(*co < 1 || *co > 4){
			cin.clear(); // clear input flag
			printf("\t\t\t\t\t\t\t\t\t   " BOLDRED "Invalid entry, Choose a column number between " RESET BOLDWHITE "1 "\
				       	RESET BOLDRED "and " RESET BOLDWHITE "4 " RESET BOLDRED "--> " RESET);
			cin >> *co;
			}
	
/*
		while(true){
			// Ask for a column
			printf("\t\t\t\t\t\t\t\t\t   " RESET BOLDCYAN "Choose a column number between " RESET BOLDWHITE "1 " RESET BOLDCYAN "and "\
			       	RESET BOLDWHITE "4 --> " RESET);;
			cin >> *co;
			
			cin.ignore();
			for(int i = 0; i < *co.size(); i++)
				if(isdigit(*co[i]){
						while(*co < 1 || *co > 4){
							cin.clear(); // clear input flag
							printf("\t\t\t\t\t\t\t\t\t   " BOLDRED "Invalid entry, Choose a column number between " RESET BOLDWHITE "1 "\
				       				RESET BOLDRED "and " RESET BOLDWHITE "4 " RESET BOLDRED "--> ");
						cin >> *co;
						}

				}else{
					continue
					}


			}


*/


		if(ships[*r][*co]){
			system("clear");
	
			// If ship hit, place to zero and change board grid
			ships[*r][*co] = 0;
			
			game_banner();
	
			board_layout(*r, *co, *on);
			
			// increase counter
			(*h)++;
			printf("\n\t\t\t\t\t\t\t\t\t\t" BOLDWHITE "--->   " RESET BOLDGREEN "HIT!  " RESET BOLDWHITE "<---   "  RESET\
				       	BOLDGREEN "%d" RESET BOLDWHITE " ships left." RESET "\n\n", (4-*h));
			}else{
			system("clear");
			
			game_banner();
			
			board_layout(*r, *co, *tw);

			printf("\n\t\t\t\t\t\t\t\t\t\t     " BOLDWHITE " --->    " RESET BOLDRED "MISS!   " RESET BOLDWHITE "<---" RESET "\n\n");
			}

		(*n)++;
		}
	end_banner();
	}




// Main function
int main(){
	system("clear");

	// Variables
	int num;

	// Pointers
	int* n = &num;

	do{
		printf(BOLDGREEN "Would you like to play a game?  Choose a game from below" RESET "\n");
		printf(BOLDWHITE "========================================================" RESET "\n\n\n");
		printf(BOLDCYAN "Battleship: " RESET BOLDYELLOW "1 " RESET "\n");
		printf(BOLDCYAN "Guess a number: " RESET BOLDYELLOW "2 " RESET "\n");
		printf(BOLDGREEN "\n\nEnter game " RESET BOLDWHITE "# " RESET BOLDGREEN "for game.  Press " RESET BOLDWHITE "3 "\
			       	RESET BOLDGREEN "to quit --> " RESET);
		cin >> *n;

		if(*n == 1)
			battleship();
		else if(*n == 2)
			guess_a_number();
		else if(*n == 3)
			printf(BOLDYELLOW "\n\nThanks for playing!\n" RESET);
			exit(0);
	}while(*n >=1 || *n <=3);

	return 0;
}
