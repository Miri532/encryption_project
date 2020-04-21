#include <iostream>
#include <string>
#include "encryption_project.h"

using namespace std;

void encrypt_dir(string& dir_name)
{

}

void decrypt_dir(string& dir_name)
{

}

int main(int argc, char** argv)
{
	string dir_name = argv[1];
	string mode = argv[2];

	if (mode == "encrypt")
	{
		encrypt_dir(dir_name);
	}

	if (mode == "decrypt")
	{
		decrypt_dir(dir_name);
	}
}

