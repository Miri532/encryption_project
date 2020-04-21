#include <iostream>
#include <string>
#include <windows.h>
#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>
#include <filesystem>
#include "encryption_project.h"

using namespace std;
namespace fs = std::filesystem;

void process_file(fs::path file_path, string& mode)
{
	std::cout << "in process file: " << file_path.filename().string() << '\n';
}

// encrypt .txt file in dir recursively
void iterate_dir(string& dir_path, string& mode)
{
	try {
		const fs::path pathToShow{ dir_path };

		for (auto iterEntry = fs::recursive_directory_iterator(pathToShow); iterEntry != fs::recursive_directory_iterator(); ++iterEntry) {
			const auto filenameStr = iterEntry->path().filename().string();
			std::cout << std::setw(iterEntry.depth() * 3) << "";
			if (iterEntry->is_directory()) {
				std::cout << "dir:  " << filenameStr << '\n';
			}
			else if (iterEntry->is_regular_file()) {
				std::cout << "file: " << filenameStr << '\n';
				if (_stricmp(iterEntry->path().extension().string().c_str(), ".txt") == 0)
				{
					process_file(iterEntry->path(), mode);
				}
			}
			else
				std::cout << "??    " << filenameStr << '\n';
		}
	}
	catch (const fs::filesystem_error & err) {
		std::cerr << "filesystem error! " << err.what() << '\n';
		if (!err.path1().empty())
			std::cerr << "path1: " << err.path1().string() << '\n';
		if (!err.path2().empty())
			std::cerr << "path2: " << err.path2().string() << '\n';
	}
	catch (const std::exception & ex) {
		std::cerr << "general exception: " << ex.what() << '\n';
	}

}


int main(int argc, char** argv)
{
	string dir_name = argv[1];
	string mode = argv[2];

	iterate_dir(dir_name, mode);

}

