#include <iostream>
#include <string>
#include <windows.h>
#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>
#include <filesystem>
#include <wincrypt.h>
#include <conio.h>


#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 



using namespace std;
namespace fs = std::filesystem;

void MyHandleError(const wchar_t* psz, int nErrorNumber)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}


bool EncryptFile(fs::path file_path)
{
	// Declare and initialize local variables.
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hXchgKey = NULL;
	HCRYPTHASH hHash = NULL;

	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;

	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;

	bool fEOF = FALSE;

	// this is going to be the dst file path 
	string file_full_path = fs::absolute(file_path).string();

	string file_name = file_path.filename().string();
	// rename the src file to temp name - this the file to be encrypted
	string tmp_file_full_path = fs::path(file_full_path).replace_filename(file_name + "_tmp.txt").string();
	fs::rename(file_full_path, tmp_file_full_path);

	// convert file name to lpcwstr
	std::wstring stemp = std::wstring(file_full_path.begin(), file_full_path.end());
	LPCWSTR sw_file_full_path = stemp.c_str();

	// convert file name to lpcwstr
	std::wstring stemp2 = std::wstring(tmp_file_full_path.begin(), tmp_file_full_path.end());
	LPCWSTR sw_tmp_file_full_path = stemp2.c_str();
	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFile(
		sw_tmp_file_full_path,
		FILE_READ_DATA | FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hSourceFile)
	{
		_tprintf(
			TEXT("The source plaintext file, %s, is open. \n"),
			sw_tmp_file_full_path);
	}
	else
	{
		MyHandleError(
			TEXT("Error opening source plaintext file!\n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	//hDestinationFile = hSourceFile;
	// Open the destination file. 
	hDestinationFile = CreateFile(
		sw_file_full_path,
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hDestinationFile)
	{
		_tprintf(
			TEXT("The destination file, %s, is open. \n"),
			sw_file_full_path);
	}
	else
	{
		MyHandleError(
			TEXT("Error opening destination file!\n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Get the handle to the default provider. 
	if (CryptAcquireContext(
		&hCryptProv,       // Address for handle to be returned.
		NULL,              // Use the current user's logon name.
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,     // Need to both encrypt and sign.
		0))                // No flags needed.
	{
		_tprintf(
			TEXT("A cryptographic provider has been acquired. \n"));
	}
	else
	{
		MyHandleError(
			TEXT("Error during CryptAcquireContext!\n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}


	//-----------------------------------------------------------
		// No password was passed.
		// Encrypt the file with a random session key, and write the 
		// key to a file. 

		//-----------------------------------------------------------
		// Create a random session key. 
	if (CryptGenKey(
		hCryptProv,
		ENCRYPT_ALGORITHM,
		KEYLENGTH | CRYPT_EXPORTABLE,
		&hKey))
	{
		_tprintf(TEXT("A session key has been created. \n"));
	}
	else
	{
		MyHandleError(
			TEXT("Error during CryptGenKey. \n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}

	//-----------------------------------------------------------
	// Get the handle to the exchange public key. 
	if (CryptGetUserKey(
		hCryptProv,
		AT_KEYEXCHANGE,
		&hXchgKey))
	{
		_tprintf(
			TEXT("The user public key has been retrieved. \n"));
	}
	else
	{
		if (NTE_NO_KEY == GetLastError())
		{
			// No exchange key exists. Try to create one.
			if (!CryptGenKey(
				hCryptProv,
				AT_KEYEXCHANGE,
				CRYPT_EXPORTABLE,
				&hXchgKey))
			{
				MyHandleError(
					TEXT("Could not create "
						"a user public key.\n"),
					GetLastError());
				goto Exit_MyEncryptFile;
			}
		}
		else
		{
			MyHandleError(
				TEXT("User public key is not available and may ")
				TEXT("not exist.\n"),
				GetLastError());
			goto Exit_MyEncryptFile;
		}
	}

	//-----------------------------------------------------------
	// Determine size of the key BLOB, and allocate memory. 
	if (CryptExportKey(
		hKey,
		hXchgKey,
		SIMPLEBLOB,
		0,
		NULL,
		&dwKeyBlobLen))
	{
		_tprintf(
			TEXT("The key BLOB is %d bytes long. \n"),
			dwKeyBlobLen);
	}
	else
	{
		MyHandleError(
			TEXT("Error computing BLOB length! \n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}

	if (pbKeyBlob = (BYTE*)malloc(dwKeyBlobLen))
	{
		_tprintf(
			TEXT("Memory is allocated for the key BLOB. \n"));
	}
	else
	{
		MyHandleError(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
		goto Exit_MyEncryptFile;
	}

	//-----------------------------------------------------------
	// Encrypt and export the session key into a simple key 
	// BLOB. 
	if (CryptExportKey(
		hKey,
		hXchgKey,
		SIMPLEBLOB,
		0,
		pbKeyBlob,
		&dwKeyBlobLen))
	{
		_tprintf(TEXT("The key has been exported. \n"));
	}
	else
	{
		MyHandleError(
			TEXT("Error during CryptExportKey!\n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}

	//-----------------------------------------------------------
	// Release the key exchange key handle. 
	if (hXchgKey)
	{
		if (!(CryptDestroyKey(hXchgKey)))
		{
			MyHandleError(
				TEXT("Error during CryptDestroyKey.\n"),
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		hXchgKey = 0;
	}

	//-----------------------------------------------------------
	// Write the size of the key BLOB to the destination file. 
	if (!WriteFile(
		hDestinationFile,
		&dwKeyBlobLen,
		sizeof(DWORD),
		&dwCount,
		NULL))
	{
		MyHandleError(
			TEXT("Error writing header.\n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}
	else
	{
		_tprintf(TEXT("A file header has been written. \n"));
	}

	//-----------------------------------------------------------
	// Write the key BLOB to the destination file. 
	if (!WriteFile(
		hDestinationFile,
		pbKeyBlob,
		dwKeyBlobLen,
		&dwCount,
		NULL))
	{
		MyHandleError(
			TEXT("Error writing header.\n"),
			GetLastError());
		goto Exit_MyEncryptFile;
	}
	else
	{
		_tprintf(
			TEXT("The key BLOB has been written to the ")
			TEXT("file. \n"));
	}

	// Free memory.
	free(pbKeyBlob);

	//---------------------------------------------------------------
   // The session key is now ready. If it is not a key derived from 
   // a  password, the session key encrypted with the private key 
   // has been written to the destination file.

   //---------------------------------------------------------------
   // Determine the number of bytes to encrypt at a time. 
   // This must be a multiple of ENCRYPT_BLOCK_SIZE.
   // ENCRYPT_BLOCK_SIZE is set by a #define statement.
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

	//---------------------------------------------------------------
	// Determine the block size. If a block cipher is used, 
	// it must have room for an extra block. 
	if (ENCRYPT_BLOCK_SIZE > 1)
	{
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	}
	else
	{
		dwBufferLen = dwBlockLen;
	}

	//---------------------------------------------------------------
	// Allocate memory. 
	if (pbBuffer = (BYTE*)malloc(dwBufferLen))
	{
		_tprintf(
			TEXT("Memory has been allocated for the buffer. \n"));
	}
	else
	{
		MyHandleError(TEXT("Out of memory. \n"), E_OUTOFMEMORY);
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// In a do loop, encrypt the source file, 
	// and write to the source file. 
	fEOF = FALSE;
	do
	{
		//-----------------------------------------------------------
		// Read up to dwBlockLen bytes from the source file. 
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			MyHandleError(
				TEXT("Error reading plaintext!\n"),
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		if (dwCount < dwBlockLen)
		{
			fEOF = TRUE;
		}

		//-----------------------------------------------------------
		// Encrypt data. 
		if (!CryptEncrypt(
			hKey,
			NULL,
			fEOF,
			0,
			pbBuffer,
			&dwCount,
			dwBufferLen))
		{
			MyHandleError(
				TEXT("Error during CryptEncrypt. \n"),
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Write the encrypted data to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbBuffer,
			dwCount,
			&dwCount,
			NULL))
		{
			MyHandleError(
				TEXT("Error writing ciphertext.\n"),
				GetLastError());
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// End the do loop when the last block of the source file 
		// has been read, encrypted, and written to the destination 
		// file.
	} while (!fEOF);

	fReturn = true;

Exit_MyEncryptFile:
	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//---------------------------------------------------------------
	// Free memory. 
	if (pbBuffer)
	{
		free(pbBuffer);
	}


	//-----------------------------------------------------------
	// Release the hash object. 
	if (hHash)
	{
		if (!(CryptDestroyHash(hHash)))
		{
			MyHandleError(
				TEXT("Error during CryptDestroyHash.\n"),
				GetLastError());
		}

		hHash = NULL;
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			MyHandleError(
				TEXT("Error during CryptDestroyKey!\n"),
				GetLastError());
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			MyHandleError(
				TEXT("Error during CryptReleaseContext!\n"),
				GetLastError());
		}
	}


	// detele the tmp.txt file
	fs::remove(tmp_file_full_path);

	return fReturn;
} // End Encryptfile.


bool DecryptFile(fs::path file_path)
{
	//---------------------------------------------------------------
	// Declare and initialize local variables.
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;

	HCRYPTPROV hCryptProv = NULL;

	DWORD dwCount;
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;

	DWORD dwKeyBlobLen;
	PBYTE pbKeyBlob = NULL;

	bool fEOF = FALSE;
	// this is going to be the dst file path
	string file_full_path = fs::absolute(file_path).string();
	string file_name = file_path.filename().string();

	// rename the src file to temp name - this the file to be encrypted
	string tmp_file_full_path = fs::path(file_full_path).replace_filename(file_name + "_tmp.txt").string();
	fs::rename(file_full_path, tmp_file_full_path);
	
	// convert file name to lpcwstr
	std::wstring stemp2 = std::wstring(tmp_file_full_path.begin(), tmp_file_full_path.end());
	LPCWSTR sw_tmp_file_full_path = stemp2.c_str();

	// convert file name to lpcwstr
	std::wstring stemp = std::wstring(file_full_path.begin(), file_full_path.end());
	LPCWSTR sw_file_full_path = stemp.c_str();


	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFile(
		sw_tmp_file_full_path,
		FILE_READ_DATA | FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hSourceFile)
	{
		_tprintf(
			TEXT("The source encrypted file, %s, is open. \n"),
			sw_tmp_file_full_path);
	}
	else
	{
		MyHandleError(
			TEXT("Error opening source plaintext file!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	//---------------------------------------------------------------
	// Open the destination file. 
	hDestinationFile = CreateFile(
		sw_file_full_path,
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hDestinationFile)
	{
		_tprintf(
			TEXT("The destination file, %s, is open. \n"),
			sw_file_full_path);
	}
	else
	{
		MyHandleError(
			TEXT("Error opening destination file!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	//---------------------------------------------------------------
	// Get the handle to the default provider. 
	if (CryptAcquireContext(
		&hCryptProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		0))
	{
		_tprintf(
			TEXT("A cryptographic provider has been acquired. \n"));
	}
	else
	{
		MyHandleError(
			TEXT("Error during CryptAcquireContext!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	//---------------------------------------------------------------
	// Create the session key.
	
	//-----------------------------------------------------------
	// Decrypt the file with the saved session key. 
	// Read the key BLOB length from the source file. 
	if (!ReadFile(
		hSourceFile,
		&dwKeyBlobLen,
		sizeof(DWORD),
		&dwCount,
		NULL))
	{
		MyHandleError(
			TEXT("Error reading key BLOB length!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	// Allocate a buffer for the key BLOB.
	if (!(pbKeyBlob = (PBYTE)malloc(dwKeyBlobLen)))
	{
		MyHandleError(
			TEXT("Memory allocation error.\n"),
			E_OUTOFMEMORY);
	}

	//-----------------------------------------------------------
	// Read the key BLOB from the source file. 
	if (!ReadFile(
		hSourceFile,
		pbKeyBlob,
		dwKeyBlobLen,
		&dwCount,
		NULL))
	{
		MyHandleError(
			TEXT("Error reading key BLOB length!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	//-----------------------------------------------------------
	// Import the key BLOB into the CSP. 
	if (!CryptImportKey(
		hCryptProv,
		pbKeyBlob,
		dwKeyBlobLen,
		0,
		0,
		&hKey))
	{
		MyHandleError(
			TEXT("Error during CryptImportKey!/n"),
			GetLastError());
		goto Exit_MyDecryptFile;
	}

	if (pbKeyBlob)
	{
		free(pbKeyBlob);
	}

	//---------------------------------------------------------------
	// The decryption key is now available, either having been 
	// imported from a BLOB read in from the source file or having 
	// been created by using the password. This point in the program 
	// is not reached if the decryption key is not available.

	//---------------------------------------------------------------
	// Determine the number of bytes to decrypt at a time. 
	// This must be a multiple of ENCRYPT_BLOCK_SIZE. 

	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	dwBufferLen = dwBlockLen;

	//---------------------------------------------------------------
	// Allocate memory for the file read buffer. 
	if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
	{
		MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
		goto Exit_MyDecryptFile;
	}

	//---------------------------------------------------------------
	// Decrypt the source file, and write to the destination file. 
	fEOF = false;
	do
	{
		//-----------------------------------------------------------
		// Read up to dwBlockLen bytes from the source file. 
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			MyHandleError(
				TEXT("Error reading from source file!\n"),
				GetLastError());
			goto Exit_MyDecryptFile;
		}

		if (dwCount <= dwBlockLen)
		{
			fEOF = TRUE;
		}

		//-----------------------------------------------------------
		// Decrypt the block of data. 
		if (!CryptDecrypt(
			hKey,
			0,
			fEOF,
			0,
			pbBuffer,
			&dwCount))
		{
			MyHandleError(
				TEXT("Error during CryptDecrypt!\n"),
				GetLastError());
			goto Exit_MyDecryptFile;
		}

		//-----------------------------------------------------------
		// Write the decrypted data to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbBuffer,
			dwCount,
			&dwCount,
			NULL))
		{
			MyHandleError(
				TEXT("Error writing ciphertext.\n"),
				GetLastError());
			goto Exit_MyDecryptFile;
		}

		//-----------------------------------------------------------
		// End the do loop when the last block of the source file 
		// has been read, encrypted, and written to the destination 
		// file.
	} while (!fEOF);

	fReturn = true;

Exit_MyDecryptFile:

	//---------------------------------------------------------------
	// Free the file read buffer.
	if (pbBuffer)
	{
		free(pbBuffer);
	}

	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//-----------------------------------------------------------
	// Release the hash object. 
	if (hHash)
	{
		if (!(CryptDestroyHash(hHash)))
		{
			MyHandleError(
				TEXT("Error during CryptDestroyHash.\n"),
				GetLastError());
		}

		hHash = NULL;
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			MyHandleError(
				TEXT("Error during CryptDestroyKey!\n"),
				GetLastError());
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			MyHandleError(
				TEXT("Error during CryptReleaseContext!\n"),
				GetLastError());
		}
	}

	// detele the tmp file
	fs::remove(tmp_file_full_path);

	return fReturn;
}



void ProcessFile(fs::path file_path, string& mode)
{
	std::cout << "in process file: " << file_path.filename().string() << '\n';
	if (_stricmp(mode.c_str(), "Encrypt") == 0)
	{
		bool res_encrypt = EncryptFile(file_path);
		if (!res_encrypt)
		{
			MyHandleError(
				TEXT("Error encrypting file!\n"),
				GetLastError());
		}
	}
	else if (_stricmp(mode.c_str(), "Decrypt") == 0)
	{
		bool res_decrypt = DecryptFile(file_path);
		if (!res_decrypt)
		{
			MyHandleError(
				TEXT("Error decrypting file!\n"),
				GetLastError());
		}
	}
}

// encrypt .txt file in dir recursively
void IterateDir(string& dir_path, string& mode)
{
	std::vector<std::thread> futures;

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
					futures.emplace_back(ProcessFile, std::ref(iterEntry->path()), std::ref(mode));
				}
			}
			else
				std::cout << "??    " << filenameStr << '\n';
		}
		// wait for all the file processing to finish
		for (auto& future : futures) {
			// Blocks until the result becomes available
			future.join();
			
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
	if (argc < 3)
	{
		_tprintf(TEXT("Usage: <target dir> <mode: Encrypt or Decrypt> \n"));
		return 1;
	}

	string dir_name = argv[1];
	string mode = argv[2];

	if (_stricmp(mode.c_str(), "Encrypt") != 0  && _stricmp(mode.c_str(), "Decrypt") != 0)
	{
		_tprintf(TEXT("Usage: <target dir> <mode: Encrypt or Decrypt> \n"));
		return 1;
	}

	if (!fs::is_directory(dir_name))
	{
		_tprintf(
			TEXT("The input dir %s, is not a directory or doen't exist. \n"),
			dir_name);
		_tprintf(TEXT("Usage: <target dir> <mode: Encrypt or Decrypt> \n"));
		return 1;
	}


	IterateDir(dir_name, mode);

}

