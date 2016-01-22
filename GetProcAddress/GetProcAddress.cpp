// WinTestApp.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "intrin.h"
#include "defines.h"
#include <malloc.h>

PTIB GetTIB();
PPEB GetPEB();
PLDR_DATA_TABLE_ENTRY GetLdrDataTableEntry(wchar_t* dllName);
bool LibraryLoaded(wchar_t* dllName);
void *GetProcAddress(wchar_t* dllName, wchar_t* procName);
void *_LoadLibraryW(wchar_t* dllName);
bool StringContains(wchar_t* haystack, wchar_t* needle);
bool StringMatches(wchar_t* str1, wchar_t* str2);
int StringLengthW(wchar_t* str);
int StringLengthA(char* str);
wchar_t* CharToWChar_T(char* str);
wchar_t** ParseForwardString(char* str);
wchar_t ToLowerW(wchar_t ch);
char ToLowerA(char ch);

int _tmain(int argc, _TCHAR* argv[])
{	
	//Test Case - forwarded function in kernel not loaded
	void *test = GetProcAddress(L"kernel32.dll", L"AddDllDirectory");

	return 0;
}

/*
* _LoadLibraryW
*
* Use: Load DLL into Process Memory
* Parameters: wchar_t string with DLL Path
* Return: void* to DLL Base
*/
void *_LoadLibraryW(wchar_t* dllName) {
	void*(*__LoadLibraryW)(wchar_t*);
	__LoadLibraryW = (void*(*)(wchar_t*))GetProcAddress(L"kernel32.dll", L"LoadLibraryW");

	if (__LoadLibraryW == nullptr) {
		return nullptr;
	}

	void* dllBase = __LoadLibraryW(dllName);

	return dllBase;
}

/*
* GetProcAddress
*
* Use: Independent GetProcAddress using TIB/PEB/LDR
* Parameters: wchar_t string with DLL Name, wchar_t string with Function Name
* Return: void* to Function - nullptr if not found
*/
void *GetProcAddress(wchar_t* dllName, wchar_t* procName) {
	void *procAddr = nullptr;

	//Get Table Entry for DLL
	PLDR_DATA_TABLE_ENTRY dllEntry = GetLdrDataTableEntry(dllName);

	if (dllEntry == nullptr) {
		return nullptr;
	}

	//DllBase as unsigned long for arithmetic
	unsigned long long dllBaseAddr = (unsigned long long)dllEntry->DllBase;

	//Cast DllBase to use struct
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBaseAddr; 
	
	//Calculate NTHeader and Cast
	PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)(dllBaseAddr + dosHeader->lfanew);

	//Calculate ExportDir Address and Cast
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBaseAddr + pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

	//Calculate AddressOfNames Absolute and Cast
	unsigned int *NameRVA = (unsigned int*)(dllBaseAddr + pExportDir->AddressOfNames);

	//Iterate over AddressOfNames
	for (int i = 0; i < pExportDir->NumberOfNames; i++) {
		//Calculate Absolute Address and cast
		char* name = (char*)(dllBaseAddr + NameRVA[i]);
		wchar_t *wname = CharToWChar_T(name);
		if (StringMatches(wname, procName)) {
			free(wname);

			//Lookup Ordinal
			unsigned short NameOrdinal = ((unsigned short*)(dllBaseAddr + pExportDir->AddressOfNameOrdinals))[i];

			//Use Ordinal to Lookup Function Address and Calculate Absolute
			unsigned int addr = ((unsigned int*)(dllBaseAddr + pExportDir->AddressOfFunctions))[NameOrdinal];
			
			//Function is forwarded
			if (addr > pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress && addr < pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + pNtHeader->OptionalHeader.DataDirectory[0].Size) {
				//Grab and Parse Forward String
				char* forwardStr = (char*)(dllBaseAddr + addr);

				wchar_t** str_arr = ParseForwardString(forwardStr);

				//Attempt to load library if not loaded
				if (!LibraryLoaded(str_arr[0])) {
					void* dllBase = _LoadLibraryW(str_arr[0]);
				}

				//Recurse using forward information
				procAddr = GetProcAddress(str_arr[0], str_arr[1]);
				free(str_arr[0]);
				free(str_arr[1]);
				free(str_arr);
			}
			else {
				procAddr = (void*)(dllBaseAddr + addr);
			}
			break;
		}
		if (wname != nullptr) {
			free(wname);
		}
	}
	return procAddr;
}

/*
 * LibraryLoaded
 *
 * Use: Check if a DLL is loaded into memory
 * Parameters: wchar_t string DLL Name
 * Return: Bool for whether DLL is loaded in Process Memory
 */
bool LibraryLoaded(wchar_t* dllName) {
	return GetLdrDataTableEntry == nullptr;
}

/*
 * GetLdrDataTableEntry
 * 
 * Use: Get LdrDataTableEntry corresponding to dllName using Thread Information Block
 *		then Program Execution Block
 * Parameters: wchar_t string containing DLL Name
 * Return: PLDR_DATA_TABLE_ENTRY corresponding to dllName
 */
PLDR_DATA_TABLE_ENTRY GetLdrDataTableEntry(wchar_t* dllName) {
	PTIB pTIB = GetTIB();
	PPEB pPEB = pTIB->pPEB;

	PLIST_ENTRY moduleListTail = &pPEB->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY moduleList = moduleListTail->Flink;

	do {
		unsigned char* modulePtrWithOffset = (unsigned char*)moduleList - (sizeof(LIST_ENTRY));

		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)modulePtrWithOffset;
		if (StringContains(entry->BaseDllName.buffer, dllName)) {
			return entry;
		}
		moduleList = moduleList->Flink;
	} while (moduleList != moduleListTail);

	return nullptr;
}

/*
 * ParseForwardString 
 *
 * Use: Parse the Forward String retrieved from AddressOfFunctions in IMAGE_EXPORT_DIRECTORY
 * Parameters: char forward string
 * Return: array of wchar_t strings, first string holding dllname and second holding function name
 */
wchar_t** ParseForwardString(char* str) {
	if (str == nullptr) {
		return nullptr;
	}
	wchar_t** str_arr = (wchar_t**)malloc(sizeof(wchar_t*)* 2);

	int length = StringLengthA(str);

	int firstLength;

	for (firstLength = 0; str[firstLength] != '.'; firstLength++) {}

	int secondLength = length - firstLength - 1;

	str_arr[0] = (wchar_t*)malloc(sizeof(wchar_t)*firstLength + 2 + 4);
	str_arr[1] = (wchar_t*)malloc(sizeof(wchar_t)*secondLength + 2);

	for (int i = 0; i < length; i++) {
		if (i < firstLength) {
			str_arr[0][i] = ToLowerA(str[i]);
		}
		if (i > firstLength) {
			str_arr[1][i - 1 - firstLength] = ToLowerA(str[i]);
		}
	}
	str_arr[0][firstLength] = '\0';
	str_arr[0][firstLength + 1] = '.';
	str_arr[0][firstLength + 1] = 'd';
	str_arr[0][firstLength + 1] = 'l';
	str_arr[0][firstLength + 1] = 'l';
	str_arr[1][secondLength] = '\0';
	return str_arr;
}

/*
* StringMatches
*
* Use: Case Insensitive String Compare
* Parameters: two wchar_t strings
* Return: Result of wchar_t equality
*/
bool StringMatches(wchar_t* str1, wchar_t* str2) {
	if (str1 == nullptr || str2 == nullptr || StringLengthW(str1) != StringLengthW(str2)) {
		return false;
	}
	
	for (int i = 0; str1[i] != '\0' && str2[i] != '\0'; i++) {
		if (ToLowerW(str1[i]) != ToLowerW(str2[i])) {
			return false;
		}
	}
	return true;
}

/*
* StringContains
*
* Use: Case Insensitive String Contains Check
* Parameters: wchar_t string to search, wchar_t string to search for
* Return: Result of wchar_t equality
*/
bool StringContains(wchar_t* haystack, wchar_t* needle) {
	if (haystack == nullptr || needle == nullptr) {
		return false;
	}

	for (int i = 0; haystack[i] != '\0'; i++) {
		if (ToLowerW(haystack[i]) == ToLowerW(needle[0])) {
			bool found = true;
			for (int j = 1; needle[j] != '\0'; j++) {
				if (ToLowerW(haystack[i + j]) != ToLowerW(needle[j])) {
					found = false;
				}
			}
			if (found) {
				return true;
			}
		}
	}
	return false;
}

/*
* StringLengthW
*
* Use: Retrieve length of wchar_t string
* Parameters: wchar_t string
* Return: Length of string
*/
int StringLengthW(wchar_t* str) {
	int length;

	for (length = 0; str[length] != '\0'; length++) {}
	return length;
}

/*
* StringLengthA
*
* Use: Retrieve length of char string
* Parameters: char string
* Return: Length of string
*/
int StringLengthA(char* str) {
	int length;

	for (length = 0; str[length] != '\0'; length++) {}
	return length;
}

/*
* CharToWChar_T
*
* Use: Convert char string to wchar_t string - caller responsible for freeing memory
* Parameters: char string
* Return: wchar_t string
*/
wchar_t* CharToWChar_T(char* str) {
	int length = StringLengthA(str);

	if (str == nullptr) {
		return nullptr;
	}

	wchar_t *wstr_t = (wchar_t*)malloc(sizeof(wchar_t)*length+2);

	for (int i = 0; i < length; i++) {
		wstr_t[i] = str[i];
	}
	wstr_t[length] = '\0';
	return wstr_t;
}

/*
* ToLowerW
*
* Use: Convert char to lower case if necessary
* Parameters: char
* Return: char
*/
wchar_t ToLowerW(wchar_t ch) {
	if (ch > 0x40 && ch < 0x5B) {
		return ch + 0x20;
	}
	return ch;
}

/*
* ToLowerA
*
* Use: Convert char to lower case if necessary
* Parameters: char
* Return: char
*/
char ToLowerA(char ch) {
	if (ch > 96 && ch < 123) {
		ch -= 32;
	}
	return ch;
}

/*
* GetTIB
*
* Use: Retrieve Pointer to Thread Information Block from GS Register(x64)
* Parameters: None
* Return: Pointer to Thread Information Block
*/
PTIB GetTIB() {
	return (PTIB)__readgsqword(0x30);
}

/*
* GetPEB
*
* Use: Retrieves Pointer to Program Execution Block from GS Register(x64)
* Parameters: None
* Return: Pointer to Program Execution Block
*/
PPEB GetPEB() {
	return (PPEB)__readgsqword(0x60);
}
