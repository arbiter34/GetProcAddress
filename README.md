# GetProcAddress
Recreation of GetProcAddress without external dependencies on Windows Libraries

# Use
```_LoadLibraryW(wstr_t)``` contains an example of how to use GetProcAddress and cast the function pointer to a function properly(?ha).

#What does it really do?
Uses GS register on x64 systems to retrieve a pointer to the Thread Information Block(TIB) which it in turn contains a pointer to the Process Environment Block(PEB).  PEB contains a pointer to PEB_LDR_DATA which contains an intrusive pointer to a LIST_ENTRY in the first LDR_DATA_TABLE_ENTRY.  

LIST_ENTRY is a node in a doubly linked list which contains all processes loaded in process memory.  LDR_DATA_TABLE_ENTRY contains a BaseDllName which can be compared against to find "kernel32.dll".  Once the LDR_DATA_TABLE_ENTRY for kernel32.dll (which is loaded into every process's memory) is located, DllBase is used to locate the start of the DLL in memory.

The start of any process in memory is a IMAGE_DOS_HEADER struct which contains e_lfanew, an offset to the IMAGE_NT_HEADERS64 struct for the given process.  IMAGE_NT_HEADERS64 contains a struct IMAGE_OPTIONAL_HEADER which contains at its tail an array of 16 IMAGE_DATA_DIRECTORY structs.  

```
typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned int VirtualAddress;
	unsigned int Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The IMAGE_DATA_DIRECTORY structs contain information needed for parsing PE's(Portable Executables).  The one of interest here is the first, which per MSDN is the Export Table.  The Export Table contains all functions exported by that executable, be it forwarded or not.  The Relative Virtual Address(RVA) contained in IMAGE_DATA_DIRECTORY for the Export Table is added to the DLL base address to calculate the absolute address of the Export Table in memory.

The Export Table is a struct IMAGE_EXPORT_DIRECTORY which contains information that can be used to find a specific function exported by the executable.  

```
  typedef struct _IMAGE_EXPORT_DIRECTORY {
	unsigned int		  Characteristics;
	unsigned int		  TimeDateStamp;
	unsigned short		MajorVersion;
	unsigned short		MinorVersion;
	unsigned int		  Name;
	unsigned int		  Base;
	unsigned int		  NumberOfFunctions;
	unsigned int		  NumberOfNames;
	unsigned int		  AddressOfFunctions;     // RVA from base of image
	unsigned int		  AddressOfNames;         // RVA from base of image
	unsigned int		  AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

AddressOfNames is an array pointer to an array of 32-bit values.  These 32-bit values are RVA's which can be added to the DLL Base Address to access strings with the function names.  The index in AddressOfNames at which the desired function is found is used as a lookup value in AddressOfNameOrdinals.  AddressOfNameOrdinals is an array pointer to an array of 16-bit values.  Using the index found from AddressOfNames is used as an index to AddressOfNameOrdinals.  The value retrieved from AddressOfNameOrdinals is used as an index on AddressOfFunctions.

AddressOfFunctions is an array pointer to an array of 32-bit values.  Each value is either an RVA pointing to the desired function, or in the case of forwarded functions, an RVA pointing to a forwarding string.  A function is forwarded if the value found in AddressOfFunctions falls within:

```
IMAGE_DATA_DIRECTORY.VirtualAddress -> IMAGE_DATA_DIRECTORY.VirtualAddress + IMAGE_DATA_DIRECTORY.Size
```
If the function is forwarded a string will be retrieved by combining the RVA and the DLL base address.  The forwarded string for ``` AcquireSRWLockExclusive ``` in ``` kernel32.dll ``` is ``` NTDLL.RtlAcquireSRWLockExclusiv```.  That string can be used to repeat this process to find the forwarded function.  While not necessary if writing shell code because one should be targeting the DLL which contains the desired function, the ability to find forwarded functions has been implemented here.

If the function is not forwarded, then the function address is RVA + DLL base address.  

#Why?
Well I was bored and it's an intro to understanding what Windows shell code does.

#Do I need to use this?
Probably not
