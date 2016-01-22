#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
	unsigned short	length;
	unsigned short	maxLength;
	unsigned char	Reserved[4];
	wchar_t*			buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ACTIVATION_CONTEXT
{
	unsigned long       magic;
	int                 ref_count;
	//struct file_info    config;
	//struct file_info    appdir;
	struct assembly    *assemblies;
	unsigned int        num_assemblies;
	unsigned int        allocated_assemblies;
	/* section data */
	unsigned long       sections;
	struct strsection_header  *wndclass_section;
	struct strsection_header  *dllredirect_section;
	struct strsection_header  *progid_section;
	struct guidsection_header *tlib_section;
	struct guidsection_header *comserver_section;
	struct guidsection_header *ifaceps_section;
	struct guidsection_header *clrsurrogate_section;
} ACTIVATION_CONTEXT;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY			InLoadOrderLinks;				/* 0x00 */
	LIST_ENTRY			InMemoryOrderLinks;				/* 0x10 */
	LIST_ENTRY			InInitializationOrderLinks;		/* 0x20 */
	void*				DllBase;						/* 0x30 */
	void*				EntryPoint;						/* 0x38 */
	unsigned long		SizeOfImage;					/* 0x40 */
	UNICODE_STRING		FullDllName;					/* 0x48 */
	UNICODE_STRING		BaseDllName;					/* 0x58 */
	unsigned long Flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			void* SectionPointer;
			unsigned long CheckSum;
		};
	};
	union
	{
		unsigned long TimeDateStamp;
		void* LoadedImports;
	};
	_ACTIVATION_CONTEXT * EntryPointActivationContext;
	void* PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	unsigned int		Length;
	unsigned int		Initialized;
	unsigned short		SsHandle;
	LIST_ENTRY			InLoadOrderModuleList;
	LIST_ENTRY			InMemoryOrderModuleList;
	void*				EntryInProgress;
	unsigned short		ShutdownInProgress;
	void*				ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	unsigned char		InheritedAddressSpace;
	unsigned char		ReadImageFileExecOptions;
	unsigned char		BeginDebugged;
	unsigned char		Reserved[5];
	unsigned short		Mutant;
	void*				ImageBaseAddress;
	PPEB_LDR_DATA		Ldr;
} PEB, *PPEB;

typedef struct _TIB {
	unsigned char	Stuff[0x60];
	PPEB			pPEB;
} TIB, *PTIB;

typedef struct _IMAGE_FILE_HEADER {
	unsigned short		Machine;				/* 0x00 */
	unsigned short		NumberOfSections;		/* 0x02 */
	unsigned int		TimeDateStamp;			/* 0x04 */
	unsigned int		PointerToSymbolTable;	/* 0x08 */
	unsigned int		NumberOfSymbols;		/* 0x0C */
	unsigned short		SizeOfOptionalHeader;	/* 0x10 */
	unsigned short		Characteristics;		/* 0x12 */
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned int VirtualAddress;
	unsigned int Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	unsigned short					Magic;						/* 0x00 */
	unsigned char					MajorLinkerVersion;			/* 0x02 */
	unsigned char					MinorLinkerVersion;			/* 0x03 */
	unsigned int					SizeOfCode;					/* 0x04 */
	unsigned int					SizeOfInitializedData;		/* 0x08 */
	unsigned int					SizeOfUninitializedData;	/* 0x0C */
	unsigned int					AddressOfEntryPoint;		/* 0x10 */
	unsigned int					BaseOfCode;					/* 0x14 */
	unsigned long long				ImageBase;					/* 0x18 */
	unsigned int					SectionAlignment;			/* 0x20 */
	unsigned int					FileAlignment;				/* 0x24 */
	unsigned short					MajorOperatingSystemVersion;/* 0x28 */
	unsigned short					MinorOperatingSystemVersion;/* 0x2A */
	unsigned short					MajorImageVersion;			/* 0x2C */
	unsigned short					MinorImageVersion;			/* 0x2E */
	unsigned short					MajorSubsystemVersion;		/* 0x30 */
	unsigned short					MinorSubsystemVersion;		/* 0x32 */
	unsigned int					Win32VersionValue;			/* 0x34 */
	unsigned int					SizeOfImage;				/* 0x38 */
	unsigned int					SizeOfHeaders;				/* 0x3C */
	unsigned int					CheckSum;					/* 0x40 */
	unsigned short					Subsystem;					/* 0x44 */
	unsigned short					DllCharacteristics;			/* 0x46 */
	unsigned long long				SizeOfStackReserve;			/* 0x48 */
	unsigned long long				SizeOfStackCommit;			/* 0x50 */
	unsigned long long				SizeOfHeapReserve;			/* 0x58 */
	unsigned long long				SizeOfHeapCommit;			/* 0x60 */
	unsigned int					LoaderFlags;				/* 0x68 */
	unsigned int					NumberOfRvaAndSizes;		/* 0x6C */
	IMAGE_DATA_DIRECTORY			DataDirectory[16];			/* 0x70 */
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
	unsigned int			Signature;
	_IMAGE_FILE_HEADER		FileHeader;
	_IMAGE_OPTIONAL_HEADER	OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_DOS_HEADER {
	unsigned short		magic;		/* 0x00 */
	unsigned short		cblp;		/* 0x02 */
	unsigned short		cp;			/* 0x04 */
	unsigned short		crlc;		/* 0x06 */
	unsigned short		cparhdr;	/* 0x08 */
	unsigned short		minalloc;	/* 0x0A */
	unsigned short		maxalloc;	/* 0x0C */
	unsigned short		ss;			/* 0x0E */
	unsigned short		sp;			/* 0x10 */
	unsigned short		csum;		/* 0x12 */
	unsigned short		ip;			/* 0x14 */
	unsigned short		cs;			/* 0x16 */
	unsigned short		lfarlc;		/* 0x18 */
	unsigned short		ovno;		/* 0x1A */
	unsigned short		res[4];		/* 0x1C */
	unsigned short		oemid;		/* 0x24 */
	unsigned short		oeminfo;	/* 0x26 */
	unsigned short		res2[10];	/* 0x28 */
	unsigned short		lfanew;		/* 0x3C */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	unsigned int		Characteristics;
	unsigned int		TimeDateStamp;
	unsigned short		MajorVersion;
	unsigned short		MinorVersion;
	unsigned int		Name;
	unsigned int		Base;
	unsigned int		NumberOfFunctions;
	unsigned int		NumberOfNames;
	unsigned int		AddressOfFunctions;     // RVA from base of image
	unsigned int		AddressOfNames;         // RVA from base of image
	unsigned int		AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;