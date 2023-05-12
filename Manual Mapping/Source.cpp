#include <iostream>
#include <Windows.h>


#ifdef _WIN64
char szdllPath[] = "E:\\repos\\dnfdll\\x64\\Debug\\dnfdll.dll";
#elif _WIN32

char szdllPath[] = "E:\\repos\\dnfdll\\Debug\\dnfdll.dll";
#else
char szdllPath[] = "";
#endif // DEBUG

PIMAGE_DOS_HEADER pDosheader;
PIMAGE_NT_HEADERS pNtheader;
PIMAGE_OPTIONAL_HEADER pOptHeader;
PIMAGE_FILE_HEADER pFileHeader;

//typedef  HINSTANCE(*pLoadLibrary)( const char* lpLibFileName);
//typedef  UINT_PTR(*pGetProcAddress)( HINSTANCE hModule, const char* lpProcName);
//typedef		BOOL  (*pDllmain)(void* hDll, DWORD dwReason, void* pReserved); 


using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	HINSTANCE			hMod;
};

struct MappingData
{
	f_LoadLibraryA  ploadlibrary ;
	f_GetProcAddress	pgetprocaddress;
	HINSTANCE			hMod;
};
using namespace std;


void* MappingFileintoMemory()
{
	
	FILE* pFile = NULL;
	DWORD FileSize = 0;
	void* pFileBuffer = 0;
	size_t flag = 0;

	//	size_t i ;

		//打开文件
	pFile = fopen(szdllPath, "rb");
	if (!pFile)
	{
		printf("open file failure!\n");
		return NULL;
	}

	//读取文件大小
	fseek(pFile, 0, SEEK_END);
	FileSize = ftell(pFile);

	fseek(pFile, 0, SEEK_SET);

	//分配缓冲区
	pFileBuffer = malloc(FileSize);
	if (!pFileBuffer)
	{
		printf("allocation space failure!\n");
		fclose(pFile);
		return NULL;
	}
	memset(pFileBuffer, 0, FileSize);
	//将文件数据读取到缓冲区
	flag = fread(pFileBuffer, FileSize, 1, pFile);
	if (!flag)
	{
		printf("read data failure!\n");
		fclose(pFile);
		free(pFile);
		return NULL;
	}
	/*输出16进制数据
		for(i=0 ; i<FileSize;i++)
		{
			printf("%x",*((byte*)pFileBuffer+i));
		}
	*/
	//关闭文件
	fclose(pFile);

	//返回指针 指向文件数据
	return pFileBuffer;

	//FILE* pFile = NULL;

	//pFile  = fopen(szdllPath, "rb");  //通过文件路径 找到文件指针
	//if (pFile == NULL)
	//{
	//	DWORD error = GetLastError();
	//	cout << "打开文件失败 错误代码：" << error << endl;
	//	return 0;
	//}

	//fseek(pFile, 0, SEEK_END);
	//int filesize = ftell(pFile);
	//cout << "File Size：" << filesize << endl;

	//fseek(pFile, 0, SEEK_SET);
	//LPVOID buf = NULL;
	////buf = VirtualAlloc(0,filesize+1,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	//buf = malloc((size_t)filesize+1);
	//
	//if (!buf)
	//{
	//	printf("分配内存失败\n");
	//	fclose(pFile);
	//	return 0;
	//}

	////memset(buf, 0, filesize);
	//size_t flag = 0;
	//flag=fread(buf, filesize, 1, pFile);

	//if (!flag)
	//{
	//	cout << "读取文件失败" << endl;
	//	free(buf);
	//	fclose(pFile);
	//	return 0;

	//	
	//}

	//for (int i = 0; i < filesize; i++)
	//{
	//	printf("%x", *((byte*)buf + i));
	//}
	//
	//fclose(pFile);
	//
	//return buf;
}


BYTE* WindowsMappingFileintoMemory()
{
	HANDLE hFile = CreateFileA(szdllPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	BYTE* pbFile = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE || hMapping == NULL || pbFile == NULL)
	{
		printf("\n========THE FILE IS NOT EXCTING===========\n");
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
		if (hMapping != NULL)
		{
			CloseHandle(hMapping);
		}
		if (pbFile != NULL)
		{
			UnmapViewOfFile(pbFile);
		}
		return 0;
	}

	return pbFile;
}


void readSectionTable(void* pFile)
{
	pDosheader = (PIMAGE_DOS_HEADER)pFile;
	if (pDosheader->e_magic != 0x5a4d)
	{
		cout << "Not PE format" << endl;
		return;
	}
	pNtheader = (PIMAGE_NT_HEADERS)((DWORD)pFile +pDosheader->e_lfanew);
	
	cout << "nt signature: " << hex<<pNtheader->Signature << endl;
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNtheader + 4);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	
	//auto pSectionHeader = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(pNtheader));

	cout << "Imgbase: " << pOptHeader->ImageBase << endl;
	cout << "File alignment: " << pOptHeader->FileAlignment << endl;
	cout << "Section alignment: " << pOptHeader->SectionAlignment << endl;
	cout << "Size of Image: " << pOptHeader->SizeOfImage << endl;
	cout << "Address Entry Point: " << pOptHeader->AddressOfEntryPoint << endl;
	int numofSections = pFileHeader->NumberOfSections;
	int sizeofOptHeader = pFileHeader->SizeOfOptionalHeader;
	cout << "Size of Optional header: " << sizeofOptHeader << endl;
	cout << "Number of sections: " << numofSections << endl;
	//pOptHeader = (PIMAGE_OPTIONAL_HEADER)
	cout << "Size of header: " << pOptHeader->SizeOfHeaders << endl;
}


#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif


void __stdcall Shellcode(MappingData* pData)
{
	if (!pData)
		return;
	
	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	//auto _LoadLibraryA = pData->pLoadLibraryA;
	//auto _GetProcAddress = pData->pGetProcAddress;
	//auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	auto _LoadLibraryA = pData->ploadlibrary;
	auto _GetProcAddress = pData->pgetprocaddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}



	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = (UINT_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (UINT_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}
	//__asm int 3;
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

bool ManualMap(void* pfile,HANDLE hProcess)
{
	/*BYTE* pSrcData =(BYTE*)pfile;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;




	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("Invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		printf("Invalid platform\n");
		delete[] pSrcData;
		return false;
	}
#endif

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			printf("Memory allocation failed (ex) 0x%X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				printf("Can't map sections: 0x%x\n", GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProcess, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf("Memory allocation failed (1) (ex) 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProcess, pShellcode, Shellcode, 0x1000, nullptr);

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	if (!hThread)
	{
		printf("Thread creation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProcess, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);

	return true;

*/







	
	MappingData data = { 0 };
	data.ploadlibrary =(f_LoadLibraryA) LoadLibraryA;
	data.pgetprocaddress =(f_GetProcAddress) GetProcAddress;


	BYTE* pBase = (BYTE*)VirtualAllocEx(hProcess,(LPVOID)pOptHeader->ImageBase,pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	cout << "ImageBase in manual map:" << hex << pOptHeader->ImageBase << endl;

	if(!pBase)
	{
		pBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pBase)
		{
			printf("Memory allocation failed (ex) 0x%X\n", GetLastError());
			
			return false;
		}
	}



	printf("Pbase 0x:%X\n", pBase);
	BYTE* entrypoint = (BYTE*)(pBase + pOptHeader->AddressOfEntryPoint);
	

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtheader);
	if (!pSectionHeader)
	{
		printf("pSectionHeader为空 \n");
	}
	
	for (UINT  i = 0; i != pFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			printf("pSectionHeader->VirtualAddress 0x:%x\n", pSectionHeader->VirtualAddress);
			SIZE_T size = 0;
		//	VirtualProtectEx(hProcess, (LPVOID)(pBase + pSectionHeader->VirtualAddress), pSectionHeader->SizeOfRawData,PAGE_EXECUTE_READWRITE,NULL);
			if (!WriteProcessMemory(hProcess,(LPVOID)(pBase + pSectionHeader->VirtualAddress), (LPVOID)((BYTE*)pfile + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, &size))
			{
				
				printf("Can't map sections: 0x%x\n", GetLastError());
			
				VirtualFreeEx(hProcess, pBase, 0, MEM_RELEASE);
				return false;
			}
			printf("SizeOfRawData 0x:%x\n", pSectionHeader->SizeOfRawData);
			printf("Bytes written 0x: % x\n", size);
		}
		else
		{
			printf("pSectionHeader->SizeOfRawData 为空\n");
		}
	}


	memcpy(pfile, &data, sizeof(data));
	WriteProcessMemory(hProcess,pBase,pfile,0x1000,0);





	void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	

	if (!pShellcode)
	{
		printf("Memory allocation failed (1) (ex) 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, pBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProcess, pShellcode, Shellcode, 0x1000, nullptr);
	
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pBase, 0, nullptr);
	if (!hThread)
	{
		printf("Thread creation failed 0x%X\n", GetLastError());
		VirtualFreeEx(hProcess, pBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	printf("线程创建完毕,pShellcode: %p\n",pShellcode);

	

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MappingData data_checked{ 0 };
		ReadProcessMemory(hProcess, pBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}
	

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);

	printf("释放内存:%X\n", pBase);
	return true;
    
}

int main()
{
	void* addr =MappingFileintoMemory();
	readSectionTable(addr);
	
	DWORD pid;
	cout << "Pid:" << endl;

	cin >> pid;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc)
	{
		cout << "openprocess failed" << endl;
		return 0;
	}
	else
	{
		cout << "openprocess succeed" << endl;
	}
	if (!ManualMap(addr, hProc))
	{
		cout << "ManualMap failed" << endl;
		return 0;
	}
	cout << "Injection succeed" << endl;
	
	return 0;
}