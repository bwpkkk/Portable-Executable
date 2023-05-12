// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdlib.h>


HMODULE					Current_Handle;		//进程句柄
PBYTE					pfile;              //指向MZ
PIMAGE_DOS_HEADER			Dos_Header;			//Dos头
PIMAGE_NT_HEADERS			Nt_Header;			//NT头
DWORD					IATSection_Base;		//IAT所在段基址
DWORD					IATSection_Size;


int WINAPI NewMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    return MessageBoxW(NULL, L"IAT", L"HOOK`", NULL);
}


BOOL cmpStr(char* strA , char* strB)
{
    //MessageBoxA(0, strA, strB,0);
    while (*strA != '\0')
    {
        if (*strA != *strB)
            return FALSE;
        else
        {
            strA++;
            strB++;
           // MessageBoxA(0, strA, strB, 0);
        }
        
    }
    return TRUE;
}

BOOL str_cmp(char* a, char* b) {
    while (*a == *b && *a != '\0' && *b != '\0') {
        a++;
        b++;
    }
    if (*a == '\0' && *b == '\0') return true;
    return false;
}


BOOL IatHook(LPCSTR DllName, LPCSTR ProcName)
{
    //MessageBeep(0);
    PIMAGE_IMPORT_DESCRIPTOR pImportAddrTable = (PIMAGE_IMPORT_DESCRIPTOR)(pfile+IATSection_Base);
    FARPROC funcAddr= GetProcAddress(GetModuleHandleA(DllName),ProcName);
   
    char buf[100];
    char temp[100];
    char temp2[100];
    _itoa_s((int)(&NewMessageBoxW), temp, 16);
    MessageBoxA(0, "NewMessageBoxW", temp, 0);
    PIMAGE_THUNK_DATA pfirstThunk, pOriginalThunk = 0;
    DWORD oldProtect = 0;
        while (pImportAddrTable->Characteristics)
        {

            if (str_cmp((char*)DllName, (char*)(pfile + pImportAddrTable->Name)))
            {
               // MessageBoxA(0, buf, (char*)(pfile + pImportAddrTable->Name), 0);
                MEMORY_BASIC_INFORMATION mbi_thunk;
               
                 pOriginalThunk= (PIMAGE_THUNK_DATA)(pfile + pImportAddrTable->OriginalFirstThunk);
                pfirstThunk = (PIMAGE_THUNK_DATA)(pfile + pImportAddrTable->FirstThunk);
               
                _itoa_s((int)(&pfirstThunk->u1.Function), temp, 16);
                VirtualQuery(pfirstThunk, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION));

                for(;pOriginalThunk->u1.AddressOfData;pOriginalThunk++, pfirstThunk++)
                {
                    PIMAGE_IMPORT_BY_NAME pEntry = (PIMAGE_IMPORT_BY_NAME)(pfile + pOriginalThunk->u1.AddressOfData);
                    if (str_cmp(pEntry->Name,(char*)ProcName))
                    {
                        
                        
                        BOOL breturn = 0;
                        breturn= VirtualProtectEx(GetCurrentProcess(), pfirstThunk, 0X1000,PAGE_EXECUTE_READWRITE, &oldProtect);
                        
                        _itoa_s((int)(pfirstThunk->u1.Function), temp2, 16);
                        _itoa_s((int)(&pfirstThunk->u1.Function), temp, 16);
                        MessageBoxA(0, temp, temp2, 0);

                       
                        //BOOL breturn = WriteProcessMemory(GetCurrentProcess(), &pfirstThunk->u1.Function, NewMessageBoxW, sizeof(DWORD), NULL);

                       
                            DWORD funcaddr =(DWORD)NewMessageBoxW;
                            memcpy(pfirstThunk, &funcaddr, 4);
                            breturn = VirtualProtectEx(GetCurrentProcess(), pfirstThunk, 0X1000, oldProtect, &oldProtect);

                       
                        _itoa_s((int)(pfirstThunk->u1.Function), temp2, 16);
                        _itoa_s((int)(&pfirstThunk->u1.Function), temp, 16);
                        MessageBoxA(0, temp, temp2, 0);
                       
                    }

                    
                    
                }
                return true;
            }
           
              
            
            pImportAddrTable++;
        }
   
   
        MessageBox(0, L"未找到dll", L"", 0);
        return false;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Current_Handle = GetModuleHandle(NULL);
        pfile = (PBYTE)Current_Handle;
        Dos_Header = (PIMAGE_DOS_HEADER)pfile;
        //MessageBeep(0);
        if (Dos_Header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            MessageBox(0,L"不是PE文件",L"未查到PE标识",0);
            return false;
        }

        Nt_Header = PIMAGE_NT_HEADERS(pfile+ Dos_Header->e_lfanew);

        if (Nt_Header->Signature != IMAGE_NT_SIGNATURE)
        {
            MessageBox(0, L"不是PE文件", L"未查到PE签名", 0);
            return false;
        }

        IMAGE_DATA_DIRECTORY IAT_SECTION = Nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IATSection_Base = IAT_SECTION.VirtualAddress;
        IATSection_Size = IAT_SECTION.Size;
        IatHook("USER32.dll","MessageBoxW");


    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

