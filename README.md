# Call Obfuscation
In the windows malware development world or rather windows internal world we have a table named IAT which holds the functions that are used in the applicaiton. to bypass AV/EDR people often try to hide these function names by means of obfuscation.

## winapi-obfuscator
This repository tries to make obfuscating WINAPI/NTAPI calls easier.
note that it is for educational purposes and I'm not responsible for any harm that is caused by using this repository!

usage:
```
python winapi-obfuscator.py [-h] --windows-sdk WINDOWS_SDK --function-names FUNCTION_NAMES [--key-length KEY_LENGTH]
```

### Grepper
grepper functionality finds function signatures in the windows SDK folder you specify which is usually located in `C:\Program Files (x86)\Windows Kits\<windows version>\Include\<version>`.
after grepping through all the defined windows header files it generates a `data.json` file which contains all the signatures.

<b>data.json</b>

```json
{
    "MessageBoxA": {"signature": "int WINAPI MessageBoxA( _In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);", "library": "user32.dll"},
    "VirtualAlloc": {"signature": "LPVOID WINAPI VirtualAlloc( _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect ) ;", "library": "kernel32.dll"},
    "VirtualProtect": {"signature": "BOOL WINAPI VirtualProtect( _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect ) ;", "library": "kernel32.dll"},
    "VirtualFree": {
        "signature": "BOOL WINAPI VirtualFree( _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT,_Post_invalid_) _When_(dwFreeType == MEM_RELEASE,_Post_ptr_invalid_) LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD dwFreeType );",
        "library": "kernel32.dll"
    },
    "WriteProcessMemory": {
        "signature": "BOOL WINAPI WriteProcessMemory( _In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, _In_reads_bytes_(nSize) LPCVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesWritten );",
        "library": "kernel32.dll"
    },
    ...
}
```

#### Windows header files
list of windows header files i've found till now(not at all complete):
```python
 __header_files = [
    [r"\um\winuser.h","user32.dll"],
    [r"\um\memoryapi.h","kernel32.dll"],
    [r"\um\psapi.h","kernel32.dll"],
    [r"\um\tlhelp32.h","kernel32.dll"],
    [r"\um\debugapi.h","kernel32.dll"],
    [r"\um\processthreadsapi.h","kernel32.dll"],
    [r"\um\fileapi.h","kernel32.dll"],
    [r"\um\libloaderapi.h","kernel32.dll"]
]
```
the script greps through these header files for function signatures.

### Obfuscation
and using this functionality you can easily obfuscate the functions that you want and it gives you the <b>new function definitions</b>, <b>encrypted function names</b>, <b>encrypted DLL names</b>, <b>different XOR keys</b> and finally the <b>code to resolve them</b>. you can copy and paste these into c/c++ and use them.

<b>all.txt</b>

```cpp
unsigned char sMessageBoxA[] = {0x20, 0x6, 0x3f, 0x27, 0x56, 0x50, 0x52, 0x10, 0x17, 0x0, 0x2c, 0x63};
unsigned char sUser32[] = {0x2d, 0x31, 0x7, 0x37, 0x50, 0x59, 0x74, 0x5c, 0x59, 0x34, 0x58};

char kMessageBoxA[] = {0x6d, 0x63, 0x4c, 0x54, 0x37, 0x37, 0x37, 0x52, 0x78, 0x78, 0x0};
char kUser32[] = {0x58, 0x42, 0x62, 0x45, 0x63, 0x6b, 0x5a, 0x38, 0x35, 0x58, 0x0};

XOR(sMessageBoxA, sizeof(sMessageBoxA),  kMessageBoxA, sizeof(kMessageBoxA));
XOR(sUser32, sizeof(sUser32),  kUser32, sizeof(kUser32));

pMessageBoxA messageBoxA = (pMessageBoxA)GetProcAddress(LoadLibraryA((LPCSTR)sUser32),(LPCSTR)sMessageBoxA);
```

## Example

```
python winapi-obfuscator.py -s "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0" -f MessageBoxA
```

<b>data.json</b>

```json
{
    "MessageBoxA": {"signature": "int WINAPI MessageBoxA( _In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);", "library": "user32.dll"},
    "VirtualAlloc": {"signature": "LPVOID WINAPI VirtualAlloc( _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect ) ;", "library": "kernel32.dll"},
    "VirtualProtect": {"signature": "BOOL WINAPI VirtualProtect( _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect ) ;", "library": "kernel32.dll"},
    "VirtualFree": {
        "signature": "BOOL WINAPI VirtualFree( _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT,_Post_invalid_) _When_(dwFreeType == MEM_RELEASE,_Post_ptr_invalid_) LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD dwFreeType );",
        "library": "kernel32.dll"
    },
    "WriteProcessMemory": {
        "signature": "BOOL WINAPI WriteProcessMemory( _In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, _In_reads_bytes_(nSize) LPCVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesWritten );",
        "library": "kernel32.dll"
    },
    ...
}
```

<b>all.txt</b>

```cpp
typedef int (WINAPI * pMessageBoxA)( _In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

unsigned char sMessageBoxA[] = {0x21, 0x3, 0xa, 0x10, 0x1b, 0x9, 0x3, 0x2f, 0x16, 0x14, 0x2d, 0x66};
unsigned char sUser32[] = {0x10, 0x19, 0x7, 0x3, 0x5a, 0x5e, 0x45, 0x1d, 0x15, 0x1b, 0x65};

char kMessageBoxA[] = {0x6c, 0x66, 0x79, 0x63, 0x7a, 0x6e, 0x66, 0x6d, 0x79, 0x6c, 0x0};
char kUser32[] = {0x65, 0x6a, 0x62, 0x71, 0x69, 0x6c, 0x6b, 0x79, 0x79, 0x77, 0x0};

XOR(sMessageBoxA, sizeof(sMessageBoxA),  kMessageBoxA, sizeof(kMessageBoxA));
XOR(sUser32, sizeof(sUser32),  kUser32, sizeof(kUser32));

pMessageBoxA messageBoxA = (pMessageBoxA)GetProcAddress(LoadLibraryA((LPCSTR)sUser32),(LPCSTR)sMessageBoxA);
```

<b>your/cpp/file.cpp</b> - copy `all.txt` content into your `cpp` file.

```cpp
void XOR(unsigned char data[], int dataSize, char key[], int keySize) {
	for (int i = 0; i < (dataSize / sizeof(unsigned char)); i++) {
		char currentKey = key[i % (keySize - 1)];
		data[i] ^= currentKey;
	}
}
typedef int (WINAPI * pMessageBoxA)( _In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
int main(){


    unsigned char sMessageBoxA[] = {0x21, 0x3, 0xa, 0x10, 0x1b, 0x9, 0x3, 0x2f, 0x16, 0x14, 0x2d, 0x66};
    unsigned char sUser32[] = {0x10, 0x19, 0x7, 0x3, 0x5a, 0x5e, 0x45, 0x1d, 0x15, 0x1b, 0x65};

    char kMessageBoxA[] = {0x6c, 0x66, 0x79, 0x63, 0x7a, 0x6e, 0x66, 0x6d, 0x79, 0x6c, 0x0};
    char kUser32[] = {0x65, 0x6a, 0x62, 0x71, 0x69, 0x6c, 0x6b, 0x79, 0x79, 0x77, 0x0};

    XOR(sMessageBoxA, sizeof(sMessageBoxA),  kMessageBoxA, sizeof(kMessageBoxA));
    XOR(sUser32, sizeof(sUser32),  kUser32, sizeof(kUser32));

    pMessageBoxA messageBoxA = (pMessageBoxA)GetProcAddress(LoadLibraryA((LPCSTR)sUser32),(LPCSTR)sMessageBoxA);
    messageBoxA(NULL, "hello", "hello", MB_OK);
}
```