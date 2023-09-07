# Call Obfuscation
In the windows malware development world or rather windows internal world we have a table named IAT which holds the functions that are used in the applicaiton. to bypass AV/EDR people often try to hide these function names by means of obfuscation.

## winapi-obfuscator
This repository tries to make obfuscating WINAPI/NTAPI calls easier.
note that it is for educational purposes and I'm not responsible for any harm that is caused by using this repository!

### grepper.py
`grepper.py` finds function signatures in a folder you specify which should be the path to windows SDK that is usually located in `C:\Program Files (x86)\Windows Kits\<windows version>\Include\<version>`.
```json
{
    "MessageBoxA": {
        "signature": "int WINAPI MessageBoxA(
            _In_opt_ HWND hWnd,
            _In_opt_ LPCSTR lpText,
            _In_opt_ LPCSTR lpCaption,
            _In_ UINT uType);",
         "library": "user32.dll"},
    ...
}
```
usage: 
```
python grepper.py <input directory> <output filename>
```

#### Windows header files
list of windows header files i've found till now(not at all complete):
```
winuser.h - user32.dll
memoryapi.h - kernel32.dll
psapi.h -kernel32.dll
tlhelp.h -kernel32.dll
debugapi.h - kernel32.dll,
processthreadsapi.h - kernel32.dll
fileapi.h - kernel32.dll
libloaderapi.h - kernel32.dll
```
the scripts greps through these header files for function signatures.

### obfuscator.py
and using this file you can easily obfuscate the functions that you want and it gives you the <b>new function definitions</b>, <b>encrypted function names</b>, <b>encrypted DLL names</b>, <b>different XOR keys</b> and finally the <b>code to resolve them</b>. you can copy and paste these into c/c++ and use them.

usage:
```
python obfuscator.py <json file> <function names> <y/n>
```

- `json file` is the `.json` file you want to feed it.
- `function names` is separated by `,` and are the functions you want to obfuscate.
- `y/n` whether you want to save them in one file or different files.

## Example
```
python obfuscator.py all_in.json MessageBoxA y
```
all.txt
```
typedef int (WINAPI * pMessageBoxA)( _In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

unsigned char sMessageBoxA[] = {0x21, 0x3, 0xa, 0x10, 0x1b, 0x9, 0x3, 0x2f, 0x16, 0x14, 0x2d, 0x66};
unsigned char sUser32[] = {0x10, 0x19, 0x7, 0x3, 0x5a, 0x5e, 0x45, 0x1d, 0x15, 0x1b, 0x65};

char kMessageBoxA[] = {0x6c, 0x66, 0x79, 0x63, 0x7a, 0x6e, 0x66, 0x6d, 0x79, 0x6c, 0x0};
char kUser32[] = {0x65, 0x6a, 0x62, 0x71, 0x69, 0x6c, 0x6b, 0x79, 0x79, 0x77, 0x0};

XOR(sMessageBoxA, sizeof(sMessageBoxA),  kMessageBoxA, sizeof(kMessageBoxA));
XOR(sUser32, sizeof(sUser32),  kUser32, sizeof(kUser32));

pMessageBoxA messageBoxA = (pMessageBoxA)GetProcAddress(LoadLibraryA((LPCSTR)sUser32),(LPCSTR)sMessageBoxA);

```

main.cpp
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