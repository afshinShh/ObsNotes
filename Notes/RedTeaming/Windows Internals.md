# Fundamentals
## processes

*maintains and represents the execution of a program; an application can contain one or more processes*

- each critical component of processes and their purpose:
```dataviewjs
dv.table(["Process Component", "Purpose"], [
  ["Private Virtual Address Space", "Virtual memory addresses that the process is allocated."],
  ["Executable Program", "Defines code and data stored in the virtual address space."],
  ["Open Handles", "Defines handles to system resources accessible to the process."],
  ["Security Context", "The access token defines the user, security groups, privileges, and other security information."],
  ["Process ID", "Unique numerical identifier of the process."],
  ["Threads", "Section of a process scheduled for execution."]
])
```
what a process looks like in memory:
```dataviewjs
dv.table(["Component", "Purpose"], [
  ["Code", "Code to be executed by the process."],
  ["Global Variables", "Stored variables."],
  ["Process Heap", "Defines the heap where data is stored."],
  ["Process Resources", "Defines further resources of the process."],
  ["Environment Block", "Data structure to define process information."]
])
```
![[Pasted image 20260705213058.png]]
## thread
*an executable unit employed by a process and scheduled based on device factors.*

```dataviewjs
dv.table(["Component", "Purpose"], [
  ["Stack", "All data relevant and specific to the thread (exceptions, procedure calls, etc.)"],
  ["Thread Local Storage", "Pointers for allocating storage to a unique data environment"],
  ["Stack Argument", "Unique value assigned to each thread"],
  ["Context Structure", "Holds machine register values maintained by the kernel"]
])
```
## Virtual memory
*allows other internal components to interact with memory as if it was physical memory without the risk of collisions between applications*

- provides each process with a [private virtual address space (opens in new tab)](https://docs.microsoft.com/en-us/windows/win32/memory/virtual-address-space). A memory manager is used to translate virtual addresses to physical addresses. By having a private virtual address space and not directly writing to physical memory, processes have less risk of causing damage.

- The theoretical maximum virtual address space is **4 GB** on a **32-bit** x86 system => **256 TB** on a **64-bit** modern system.

- This address space is split in half, the lower half (_0x00000000 - 0x7FFFFFFF_) is allocated to processes as mentioned above. The upper half (_0x80000000 - 0xFFFFFFFF_) is allocated to OS memory utilization
	- ![[Pasted image 20260705214511.png]]
- can be increased through settings (_increaseUserVA_) or the [AWE (**A**ddress **W**indowing **E**xtensions) (opens in new tab)](https://docs.microsoft.com/en-us/windows/win32/memory/address-windowing-extensions).
## dynamic link libraries (DLLs)
*a library that contains code and data that can be used by more than one program at the same time.*

- From the [Windows documentation](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library#:~:text=A%20DLL%20is%20a%20library,common%20dialog%20box%20related%20functions.), "The use of DLLs helps promote modularization of code, code reuse, efficient memory usage, and reduced disk space. So, the operating system and the programs load faster, run faster, and take less disk space on the computer."

> [!example] example of a from the _Visual C++ Win32 Dynamic-Link Library project_.
```cpp
#include "stdafx.h"
#define EXPORTING_DLL
#include "sampleDLL.h"
BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved
)
{
    return TRUE;
}

void HelloWorld()
{
    MessageBox( NULL, TEXT("Hello World"), TEXT("In a DLL"), MB_OK);
}
```
header file for the previous DLL:
```cpp
#ifndef INDLL_H
    #define INDLL_H
    #ifdef EXPORTING_DLL
        extern __declspec(dllexport) void HelloWorld();
    #else
        extern __declspec(dllimport) void HelloWorld();
    #endif

#endif
```

- how are they used in an application?
	DLLs can be loaded in a program using _load-time dynamic linking_ or _run-time dynamic linking_.

- When loaded using _load-time dynamic linking_, explicit calls to the DLL functions are made from the application. You can only achieve this type of linking by providing a header (_.h_) and import library (_.lib_) file.
> [!example] an example of calling an exported DLL function from an application.
```cpp
#include "stdafx.h"
#include "sampleDLL.h"
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HelloWorld();
    return 0;
}
```
When loaded using _run-time dynamic linking_, a separate function (`LoadLibrary` or `LoadLibraryEx`) is used to load the DLL at run time. Once loaded, you need to use `GetProcAddress` to identify the exported DLL function to call.
> [!example] an example of loading and importing a DLL function in an application.
```cpp
...
typedef VOID (*DLLPROC) (LPTSTR);
...
HINSTANCE hinstDLL;
DLLPROC HelloWorld;
BOOL fFreeDLL;

hinstDLL = LoadLibrary("sampleDLL.dll");
if (hinstDLL != NULL)
{
    HelloWorld = (DLLPROC) GetProcAddress(hinstDLL, "HelloWorld");
    if (HelloWorld != NULL)
        (HelloWorld);
    fFreeDLL = FreeLibrary(hinstDLL);
}
...
```

## PE (Portable Executable) format
*defines the information about the executable and stored data: also defines the structure of how data components are stored.* 

= (**P**ortable **E**xecutable) and COFF (**C**ommon **O**bject **F**ile **F**ormat)

broken up into seven components:
![[Pasted image 20260705220052.png]]
#### DOS header 
*defines the type of file*
The `MZ` DOS header defines the file format as `.exe`
```
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..........ÿÿ..
00000010  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ¸.......@.......
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00  ............è...
00000040  0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68  ..º..´.Í!¸.LÍ!Th
```
#### DOS Stub
*a program run by default at the beginning of a file that prints a compatibility message*. This does not affect any functionality of the file for most users.
=> `This program cannot be run in DOS mode`
```
00000040  0E 1F BA 0E 00 B4 09  21 B8 01 4C  21 54 68  ..º..´.Í!¸.LÍ!Th
00000050  69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F  is program canno
00000060  74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20  t be run in DOS
00000070  6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00  mode....$.......
```
#### PE File Header
*provides PE header information of the binary*. Defines the format of the file, contains the signature and image file header, and other information headers.
```
000000E0  00 00 00 00 00 00 00 00 50 45 00 00 64 86 06 00  ..........d†..
000000F0  10 C4 40 03 00 00 00 00 00 00 00 00 F0 00 22 00  .Ä@.........ð.".
00000100  0B 02 0E 14 00 0C 00 00 00 62 00 00 00 00 00 00  .........b......
00000110  70 18 00 00 00 10 00 00 00 00 00 40 01 00 00 00  p..........@....
00000120  00 10 00 00 00 02 00 00 0A 00 00 00 0A 00 00 00  ................
00000130  0A 00 00 00 00 00 00 00 00 B0 00 00 00 04 00 00  .........°......
00000140  63 41 01 00 02 00 60 C1 00 00 08 00 00 00 00 00  cA....`Á........
00000150  00 20 00 00 00 00 00 00 00 00 10 00 00 00 00 00  . ..............
00000160  00 10 00 00 00 00 00 00 00 00 00 00 10 00 00 00  ................
00000170  00 00 00 00 00 00 00 00 94 27 00 00 A0 00 00 00  ........”'.. ...
00000180  00 50 00 00 10 47 00 00 00 40 00 00 F0 00 00 00  .P...G...@..ð...
00000190  00 00 00 00 00 00 00 00 00 A0 00 00 2C 00 00 00  ......... ..,...
000001A0  20 23 00 00 54 00 00 00 00 00 00 00 00 00 00 00   #..T...........
000001B0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001C0  10 20 00 00 18 01 00 00 00 00 00 00 00 00 00 00  . ..............
000001D0  28 21 00 00 40 01 00 00 00 00 00 00 00 00 00 00  (!..@...........
000001E0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```
#### Image Optional Header
an important part of the PE file header
#### Data Dictionaries
part of the image optional header. They point to the image data directory structure.
#### Section Table
*will define the available sections and information in the image*. sections store the contents of the file, such as code, imports, and data
```
000001F0  2E 74 65 78 74 00 00 00 D0 0B 00 00 00 10 00 00  .text...Ð.......
00000200  00 0C 00 00 00 04 00 00 00 00 00 00 00 00 00 00  ................
00000210  00 00 00 00 20 00 00 60 2E 72 64 61 74 61 00 00  .... ..`.rdata..
00000220  76 0C 00 00 00 20 00 00 00 0E 00 00 00 10 00 00  v.... ..........
00000230  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40  ............@..@
00000240  2E 64 61 74 61 00 00 00 B8 06 00 00 00 30 00 00  .data...¸....0..
00000250  00 02 00 00 00 1E 00 00 00 00 00 00 00 00 00 00  ................
00000260  00 00 00 00 40 00 00 C0 2E 70 64 61 74 61 00 00  ....@..À.pdata..
00000270  F0 00 00 00 00 40 00 00 00 02 00 00 00 20 00 00  ð....@....... ..
00000280  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40  ............@..@
00000290  2E 72 73 72 63 00 00 00 10 47 00 00 00 50 00 00  .rsrc....G...P..
000002A0  00 48 00 00 00 22 00 00 00 00 00 00 00 00 00 00  .H..."..........
000002B0  00 00 00 00 40 00 00 40 2E 72 65 6C 6F 63 00 00  ....@..@.reloc..
000002C0  2C 00 00 00 00 A0 00 00 00 02 00 00 00 6A 00 00  ,.... .......j..
000002D0  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42  ............@..B
```
```dataviewjs
dv.table(["Section", "Purpose"], [
  [".text", "Contains executable code and entry point"],
  [".data", "Contains initialized data (strings, variables, etc.)"],
  [".rdata or .idata", "Contains imports (Windows API) and DLLs."],
  [".reloc", "Contains relocation information"],
  [".rsrc", "Contains application resources (images, etc.)"],
  [".debug", "Contains debug information"]
])
```
## interacting with windows internals
