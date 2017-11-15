# ErrDoc

## Installation
### Prerequisites for ErrDoc bugfinder
CMake    
Clang and LLVM: http://clang.llvm.org/get_started.html.   
Python3 
### Prerequisites for ErrDoc patcher
Clang Libtooling: https://clang.llvm.org/docs/LibASTMatchersTutorial.html    
Bear: https://github.com/rizsotto/Bear
## Source Files
#### *ErrDocAllPath.cpp*
Explore and output all paths of a C program.
[Usage](#errdocallpathcpp-1)
#### *ErrDocErrPath.cpp*  
Explore and output error paths of a C program.    
#### *ErrDocNerrPath.cpp*  
Explore and output non-error paths of a C program.     
#### *ErrDocRR.cpp* 
Find RR bugs and output buggy line and bugfix line.    

## Usage and Example
### Path exploration
#### *ErrDocAllPath.cpp* 
1. Copy this file to [llvm source folder]/tools/clang/lib/StaticAnalyzer/Checkers/
2. Register the alpha.unix.ErrDocAllPath checker:    
Open [llvm source folder]/tools/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td, look for the block starting with let ParentPackage = UnixAlpha in, and inside it, add the text:
```
    def ErrDocAllPath : Checker<"ErrDocAllPath">,
        HelpText<"Explore all paths">,
        DescFile<"ErrDocAllPath.cpp">;
```
3. Register this checker to be compiled:    
Open [llvm source folder]/tools/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt, add the line ErrDocAllPath.cpp.
4. Build llvm/clang: Inside the build directory, run ```make```.
5. Run checker on example.c (Use [llvm/clang build folder]/bin/scan-build for projects.):  
```[llvm/clang build folder]/bin/clang -cc1 -I/usr/include  -I[path to llvm/clang build folder]/lib/clang/[clang version]/include/ -w -analyze -analyzer-checker=alpha.unix.ErrDocAllPath example.c ``` 

to be continued....
