# ErrDoc

## Installation
### Prerequisites for ErrDoc pathexplorer and bugfinder
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
#### *ErrDocEP.cpp* 
Find EP and EC bugs. 
#### *RRPatcher.cpp* 
Patch RR bugs.
#### *EPPatcher.cpp* 
Patch EP and EC bugs.

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

#### *ErrDocErrPath.cpp* 
0. #define ERROR_SPEC_NAME "/home/tyc/clang/work/example11/rpex/workflow/test/error_spec.txt"
1. Copy this file to [llvm source folder]/tools/clang/lib/StaticAnalyzer/Checkers/
2. Register the alpha.unix.ErrDocErrPath checker:    
Open [llvm source folder]/tools/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td, look for the block starting with let ParentPackage = UnixAlpha in, and inside it, add the text:
```
    def ErrDocErrPath : Checker<"ErrDocErrPath">,
        HelpText<"Explore error paths">,
        DescFile<"ErrDocErrPath.cpp">;
```
3. Register this checker to be compiled:    
Open [llvm source folder]/tools/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt, add the line ErrDocAllPath.cpp.
4. Build llvm/clang: Inside the build directory, run ```make```.
5. Run checker on example.c (Use [llvm/clang build folder]/bin/scan-build for projects.):    
```echo "malloc, -1, 0, EQ, -1, -1, P" > error_spec.txt"```   
```echo "__RETURN_VAL__, -1, 0, NE, -1, -1, I" >> error_spec.txt"```   
```[llvm/clang build folder]/bin/clang -cc1 -I/usr/include  -I[path to llvm/clang build folder]/lib/clang/[clang version]/include/ -w -analyze -analyzer-checker=alpha.unix.ErrDocErrPath example.c ```   

### ErrDoc bugfinder
### ErrDoc patcher
to be continued....
