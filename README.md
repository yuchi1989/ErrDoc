# ErrDoc

## What is ErrDoc?
ErrDoc is a tool that is able to detect, categorize and fix error handling bugs for C programs. The technique is described in detail in 2017 FSE paper *Automatically Diagnosing and Repairing Error Handling Bugs in C* by Yuchi Tian and Baishakhi Ray.
## Prerequisites
### ErrDoc pathexplorer and bugfinder
CMake    
Clang and LLVM: http://clang.llvm.org/get_started.html.   
Python3 
### ErrDoc patcher
Clang Libtooling: https://clang.llvm.org/docs/LibASTMatchersTutorial.html    
Bear: https://github.com/rizsotto/Bear
## Source Files

*ErrDocAllPath.cpp*:    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Explore and output all paths of a C program. [Usage](#errdocallpathcpp)    
*ErrDocErrPath.cpp*:    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Explore and output error paths of a C program. [Usage](#errdocerrpathcpp)    
*ErrDocNerrPath.cpp*:   &nbsp;&nbsp;&nbsp;&nbsp; Explore and output non-error paths of a C program. <br />    
*fp_analysis/*:   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [Usage and Example](#2errdoc-function-pairs-analysis)    
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Analyze function pairs signatures for C programs, which are used by ErrDocRR.cpp for identifying RR bugs.    
*fp_analysis/RPEx.cpp*:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Collect all function calls lists for each caller along each error path.      
*fp_analysis/RPExDatafolw.cpp*:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Using dataflow analysis to remove function pairs that do not have data dependency.   
 <br />
*ErrDocRR.cpp*:          Find RR bugs and output buggy line and bugfix line.   
*ErrDocEP.cpp*:          Find EP and EC bugs.   
*RRPatcher.cpp*:         Patch RR bugs.    
*EPPatcher.cpp*:         Patch EP and EC bugs.    

## Usage and Example
### 1.Path exploration
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
5. Run checker on pathexample.c (Use *[llvm/clang build folder]/bin/scan-build* for projects.):    
```[llvm/clang build folder]/bin/clang -cc1 -I/usr/include  -I[llvm/clang build folder]/lib/clang/[clang version]/include/ -w -analyze -analyzer-checker=alpha.unix.ErrDocAllPath pathexample.c ```

#### *ErrDocErrPath.cpp* 
1. Edit the following line in the source file.    
      ```#define ERROR_SPEC_NAME "ERR_SPEC_FILE"```    
      Replace the ERR_SPEC_FILE with the absolute path of the error specification file.    
      For example:    
      ```#define ERROR_SPEC_NAME "/home/user/download/error_spec.txt"```    
      
2. Copy this file to [llvm source folder]/tools/clang/lib/StaticAnalyzer/Checkers/
3. Register the alpha.unix.ErrDocErrPath checker:    
Open [llvm source folder]/tools/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td, look for the block starting with let ParentPackage = UnixAlpha in, and inside it, add the text:
```
    def ErrDocErrPath : Checker<"ErrDocErrPath">,
        HelpText<"Explore error paths">,
        DescFile<"ErrDocErrPath.cpp">;
```
4. Register this checker to be compiled:    
Open [llvm source folder]/tools/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt, add the line ErrDocAllPath.cpp.
5. Build llvm/clang: Inside the build directory, run ```make```.
6. Run checker on pathexample.c (Use *[llvm/clang build folder]/bin/scan-build* for projects.):    
```echo "malloc, -1, 0, EQ, -1, -1, P" > /home/user/download/error_spec.txt```    
```echo "__RETURN_VAL__, -1, 0, NE, -1, -1, I" >> /home/user/download/error_spec.txt```    
```[llvm/clang build folder]/bin/clang -cc1 -I/usr/include  -I[llvm/clang build folder]/lib/clang/[clang version]/include/ -w -analyze -analyzer-checker=alpha.unix.ErrDocErrPath pathexample.c ```   

### 2.ErrDoc function pairs analysis
#### Methodology
1. Collect function calls lists along each error path.    
2. Call extract_function_pairs.py to extract initial function pairs and compute their frequency.    
3. Call refine_function_pairs.py to rank and refine function pairs.    
4. Do the dataflow analysis to keep the funtion pairs with data dependency.
#### Example
1. Edit the following line in *RPEx.cpp* to replace the relative path with absolute path    
```#define ERROR_SPEC_NAME "fp_analysis/openssl_error_spec.txt"```    
2. Edit the following lines in *RPExDataflow.cpp* to replace the relative path with absolute path    
```
#define ERROR_SPEC_NAME "fp_analysis/result/openssl_error_global_spec.txt"
#define FUNCTION_PAIRS_SPEC "fp_analysis/result/openssl_pair_spec.txt"
```    
3. Build both checkers(*RPEx.cpp* and *RPExDataflow.cpp*) the same way as previous path explorer checkers
4. Pull project openssl and edit the following three lines of file *fp_analysis/fp_analysis.sh*
```
home="[absolute path of fp_analysis folder]"
project="[absolute path for openssl project folder]"
clang_build="[absolute path for clang build folder]"
```    
5.  Run *fp_analysis.sh*    
### 3.ErrDoc bugfinder
### 4.ErrDoc patcher
to be continued....

## Acknowledgements:
* Clang static analyzer: https://clang-analyzer.llvm.org/
* EPEx: https://github.com/yujokang/EPEx
