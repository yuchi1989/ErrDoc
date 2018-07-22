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
*RR/ErrDocRR.cpp*: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Find RR bugs and output buggy line and bugfix line.             [Usage and Example](#rr-bugs-detection)  
*ErrDocEP.cpp*:          Find EP and EC bugs.   
*RRPatcher.cpp*:         Patch RR bugs.    
*EPPatcher.cpp*:         Patch EP and EC bugs.    

## Usage and Example
### 1.Path exploration
#### Introduction
The path exploration checkers are tools to traverse paths like error paths or non-error paths, which can be used for further program analysis. The following path exploration checkers can be used for general program analysis purpose.
#### Example
##### *ErrDocAllPath.cpp* 
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

##### *ErrDocErrPath.cpp* 
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
#### Introduction
Function pairs analysis can be used to infer functions that work in pairs, for example, malloc and free. With the identified function pairs and corresponding signatures, the RR bugs can be identified and fixed.
#### Methodology
1. Collect function calls lists along each error path.(*RPEx.cpp*)    
2. Extract initial function pairs and compute their frequency by pairing function calls before target function call with ones after target function call along an error path.(*extract_function_pairs.py*)    
3. Rank and refine function pairs.(*refine_function_pairs.py*)    
4. Do the dataflow analysis to discard the funtion pairs that do not have data dependency.(*RPExDataflow.cpp*)
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
#### RR bugs detection
 
1. Edit the following lines in *ErrDocRR.cpp*.    
```
#define ERROR_SPEC_NAME "[error_spec.txt]"
#define FUNCTION_PAIRS_SPEC "[function_pairs_spec.txt]"
```

2. Build and register checker *ErrDocRR.cpp*.   
##### example1(RR/RRexample.c):
1. Edit the following lines and build checker *ErrDocRR.cpp*.    
```
   #define ERROR_SPEC_NAME "[absolute path of RR/RR_example_error_spec.txt]"
   #define FUNCTION_PAIRS_SPEC "[absolute path of RR/RR_example_function_pairs_spec.txt]"
```
2. Run the following commands:    
```
./build/bin/clang -cc1 -I/usr/include  -I./build/lib/clang/3.9.0/include/ -w -analyze -analyzer-checker=alpha.unix.ErrDocRR RRexample.c 
cat *.e.log
python3 ../extract_RR_results.py *.e.log
```
Results:    
```
ErrDocRR detects 3 RR bugs
ErrDocRR: B: left function pair:  malloc, filename: example3.c, caller name: start_malloc, bug line number: 4, source file name: example3.c; bugfix line number: 15, function pair signature: 0:free:1
ErrDocRR: B: left function pair:  malloc, filename: example3.c, caller name: start_malloc, bug line number: 9, source file name: example3.c; bugfix line number: 15, function pair signature: 0:free:1
ErrDocRR: B: left function pair:  malloc, filename: example3.c, caller name: start_malloc, bug line number: 4, source file name: example3.c; bugfix line number: 11, function pair signature: 0:free:1
```
##### example2(openssl):
1. Edit the following lines and build checker *ErrDocRR.cpp*.  
File openssl_error_global_spec.txt and openssl_function_pair_signature_analysis.txt are outputs from previous function pairs analysis. We can also manually created the two files.    
```
#define ERROR_SPEC_NAME "fp_analysis/result/openssl_error_global_spec.txt"
#define FUNCTION_PAIRS_SPEC "fp_analysis/result/openssl_function_pair_signature_analysis.txt"
```
2. Run the following commands:    
```
cd $openssl
${clang_build}/bin/scan-build -enable-checker alpha.unix.ErrDocRR -analyze-headers --use-analyzer ${clang_build}/bin/clang ./config 
${clang_build}/bin/scan-build -enable-checker alpha.unix.ErrDocRR -analyze-headers --use-analyzer ${clang_build}/bin/clang make 
cd $home
python3 ./output_gatherer.py ./result/openssl_bugs_analysis.txt $openssl
cat ./result/openssl_bugs_analysis.txt | grep "O:" |sort -k2n | uniq
python3 ./extract_RR_results.py ./result/openssl_bugs_analysis.txt | grep "B:" |sort -k2n | uniq > ./result/openssl_bugs.txt
```

#### EP bugs detection
 
1. Edit the following lines in *ErrDocRR.cpp*.    
```
#define ERROR_SPEC_NAME "[error_spec.txt]"
#define TARGET_FUNCTION_ERROR_SPEC_NAME "[target_spec.txt]"
```

2. Build and register checker *ErrDocRR.cpp*.   
##### example1(EP/example.c):
1. Edit the following lines and build checker *ErrDocEP.cpp*.    
```
   #define ERROR_SPEC_NAME "[absolute path of EP/error_spec.txt]"
   #define TARGET_FUNCTION_ERROR_SPEC_NAME "[absolute path of EP/target_spec.txt]"
```
2. Run the following commands:    
```
./build/bin/clang -cc1 -I/usr/include  -I./build/lib/clang/3.9.0/include/ -w -analyze -analyzer-checker=alpha.unix.ErrDocEP example.c
cat *.e.log
```
Results:    
```


```
### 4.ErrDoc patcher
to be continued....

## Acknowledgements:
* Clang static analyzer: https://clang-analyzer.llvm.org/
* EPEx: https://github.com/yujokang/EPEx
