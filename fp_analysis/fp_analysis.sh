#/bin/bash
#function pairs analysis

home="[absolute path of fp_analysis folder]"
project="[absolute path for openssl project folder]"
clang_build="[absolute path for clang build folder]"


#Step1: collect function pairs lists along each error path
cd $home
mkdir -p result

cd $project
make clean &> ${home}/result/clean.txt

cd $project
${clang_build}/bin/scan-build -enable-checker alpha.unix.RPEx -analyze-headers --use-analyzer ${clang_build}/bin/clang ./config &> ${home}/result/config.txt
${clang_build}/bin/scan-build -enable-checker alpha.unix.RPEx -analyze-headers --use-analyzer ${clang_build}/bin/clang make &> ${home}/result/make.txt
cd $home
mkdir -p result
python3 ./output_gatherer.py ${home}/result/openssl_path.txt $project

#Step2: statistically extract and refine function pairs
cd $home
python3 ${home}/analyze_function_pair.py ${home}/result/openssl_path.txt ${home}/result/function_pair_frequency.txt
python3 ${home}/refine_function_pair.py ${home}/result/function_pair_frequency.txt 2 > ${home}/result/function_pair_candidate.txt


echo "__RETURN_VAL__, -1, 1, NE, -1, -1, I" > ${home}/result/openssl_error_global_spec.txt
cp ${home}/result/function_pair_candidate.txt ${home}/result/openssl_pair_spec.txt


#Step3: dataflow analysis to keep only function pairs that have data dependency
cd $project
make clean &> ${home}/result/clean.txt

cd $project
${clang_build}/bin/scan-build -enable-checker alpha.unix.RPExDataflow -analyze-headers --use-analyzer ${clang_build}/bin/clang ./config &> ${home}/result/config.txt
${clang_build}/bin/scan-build -enable-checker alpha.unix.RPExDataflow -analyze-headers --use-analyzer ${clang_build}/bin/clang make &> ${home}/result/make.txt
cd $home
python3 ./output_gatherer.py ./result/openssl_function_pair_signature_analysis.txt $project
cat ./result/openssl_function_pair_signature_analysis.txt | grep "S:" |sort -k2n | uniq | sed "s/^..........//" | sed "s/.$//" > ./result/signature.txt
python3 ${home}/extract_function_pair.py ./result/signature.txt > ${home}/result/function_pairs.txt

cat ${home}/result/function_pairs.txt