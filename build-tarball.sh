#!/bin/sh -e
mkdir -p out/${OUTPUT_FILENAME}
cd out

go build -o ${OUTPUT_FILENAME}/kube-bench .
cp LICENSE ${OUTPUT_FILENAME}/LICENSE
cp README.md ${OUTPUT_FILENAME}/README.md
cp -rf cfg ${OUTPUT_FILENAME}/cfg

tar -czf ${OUTPUT_FILENAME}.tar.gz ${OUTPUT_FILENAME}
