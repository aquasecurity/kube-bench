#!/bin/sh -e
mkdir -p out/${OUTPUT_FILENAME}

go build -o out/${OUTPUT_FILENAME}/kube-bench .
cp LICENSE out/${OUTPUT_FILENAME}/LICENSE
cp README.md out/${OUTPUT_FILENAME}/README.md
cp -rf cfg out/${OUTPUT_FILENAME}/cfg

tar -czf out/${OUTPUT_FILENAME}.tar.gz out/${OUTPUT_FILENAME}
