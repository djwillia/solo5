#!/bin/bash

echo "UKVM_MODULE_FILES= \\"
for m in $@; do
    echo "ukvm-$m.c \\"
done
echo 
echo "UKVM_MODULE_FLAGS= \\"
for m in $@; do
    echo "-DUKVM_MODULE_${m^^} \\"
done
echo 
