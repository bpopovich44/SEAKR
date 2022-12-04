#!/bin/bash

nodes=(n00 n02 n03 n05 n06 n08 n09 n10 n20 n21 n22 n23 n24 n25)

for f in ${nodes[@]}
do

        bsub -m "$f" -J script_lsf_$f sleep 100
        echo "$f"
done
