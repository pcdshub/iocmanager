#!/usr/bin/bash
num=0
while true; do
    echo $num
    sleep 1
    (( num += 1 ))
done
