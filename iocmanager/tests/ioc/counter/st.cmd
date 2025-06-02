#!/usr/bin/bash
for num in {1..1000}
do
    echo "$num";
    sleep 1;
done
echo "Exiting counter fake IOC (probably something went wrong if we counted to 1000)"
