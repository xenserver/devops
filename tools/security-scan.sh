#!/bin/bash

if [ ! -f hosts ]; then
   echo "Error: Unable to find the 'hosts' file that should contain list of host or IP addreses to check, one per line."
   exit 1
fi


while read p; do
  python hb-test.py $p  >/tmp/report_$p.log 2>&1
  RESULT=$?
  if [ "$RESULT" -ne 0 ]; then
    echo "fail ($RESULT): $p"
  else
    echo "ok      : $p"
  fi
done < hosts
