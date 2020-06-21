#!/bin/sh

echo "start ?????"

while true ;do
  COUNT=$(ps -ef |grep sniff |grep -v "grep" |wc -l) 
  echo $COUNT
  echo $(ps -a)
  if [ $COUNT -eq 0 ]
  then
    echo "process has been restarted!"
    echo $COUNT
    ./sniff -device=en0   
  fi
  sleep 1
done
    
	