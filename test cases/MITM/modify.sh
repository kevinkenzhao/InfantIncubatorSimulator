#!/bin/bash
read MESSAGE
if grep -q "UPDATE" <<< "$MESSAGE"
then
	var=$(echo "$MESSAGE" | awk '{ sub(/UPDATE/,"GET"); print }')
	echo $var
elif grep -q "GET" <<< "$MESSAGE"
then
	var=$(echo "$MESSAGE" | awk '{ sub(/GET/,"UDPATE"); print }')
	echo $var
else
	echo $MESSAGE
fi

