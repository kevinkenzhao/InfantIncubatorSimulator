kill -9 $(sudo lsof -t -i:23456)
kill -9 $(sudo lsof -t -i:5557)
sleep 3 #allot time for termination of above processes 

python3 SampleNetworkServer.py & #start server in the background
sleep 1
socat -u tcp-l:5557,fork system:./test.sh | nc -u 127.0.0.1 23456 & #start socat with script that rewrites commands; modified commands are piped to port 23456
sleep 1
token="$(echo "AUTH !Q#E%T&U8i6y4r2w" | nc -w 3 -u 127.0.0.1 23456)" #terminate netcat after three seconds
echo "the token: ${token}"
sleep 1
echo "issuing UPDATE_TEMP command to server..."
UPDATE_CMD="${token};UPDATE_TEMP"
echo "full command: ${UPDATE_CMD}"
echo "${UPDATE_CMD}" | nc -w 3 127.0.0.1 5557
#kill -9 $(sudo lsof -t -i:23456)
#kill -9 $(sudo lsof -t -i:5557)
