all: helloworld/main.test nonzeroexit/main.test

helloworld/main.test: helloworld/main.cpp
	g++ helloworld/main.cpp -o helloworld/main.test

nonzeroexit/main.test: nonzeroexit/main.cpp
	g++ nonzeroexit/main.cpp -o nonzeroexit/main.test

clean:
	rm -rf helloworld/*.test nonzeroexit/*.test
