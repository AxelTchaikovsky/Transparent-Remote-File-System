all: mylib.so server

server: server.c marshall.h
	gcc -Wall -Werror server.c -o server

mylib.o: mylib.c marshall.h
	gcc -Wall -Werror -fPIC -DPIC -c mylib.c

mylib.so: mylib.o
	ld -shared -o mylib.so mylib.o -ldl

clean:
	rm -f *.o *.so

