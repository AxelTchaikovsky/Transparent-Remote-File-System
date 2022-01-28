all: mylib.so server

mylib.o: mylib.c marshall.h
	gcc -Wall -Werror -fPIC -DPIC -c mylib.c

mylib.so: mylib.o
	ld -shared -o mylib.so mylib.o -ldl

server: server.c marshall.h ../include/dirtree.h
	gcc -Wall -Werror server.c -o server -I../include -L../lib -ldirtree

clean:
	rm -f *.o *.so

