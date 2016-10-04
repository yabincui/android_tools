app: throw.cpp cxxabi.cpp main.c
	g++ -c -o throw.o -O0 -ggdb throw.cpp
	g++ -c -o cxxabi.o -O0 -ggdb cxxabi.cpp
	gcc -c -o main.o -O0 -ggdb main.c
	gcc main.o throw.o cxxabi.o -o app
	g++ -S -o throw.s throw.cpp
	objdump -D app >b.asm
	objdump -DlS app >a.asm
