all: app test_exception read_cfi #unwind unwind32 readelf

app: throw.cpp cxxabi.cpp main.c Makefile
	g++ -c -o throw.o -O0 -ggdb throw.cpp
	g++ -c -o cxxabi.o -O0 -ggdb cxxabi.cpp
	gcc -c -o main.o -O0 -ggdb main.c
	gcc main.o throw.o cxxabi.o -o app
	g++ -S -o throw.s throw.cpp
	objdump -D app >b.asm
	objdump -DlS app >a.asm

test_exception: test_exception.cpp test_exception_lib.cpp Makefile
	g++ -o test_exception.o -c -std=c++11 -g test_exception.cpp
	g++ -o test_exception_lib.o -c -std=c++11 -g -fno-exceptions test_exception_lib.cpp
	g++ -o test_exception -g test_exception.o test_exception_lib.o -lpthread	

	
read_cfi: read_cfi.cpp Makefile dwarf_string.h
	g++ -g -std=c++11 -o read_cfi read_cfi.cpp

readelf: readelf.o elf_reader.o
	g++ -std=c++11 -o $@ $^

CPPFLAGS := -std=c++11 -g

unwind: unwind.o GetCurrentRegs_x86_64.o elf_reader.o map.o
	g++ -o $@ $^

unwind32: unwind_32.o GetCurrentRegs_x86_32.o elf_reader_32.o map_32.o
	g++ -m32 -o $@ $^


%_32.o : %.cpp Makefile
	g++ -m32 $(CPPFLAGS) -c -o $@ $<

%_32.o : %.S Makefile
	g++ -m32 -c -o $@ $<


%.o : %.cpp Makefile
	g++ $(CPPFLAGS) -c -o $@ $<

%.o : %.S Makefile
	g++ -c -o $@ $<
