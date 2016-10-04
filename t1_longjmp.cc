// Test if longjmp can cause unwinding.

#include <stdio.h>
#include <setjmp.h>

jmp_buf env;

class D {
  public:
    D() {
      printf("D()\n");
    }
    ~D() {
      printf("~D()\n");
    }
};

void second() {
  printf("second\n");
  D d;
  longjmp(env, 1);
}

void first() {
  printf("first\n");
  D d;
  second();
}

int main() {
  if (!setjmp(env)) {
    first();
  } else {
    printf("main\n");
  }
  return 0;
}

