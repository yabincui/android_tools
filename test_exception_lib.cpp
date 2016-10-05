#include <pthread.h>
#include <stdio.h>

class C {
  public:
    C() {
      printf("C()\n");
    }
    ~C() {
      printf("~C()\n");
    }
};

void raise2() {
  pthread_exit(nullptr);
}

void f2() {
  C c;
  raise2();
}
