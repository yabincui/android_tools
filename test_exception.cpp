#include <pthread.h>
#include <stdio.h>

class D {
  public:
    D() {
      printf("D()\n");
    }
    ~D() {
      printf("~D()\n");
    }
};

struct Exception {};

void raise() {
  //throw Exception();
  pthread_exit(nullptr);
}

void f2();

void f1() {
  D d;
  f2();
}

void* threadFunc(void*) {
  f1();
  return nullptr;
}
// Exit not in the main thread can unwind the stack

int main() {
  pthread_t thread;
  pthread_create(&thread, nullptr, threadFunc, nullptr);
  pthread_join(thread, nullptr);
  /*
  D d;
  pthread_exit(nullptr);
  */
  /*
  try {
    f1();
  } catch (...) {
  }
  */
  return 0;
}
