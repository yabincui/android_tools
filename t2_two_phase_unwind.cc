// TEST if the unwind phases are divided to search phase and cleanup phase.
// If the handler can't be found, the cleanup phase will not be called.

#include <stdio.h>

class D {
  public:
    D() {
      fprintf(stderr, "D()\n");
    }
    ~D() {
      fprintf(stderr, "~D()\n");
    }
};

void first() {
  D d;
  throw 1;
}

int main() {
  try {
    first();
  } catch (int) {
    fprintf(stderr, "exception caught for an int\n");
  }
  fprintf(stderr, "main\n");
  return 0;
}
