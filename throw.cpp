#include "throw.h"

#include <stdio.h>

extern "C" {

class D {
  public:
   D() {
    printf("D::D()\n");
   }
   ~D() {
    printf("D::~D()\n");
   }
};


struct FakeException{};

void raise() {
  throw Exception();
}

void tryButDontCatch() {
  D d;
  try {
    printf("Run a try which will never throw\n");
  } catch (FakeException&) {
    printf("Exception caught... with the wrong catch!\n");
  }

  try {
    raise();
  } catch(FakeException&) {
    printf("Run tryButDontCatch::catch(FakeException)\n");
  }
  printf("tryButDontCatch handled an exception and resumed execution\n");
}

void catchIt() {
  try {
    tryButDontCatch();
  } catch(FakeException&) {
    printf("Run tryButDontCatch::catch(FakeException)\n");
  } catch(Exception&) {
    printf("Run tryButDontCatch::catch(Exception)\n");
  }
  printf("catchIt handled an exception and resumed execution\n");
}

void withDestructor() {
  D d;
  raise();
}

void runDestructors() {
  try {
    withDestructor();
  } catch(Exception&) {
    printf("runDestructors::catch(Exception&)\n");
  }
}

void throwFunc() {
  catchIt();
  //runDestructors();
}

}
