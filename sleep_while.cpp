#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

uint64_t GetTimeInNs() {
  timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void BusyFunction(uint64_t busy_time) {
  uint64_t end_time = GetTimeInNs() + busy_time;
  while (true) {
	if (GetTimeInNs() >= end_time) {
		break;
	}
  }
}

void sleepFunction(uint64_t sleep_time) {
  timespec req, rem;
  req.tv_sec = sleep_time / 1000000000;
  req.tv_nsec = sleep_time % 1000000000;
  while (true) {
    int ret = nanosleep(&req, &rem);
    if (ret == 0) break;
    if (rem.tv_sec == 0 && rem.tv_nsec == 0) {
      break;
    }
    printf("rem.tv_sec = %d, rem.tv_nsec = %d\n", (int)rem.tv_sec, (int)rem.tv_nsec);
    req = rem;
  }
}

int main() {
  while (true) {
    int duration_time = 1000000000;
    printf("start loop\n");
    BusyFunction(duration_time);
    printf("after busy\n");
    sleepFunction(duration_time);
    printf("after sleep\n");
  }
}
