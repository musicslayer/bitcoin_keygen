// Copyright (c) 2016 Llamasoft

#include <time.h>
#include "timer.h"


struct timespec get_clock() {
    struct timespec now_clock;
    clock_gettime(CLOCK_MONOTONIC, &now_clock);

    return now_clock;
}


long get_clockdiff_ns(struct timespec prev_clock) {
    struct timespec now_clock = get_clock();

    return (long)(now_clock.tv_sec  - prev_clock.tv_sec ) * TO_NANOSECOND
         + (long)(now_clock.tv_nsec - prev_clock.tv_nsec);
}


// TO_NANOSECOND / TO_MILLISECOND = TO_MICROSECOND
// I hate reinventing the wheel, but simply doing get_clockdiff_ns() / 1000000
//   may not work if the high bits of get_clockdiff_ns() have overflowed
long get_clockdiff_ms(struct timespec prev_clock) {
    struct timespec now_clock = get_clock();

    return (long)(now_clock.tv_sec  - prev_clock.tv_sec ) * TO_MILLISECOND
         + (long)(now_clock.tv_nsec - prev_clock.tv_nsec) * TO_MILLISECOND / TO_NANOSECOND;
}


// Ditto for here, except overflows converted to doubles have a tendancy
//   to result in negative values
double get_clockdiff_s(struct timespec prev_clock) {
    struct timespec now_clock = get_clock();

    return (double)(now_clock.tv_sec  - prev_clock.tv_sec )
         + (double)(now_clock.tv_nsec - prev_clock.tv_nsec) / TO_NANOSECOND;
}