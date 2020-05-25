/*
 * Copyright 2020 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hal/us_ticker_api.h>
#include <mbed.h>

#include <avsystem/commons/avs_time.h>

// OK, this is a tricky one.
//
// mbed OS gives us a ticker, which is a 64-bit number in microseconds. This
// gives us a high resolution monotonic clock with enough range to not overflow
// in over 584000 years. Awesome.
//
// It's much worse in terms of the real time. Many of the platforms include an
// RTC, but all the public APIs do not have any subsecond precision.
//
// So, what we do:
//
// - When either the monotonic or the real-time clock is queried through
//   Commons, we query both through mbed OS.
//
// - We maintain a global value that stores high precision difference between
//   both clocks, so that we can calculate high precision real time as:
//
//       REALTIME = MONOTONIC - MONOTONIC_MINUS_REALTIME
//
// - We check whether the difference between the clock did not change too much
//   during execution. This may happen e.g. if the RTC has been adjusted using
//   stime(); maybe there is an NTP thread running or something like that?
//
// - In case we detect RTC readjustment, we recalculate MONOTONIC_MINUS_REALTIME
//   by actively waiting for the second-precision RTC to "flip value",
//   signifying the start of the RTC's second. We then store the current
//   difference between both clocks.
//
// - Note that when we query the clocks, the actual difference between the
//   ticker and the RTC will drift away from the stored value.
//
//   For example, when we measure MONOTONIC_MINUS_REALTIME value, let's say the
//   RTC reads 1000 (as UNIX timestamp), and the ticker is at 1234567890
//   microseconds. MONOTONIC_MINUS_REALTIME, expressed in microseconds, will
//   then be set to 234567890. Now let's say that 2.5 seconds passes. The RTC
//   will be at 1002 s, and the ticker at 1237067890 us -- the difference
//   between the two being 235067890 us, i.e. half a second more than the
//   initially calculated value.
//
//   In the end, due to the RTC value being updated only after a whole second
//   passes, it is expected that the "monotonic minus realtime" difference might
//   be bigger than up to a second from the stored value, which is always
//   calculated at the beginning of the RTC's second.
//
//   To accomodate for slight inaccuracies in keeping time by both mechanisms,
//   we actually allow the "monotonic minus realtime" value to drift a little
//   more, so that the stored value is considered valid if subtracting it from
//   the actually measured value yields a value anywhere in the range:
//
//       (-DRIFT_LEEWAY, 1 s + DRIFT_LEEWAY)
//
//   The allowed leeway is controlled by the macro below.

#define DRIFT_LEEWAY_MS 100

namespace {

const avs_time_duration_t MIN_DRIFT =
        avs_time_duration_from_scalar(-DRIFT_LEEWAY_MS, AVS_TIME_MS);
const avs_time_duration_t MAX_DRIFT =
        avs_time_duration_from_scalar(1000 + DRIFT_LEEWAY_MS, AVS_TIME_MS);

Mutex MONOTONIC_MINUS_REAL_MUTEX;
avs_time_duration_t MONOTONIC_MINUS_REAL = AVS_TIME_DURATION_INVALID;

class MonotonicMinusRealLockGuard {
public:
    MonotonicMinusRealLockGuard() {
        MONOTONIC_MINUS_REAL_MUTEX.lock();
    }

    ~MonotonicMinusRealLockGuard() {
        MONOTONIC_MINUS_REAL_MUTEX.unlock();
    }

private:
    MonotonicMinusRealLockGuard(const MonotonicMinusRealLockGuard &);
    MonotonicMinusRealLockGuard &operator=(const MonotonicMinusRealLockGuard &);
};

avs_time_duration_t get_monotonic_minus_real() {
    MonotonicMinusRealLockGuard lock;
    return MONOTONIC_MINUS_REAL;
}

void set_monotonic_minus_real(avs_time_duration_t new_value) {
    MonotonicMinusRealLockGuard lock;
    MONOTONIC_MINUS_REAL = new_value;
}

struct CurrentTime {
    time_t rtc_value_s;
    uint64_t ticker_value_us;

    avs_time_duration_t ticker_minus_rtc() const {
        return avs_time_duration_from_scalar(
                (int64_t) (ticker_value_us - 1000000 * (uint64_t) rtc_value_s),
                AVS_TIME_US);
    }

    avs_time_duration_t drift() const {
        return avs_time_duration_diff(ticker_minus_rtc(),
                                      get_monotonic_minus_real());
    }
};

#ifdef TARGET_RZA1XX
extern "C" uint64_t us_ticker_read64();
#endif // TARGET_RZA1XX

CurrentTime current_time() {
    CurrentTime result;
    result.rtc_value_s = time(NULL);
#if MBED_MAJOR_VERSION > 5 \
        || (MBED_MAJOR_VERSION == 5 && MBED_MINOR_VERSION >= 5)
    // mbed OS >= 5.5
    result.ticker_value_us = ticker_read_us(get_us_ticker_data());
#else
    // mbed OS <= 5.4 has a 32-bit ticker, so the value overflows after 2**32
    // microseconds, or around 71.5 minutes. This causes all kinds of issues
    // related to timekeeping, and we were unable to find a satisfying method
    // of working around this problem using mbed OS API only. For GR-LYCHEE,
    // the underlying ticker is in fact 64-bit, but is only truncated to
    // 32-bit to satisfy mbed OS API. Code below relies on a patch exposing
    // 64-bit ticker value via custom us_ticker_read64 function. Making it
    // compatible with other targets will require similar hacks.
#    ifdef TARGET_RZA1XX
    // defined in mbed-os/targets/TARGET_RENESAS/TARGET_RZA1XX/us_ticker.c
    // NOTE: requires applying rza1xx-64bit-ticker.patch on mbed-os repository
    result.ticker_value_us = us_ticker_read64();
#    else // TARGET_RZA1XX
#        error "mbed OS <= 5.4 uses a 32-bit microsecond ticker, which is too short " \
       "to make Anjay work correctly. Either update mbed OS to >= 5.5, or " \
       "provide a 64-bit ticker implementation for your platform in place " \
       "of this error message."
#    endif // TARGET_RZA1XX
#endif
    return result;
}

CurrentTime current_time_synchronized() {
    CurrentTime current = current_time();
    avs_time_duration_t drift = current.drift();
    if (!avs_time_duration_less(drift, MAX_DRIFT)
            || !avs_time_duration_less(MIN_DRIFT, drift)) {
        // update TICKER_MINUS_RTC, this might block for up to a second
        CurrentTime base = current;
        do {
            current = current_time();
        } while (base.rtc_value_s == current.rtc_value_s);
        set_monotonic_minus_real(current.ticker_minus_rtc());
    }
    return current;
}

} // namespace

avs_time_monotonic_t avs_time_monotonic_now(void) {
    return avs_time_monotonic_from_scalar(
            current_time_synchronized().ticker_value_us, AVS_TIME_US);
}

avs_time_real_t avs_time_real_now(void) {
    avs_time_monotonic_t monotonic_now = avs_time_monotonic_now();
    avs_time_real_t result;
    result.since_real_epoch =
            avs_time_duration_diff(monotonic_now.since_monotonic_epoch,
                                   get_monotonic_minus_real());
    return result;
}
