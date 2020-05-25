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

#include <avsystem/commons/avs_defs.h>

extern "C" {
#include <avsystem/commons/avs_init_once.h>
} // extern "C"

#include "avs_mbed_hacks.h"

namespace {

rtos::Mutex g_init_once_mutex;

// in mbed OS >= 5.8, ScopedMutexLock is preimplemented
#if !PREREQ_MBED_OS(5, 8, 0)
class ScopedMutexLock {
    rtos::Mutex &mtx_;

public:
    ScopedMutexLock(rtos::Mutex &mtx) : mtx_(mtx) {
        if (mtx.lock() != osOK) {
            AVS_UNREACHABLE("failed to lock mutex");
        }
    }

    ~ScopedMutexLock() {
        mtx_.unlock();
    }
};
#endif

enum init_state { INIT_NOT_STARTED, INIT_IN_PROGRESS, INIT_DONE };

} // namespace

extern "C" {

int avs_init_once(volatile avs_init_once_handle_t *handle,
                  avs_init_once_func_t *func,
                  void *func_arg) {
    ScopedMutexLock lock(g_init_once_mutex);
    volatile int *state = (volatile int *) handle;

    AVS_ASSERT(*state != INIT_IN_PROGRESS,
               "unexpected init state (recursive init_once call?)");

    int result = 0;
    if (*state != INIT_DONE) {
        *state = INIT_IN_PROGRESS;
        result = func(func_arg);
        if (result) {
            *state = INIT_NOT_STARTED;
        } else {
            *state = INIT_DONE;
        }
    }

    return result;
}

} // extern "C"
