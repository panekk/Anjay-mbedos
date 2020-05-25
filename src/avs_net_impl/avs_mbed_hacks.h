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

#ifndef AVS_MBED_HACKS_H
#define AVS_MBED_HACKS_H

#include <mbed.h>

#define PREREQ_MBED_OS(Maj, Min, Patch) \
        (MBED_MAJOR_VERSION > (Maj) \
                || (MBED_MAJOR_VERSION == (Maj) && MBED_MINOR_VERSION > (Min)) \
                || (MBED_MAJOR_VERSION == (Maj) && MBED_MINOR_VERSION == (Min) \
                        && MBED_PATCH_VERSION >= (Patch)))

#if PREREQ_MBED_OS(5, 10, 0)
#include <InternetSocket.h>
#else // mbed OS < 5.10
typedef Socket InternetSocket;
#endif

#include "avs_socket_impl.h"

namespace avs_mbed_hacks {

nsapi_size_or_error_t dns_query_multiple(const char *host,
                                         SocketAddress *addr,
                                         nsapi_size_t addr_count,
                                         nsapi_version_t version);

int32_t get_local_port(const InternetSocket *mbed_socket);

bool socket_types_match(const avs_mbed_impl::AvsSocket *left,
                        const avs_mbed_impl::AvsSocket *right);

}

#endif /* AVS_MBED_HACKS_H */

