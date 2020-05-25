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

#ifndef AVS_SOCKET_GLOBAL_H
#define AVS_SOCKET_GLOBAL_H

#include <NetworkInterface.h>

#include <avsystem/commons/avs_list_cxx.hpp>
#include <avsystem/commons/avs_net.h>

class AvsSocketGlobal {
    static NetworkInterface *INTERFACE;
    static uint8_t MAX_DNS_RESULTS;
    static size_t RECV_BUFFER_SIZE;
    static avs_net_af_t PREFERRED_FAMILY;

public:
    AvsSocketGlobal(NetworkInterface *interface,
                    uint8_t max_dns_results,
                    size_t recv_buffer_size,
                    avs_net_af_t preferred_family);
    ~AvsSocketGlobal();

    static NetworkInterface &get_interface();
    static uint8_t max_dns_result();
    static size_t recv_buffer_size();
    static avs_net_af_t preferred_family();

    static int poll(avs::List<avs_net_socket_t *> &out,
                    const avs::ListView<avs_net_socket_t *const> &avs_sockets,
                    uint32_t timeout_ms);
};

#endif /* AVS_SOCKET_GLOBAL_H */
