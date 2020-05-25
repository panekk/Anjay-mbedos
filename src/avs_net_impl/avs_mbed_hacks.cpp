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

#include <avsystem/commons/avs_commons_config.h>

#include <memory>

#include <mbed_assert.h>
#include <nsapi_dns.h>

#include <lwip/api.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>

#include "avs_mbed_hacks.h"
#include "avs_socket_impl.h"

#if PREREQ_MBED_OS(5, 9, 0)
#    include <LWIPStack.h>
#else // mbed OS <= 5.8
#    include <lwip_stack.h>
#endif

using namespace avs_mbed_impl;
using namespace std;

namespace {

// based on
// http://web.archive.org/web/20130121234802/http://byuu.org/articles/programming/public_cast
// used get_local_address(), see there for more information
template <typename T>
struct PublicCast {
    static typename T::type value;
};

template <typename T>
typename T::type PublicCast<T>::value;

template <typename T, typename T::type P>
struct PublicCastHelper {
    static typename T::type value;
};

template <typename T, typename T::type P>
typename T::type PublicCastHelper<T, P>::value = PublicCast<T>::value = P;

struct P_socket {
    typedef nsapi_socket_t(InternetSocket::*type);
};

template struct PublicCastHelper<P_socket, &InternetSocket::_socket>;

} // namespace

// This file contains various hacks working around things that are broken on
// mbed OS. We hope to get rid of these once we manage to push necessary changes
// into mbed OS itself.
namespace avs_mbed_hacks {

nsapi_size_or_error_t dns_query_multiple(const char *host,
                                         SocketAddress *addr,
                                         nsapi_size_t addr_count,
                                         nsapi_version_t version) {
#if PREREQ_MBED_OS(5, 12, 0)
    // mbed OS >= 5.12 has the old API as well, but it's broken, resulting in
    // infinite recursion, so we use the new API even though we don't need the
    // additional argument.
    return nsapi_dns_query_multiple(nsapi_create_stack(
                                            &AvsSocketGlobal::get_interface()),
                                    host, addr, addr_count, NULL, version);
#elif PREREQ_MBED_OS(5, 7, 5)
    return nsapi_dns_query_multiple(nsapi_create_stack(
                                            &AvsSocketGlobal::get_interface()),
                                    host, addr, addr_count, version);
#else
    // In mbed OS < 5.7.5, all the overloads of nsapi_dns_query_multiple() are
    // broken, except for the one that operates on C-based types (nsapi_stack_t
    // and nsapi_addr_t). It still doesn't work as documented, but at least it
    // can get the job done.
    //
    // However, there is no way to get nsapi_stack_t * from NetworkStack * using
    // public API, so we check if it's lwIP and work only in that case for now
    nsapi_size_or_error_t result;
    if (nsapi_create_stack(&AvsSocketGlobal::get_interface())
            == nsapi_create_stack(&lwip_stack)) {
        // lwIP stack, perform the multiple query
        auto_ptr<nsapi_addr_t> nsapi_addrs(
                reinterpret_cast<nsapi_addr_t *>(operator new(
                        sizeof(nsapi_addr_t) * addr_count)));
        if (!nsapi_addrs.get()) {
            return NSAPI_ERROR_NO_MEMORY;
        }
        result = nsapi_dns_query_multiple(&lwip_stack, host, nsapi_addrs.get(),
                                          addr_count, version);
        // process the result
        if (result == 0) {
            // since the return value is broken, we don't know how many
            // addresses were actually returned; search for the first UNSPEC
            // element
            while ((nsapi_size_t) result < addr_count
                   && nsapi_addrs.get()[result].version != NSAPI_UNSPEC) {
                addr[result] = nsapi_addrs.get()[result];
                ++result;
            }
        }
    } else {
        // unsupported stack, so revert to single-result query
        MBED_ASSERT(addr_count >= 1);
        *addr = SocketAddress();
        result = nsapi_dns_query(nsapi_create_stack(
                                         &AvsSocketGlobal::get_interface()),
                                 host, addr, version);
        if (result == 0 && addr->get_ip_version() != NSAPI_UNSPEC) {
            result = 1;
        }
    }
    return result;
#endif
}

int32_t get_local_port(const InternetSocket *mbed_socket) {
    // mbed OS does not have any API for retrieving port number after binding
    // a socket to an ephemeral port.
    //
    // This hack may be removed when the following ticket is resolved:
    // https://github.com/ARMmbed/mbed-os/issues/5922
    //
    // to get this information, we need to inspect deeply private data :(
    // LwipSocketHack is partial replica of struct lwip_socket in lwip_stack.c
    // also, we use byuu's PublicCast hack to access private Socket::_socket
    // member to retrieve its pointer
    struct LwipSocketHack {
        bool in_use;
        struct netconn *conn;
    };

#if PREREQ_MBED_OS(5, 9, 0)
    NetworkStack *lwip = &LWIP::get_instance();
#else // mbed OS <= 5.8
    NetworkStack *lwip = nsapi_create_stack(&lwip_stack);
#endif
    if (nsapi_create_stack(&AvsSocketGlobal::get_interface()) == lwip) {
        LwipSocketHack *lwip_socket = reinterpret_cast<LwipSocketHack *>(
                mbed_socket->*PublicCast<P_socket>::value);
        switch (lwip_socket->conn->type) {
        case NETCONN_TCP:
            return lwip_socket->conn->pcb.tcp->local_port;
        case NETCONN_UDP:
            return lwip_socket->conn->pcb.udp->local_port;
        default:;
        }
    }
    return -1;
}

bool socket_types_match(const AvsSocket *left, const AvsSocket *right) {
    // normally we'd use typeid(*left) == typeid(*right), or even replace this
    // whole call with a dynamic_cast. But mbed applications are compiled with
    // RTTI disabled, so instead we use a little hack and compare vtables,
    // assuming that it's the first element of a polymorphic object
    return *reinterpret_cast<void *const *>(left)
           == *reinterpret_cast<void *const *>(right);
}

} // namespace avs_mbed_hacks
