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

#include <algorithm>

#include <time.h>

#include <avsystem/commons/avs_addrinfo.h>
#include <avsystem/commons/avs_commons_config.h>

#include "avs_mbed_hacks.h"
#include "avs_socket_impl.h"

using namespace avs_mbed_hacks;
using namespace avs_mbed_impl;
using namespace std;

struct avs_net_addrinfo_struct {
    bool v4mapped;
    uint8_t count;
    uint8_t current_index;
    SocketAddress results[1]; // actually a VLA
};

namespace {

static SocketAddress create_v4mapped(const SocketAddress &addr) {
    MBED_ASSERT(addr.get_ip_version() == NSAPI_IPv4);
    uint8_t bytes[16];
    memset(bytes, 0, sizeof(bytes));
    bytes[10] = 0xFF;
    bytes[11] = 0xFF;
    memcpy(&bytes[12], addr.get_ip_bytes(), 4);
    return SocketAddress(bytes, NSAPI_IPv6, addr.get_port());
}

void prioritize_preferred(avs_net_addrinfo_t *ctx,
                          const SocketAddress &preferred) {
    for (uint8_t i = 0; i < ctx->count; ++i) {
        if (ctx->results[i] == preferred) {
            if (i != 0) {
                swap(ctx->results[0], ctx->results[i]);
            }
            return;
        }
    }
}

class AvsRand {
    unsigned seed_;

public:
    AvsRand() : seed_(time(NULL)) {}

    int operator()(size_t range) {
        MBED_ASSERT(range <= AVS_RAND_MAX);
        return avs_rand_r(&seed_) % range;
    }
};

void randomize_addresses(avs_net_addrinfo_t *ctx) {
    AvsRand random_func;
    random_shuffle(ctx->results, ctx->results + ctx->count, random_func);
}

bool address_matches_family(const SocketAddress &addr,
                            avs_net_af_t requested_family,
                            int flags) {
    switch (requested_family) {
    case AVS_NET_AF_INET4:
        return addr.get_ip_version() == NSAPI_IPv4;
    case AVS_NET_AF_INET6:
        switch (addr.get_ip_version()) {
        case NSAPI_IPv4:
            // IPv4 addresses are valid for IPv6 requests if V4MAPPED is on
            return (flags & AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED);
        case NSAPI_IPv6:
            return true;
        case NSAPI_UNSPEC:
        default:
            return false;
        }
    case AVS_NET_AF_UNSPEC:
    default:
        // all addresses are valid for unspecified requested family
        return true;
    }
}

nsapi_error_t
perform_dns_query(avs_net_addrinfo_t *ctx,
                  size_t ctx_results_allocated_count,
                  avs_net_af_t family,
                  const char *host,
                  uint16_t port,
                  const avs_net_resolved_endpoint_t *preferred_endpoint) {
    nsapi_size_or_error_t retval;
    switch (family) {
    case AVS_NET_AF_INET4:
        retval = dns_query_multiple(host, ctx->results,
                                    ctx_results_allocated_count, NSAPI_IPv4);
        break;
    case AVS_NET_AF_INET6:
        retval = dns_query_multiple(host, ctx->results,
                                    ctx_results_allocated_count, NSAPI_IPv6);
        break;
    case AVS_NET_AF_UNSPEC:
        retval = dns_query_multiple(host, ctx->results,
                                    ctx_results_allocated_count, NSAPI_IPv6);
        if (retval >= 0 && (size_t) retval < ctx_results_allocated_count) {
            nsapi_size_or_error_t v4result =
                    dns_query_multiple(host, &ctx->results[retval],
                                       ctx_results_allocated_count - retval,
                                       NSAPI_IPv4);
            if (v4result < 0) {
                retval = v4result;
            } else {
                retval += v4result;
            }
        }
        break;
    default:
        LOG(ERROR, "Invalid IP address family");
        return NSAPI_ERROR_PARAMETER;
    }
    if (retval < 0) {
        LOG(ERROR, "nsapi_dns_query_multiple() error %d", retval);
        return retval;
    }
    ctx->count = retval;
    for (uint8_t i = 0; i < ctx->count; ++i) {
        ctx->results[i].set_port(port);
    }

    randomize_addresses(ctx);
    if (preferred_endpoint
            && preferred_endpoint->size == sizeof(SocketAddress)) {
        SocketAddress preferred_addr;
        memcpy(&preferred_addr, &preferred_endpoint->data,
               sizeof(SocketAddress));
        if (preferred_addr.get_port() == port) {
            prioritize_preferred(ctx, preferred_addr);
        }
    }
    return NSAPI_ERROR_OK;
}

} // namespace

void avs_net_addrinfo_delete(avs_net_addrinfo_t **ctx) {
    if (*ctx) {
        // we need to use operator delete because we want to use auto_ptr
        // in AvsSocket::resolve_addrinfo() which doesn't allow deleter override
        delete *ctx;
        *ctx = NULL;
    }
}

avs_net_addrinfo_t *avs_net_addrinfo_resolve_ex(
        avs_net_socket_type_t socket_type,
        avs_net_af_t family,
        const char *host,
        const char *port_str,
        int flags,
        const avs_net_resolved_endpoint_t *preferred_endpoint) {
    uint16_t port;
    if (port_from_string(&port, port_str)) {
        LOG(ERROR, "Invalid port number");
        return NULL;
    }
    if (!host || !*host) {
        switch (family) {
        case AVS_NET_AF_INET4:
            host = "0.0.0.0";
            break;
        case AVS_NET_AF_INET6:
            host = "::";
            break;
        default:
            host = "";
        }
    }
    uint8_t number_of_entries_to_allocate = 1;
    SocketAddress literal_addr;
    if (literal_addr.set_ip_address(host)) {
        // host could be parsed as an IP address, DNS resolution not needed
        literal_addr.set_port(port);
        if (!address_matches_family(literal_addr, family, flags)) {
            LOG(ERROR, "IP address of invalid family passed");
            return NULL;
        }
    } else {
        if (flags & AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE) {
            LOG(ERROR, "Invalid IP address when resolving in passive mode");
            return NULL;
        }
        // not an IP address, proceed with DNS query
        number_of_entries_to_allocate = AvsSocketGlobal::max_dns_result();
    }

    size_t alloc_bytes =
            offsetof(avs_net_addrinfo_t, results)
            + number_of_entries_to_allocate * sizeof(SocketAddress);
    auto_ptr<avs_net_addrinfo_t> ctx(
            reinterpret_cast<avs_net_addrinfo_t *>(operator new(alloc_bytes,
                                                                nothrow)));
    if (!ctx.get()) {
        LOG(ERROR, "Out of memory");
        return NULL;
    }
    memset(ctx.get(), 0, alloc_bytes);
    if (flags & AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED) {
        ctx->v4mapped = true;
        if (family == AVS_NET_AF_INET6) {
            family = AVS_NET_AF_UNSPEC;
        }
    }
    if (literal_addr.get_ip_version() != NSAPI_UNSPEC) {
        // host was a literal IP address
        ctx->count = 1;
        ctx->results[0] = literal_addr;
    } else if (perform_dns_query(ctx.get(), number_of_entries_to_allocate,
                                 family, host, port, preferred_endpoint)) {
        return NULL;
    }
    return ctx.release();
}

int avs_net_addrinfo_next(avs_net_addrinfo_t *ctx,
                          avs_net_resolved_endpoint_t *out) {
    if (ctx->current_index >= ctx->count) {
        return AVS_NET_ADDRINFO_END;
    }
    MBED_ASSERT(ctx->results[ctx->current_index].get_ip_version() == NSAPI_IPv4
                || ctx->results[ctx->current_index].get_ip_version()
                           == NSAPI_IPv6);
    if (ctx->v4mapped
            && ctx->results[ctx->current_index].get_ip_version()
                           == NSAPI_IPv4) {
        store_resolved_endpoint(out, create_v4mapped(
                                             ctx->results[ctx->current_index]));
    } else {
        store_resolved_endpoint(out, ctx->results[ctx->current_index]);
    }
    ++ctx->current_index;
    return 0;
}
