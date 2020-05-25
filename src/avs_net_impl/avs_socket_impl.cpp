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

#include <string.h>

#include <Semaphore.h>
#include <mbed.h>
#include <mbed_assert.h>
#include <mbed_error.h>

#include <avsystem/commons/avs_commons_config.h>
#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_list_cxx.hpp>
#include <avsystem/commons/avs_socket_v_table.h>

#include "avs_mbed_hacks.h"
#include "avs_socket_impl.h"

using namespace avs_mbed_hacks;
using namespace avs_mbed_impl;
using namespace mbed;
using namespace rtos;
using namespace std;

struct avs_net_socket_struct {
    const avs_net_socket_v_table_t *const operations;
    avs_max_align_t impl_placeholder;
};

namespace {

AVS_STATIC_ASSERT(sizeof(SocketAddress)
                          <= AVS_NET_SOCKET_RAW_RESOLVED_ENDPOINT_MAX_SIZE,
                  endpoint_size_supported);

#if PREREQ_MBED_OS(5, 6, 0)
EventFlags AVS_SOCKET_POLL_FLAG;
#else // mbed OS < 5.6 does not have EventFlags
Semaphore AVS_SOCKET_POLL_SEM;
#endif

AvsSocket *get_impl(avs_net_socket_t *socket) {
    return reinterpret_cast<AvsSocket *>(
            &reinterpret_cast<avs_net_socket_t *>(socket)->impl_placeholder);
}

avs_error_t
connect_net(avs_net_socket_t *net_socket, const char *host, const char *port) {
    return get_impl(net_socket)->connect(host, port);
}

avs_error_t send_net(avs_net_socket_t *net_socket,
                     const void *buffer,
                     size_t buffer_length) {
    return get_impl(net_socket)->send(buffer, buffer_length);
}

avs_error_t send_to_net(avs_net_socket_t *net_socket,
                        const void *buffer,
                        size_t buffer_length,
                        const char *host,
                        const char *port) {
    return get_impl(net_socket)->send_to(buffer, buffer_length, host, port);
}

avs_error_t receive_net(avs_net_socket_t *net_socket,
                        size_t *out_size,
                        void *buffer,
                        size_t buffer_length) {
    return get_impl(net_socket)->receive(out_size, buffer, buffer_length);
}

avs_error_t receive_from_net(avs_net_socket_t *net_socket,
                             size_t *out_size,
                             void *message_buffer,
                             size_t buffer_size,
                             char *host,
                             size_t host_size,
                             char *port,
                             size_t port_size) {
    return get_impl(net_socket)
            ->receive_from(out_size, message_buffer, buffer_size, host,
                           host_size, port, port_size);
}

avs_error_t bind_net(avs_net_socket_t *net_socket,
                     const char *localaddr,
                     const char *port) {
    return get_impl(net_socket)->bind(localaddr, port);
}

avs_error_t accept_net(avs_net_socket_t *server_net_socket,
                       avs_net_socket_t *new_net_socket);

avs_error_t close_net(avs_net_socket_t *net_socket) {
    get_impl(net_socket)->close();
    return AVS_OK;
}

avs_error_t shutdown_net(avs_net_socket_t *net_socket) {
    return get_impl(net_socket)->shutdown();
}

avs_error_t cleanup_net(avs_net_socket_t **net_socket) {
    get_impl(*net_socket)->~AvsSocket();
    free(*net_socket);
    *net_socket = NULL;
    return AVS_OK;
}

const void *system_socket_net(avs_net_socket_t *net_socket) {
    return get_impl(net_socket);
}

avs_error_t remote_host_net(avs_net_socket_t *net_socket,
                            char *out_buffer,
                            size_t out_buffer_size) {
    return get_impl(net_socket)->remote_host(out_buffer, out_buffer_size);
}

avs_error_t remote_hostname_net(avs_net_socket_t *net_socket,
                                char *out_buffer,
                                size_t out_buffer_size) {
    return get_impl(net_socket)->remote_hostname(out_buffer, out_buffer_size);
}

avs_error_t remote_port_net(avs_net_socket_t *net_socket,
                            char *out_buffer,
                            size_t out_buffer_size) {
    return get_impl(net_socket)->remote_port(out_buffer, out_buffer_size);
}

avs_error_t local_host_net(avs_net_socket_t *net_socket,
                           char *out_buffer,
                           size_t out_buffer_size) {
    return get_impl(net_socket)->local_host(out_buffer, out_buffer_size);
}

avs_error_t local_port_net(avs_net_socket_t *net_socket,
                           char *out_buffer,
                           size_t out_buffer_size) {
    return get_impl(net_socket)->local_port(out_buffer, out_buffer_size);
}

avs_error_t get_opt_net(avs_net_socket_t *net_socket,
                        avs_net_socket_opt_key_t option_key,
                        avs_net_socket_opt_value_t *out_option_value) {
    return get_impl(net_socket)->get_opt(option_key, out_option_value);
}

avs_error_t set_opt_net(avs_net_socket_t *net_socket,
                        avs_net_socket_opt_key_t option_key,
                        avs_net_socket_opt_value_t option_value) {
    return get_impl(net_socket)->set_opt(option_key, option_value);
}

const avs_net_socket_v_table_t NET_VTABLE = { connect_net,
                                              NULL,
                                              send_net,
                                              send_to_net,
                                              receive_net,
                                              receive_from_net,
                                              bind_net,
                                              accept_net,
                                              close_net,
                                              shutdown_net,
                                              cleanup_net,
                                              system_socket_net,
                                              NULL,
                                              remote_host_net,
                                              remote_hostname_net,
                                              remote_port_net,
                                              local_host_net,
                                              local_port_net,
                                              get_opt_net,
                                              set_opt_net };

avs_error_t accept_net(avs_net_socket_t *server_net_socket,
                       avs_net_socket_t *new_net_socket) {
    AvsSocket *new_avs_socket = NULL;
    if (new_net_socket
            && reinterpret_cast<avs_net_socket_t *>(new_net_socket)->operations
                           == &NET_VTABLE) {
        new_avs_socket = get_impl(new_net_socket);
    }
    return get_impl(server_net_socket)->accept(new_avs_socket);
}

avs_error_t create_net_socket(avs_net_socket_t **socket,
                              avs_net_socket_type_t socket_type,
                              const void *socket_configuration) {
    const avs_net_socket_v_table_t *const VTABLE_PTR = &NET_VTABLE;
    const avs_net_socket_configuration_t *configuration =
            reinterpret_cast<const avs_net_socket_configuration_t *>(
                    socket_configuration);
    size_t size = offsetof(avs_net_socket_t, impl_placeholder);
    switch (socket_type) {
    case AVS_NET_TCP_SOCKET:
        size += sizeof(AvsTcpSocket);
        break;
    case AVS_NET_UDP_SOCKET:
        size += sizeof(AvsUdpSocket);
        break;
    default:
        error("Invalid socket type\r\n");
    }
    avs_net_socket_t *net_socket =
            reinterpret_cast<avs_net_socket_t *>(calloc(1, size));
    if (!net_socket) {
        return avs_errno(AVS_ENOMEM);
    }
    *socket = reinterpret_cast<avs_net_socket_t *>(net_socket);

    const_cast<const avs_net_socket_v_table_t *&>(net_socket->operations) =
            VTABLE_PTR;
    avs_error_t err = AVS_OK;
    switch (socket_type) {
    case AVS_NET_TCP_SOCKET: {
        AvsTcpSocket *ptr =
                reinterpret_cast<AvsTcpSocket *>(&net_socket->impl_placeholder);
        MBED_ASSERT(static_cast<AvsSocket *>(ptr) == get_impl(*socket));
        err = (new (ptr) AvsTcpSocket())->initialize(configuration);
        break;
    }
    case AVS_NET_UDP_SOCKET: {
        AvsUdpSocket *ptr =
                reinterpret_cast<AvsUdpSocket *>(&net_socket->impl_placeholder);
        MBED_ASSERT(static_cast<AvsSocket *>(ptr) == get_impl(*socket));
        err = (new (ptr) AvsUdpSocket())->initialize(configuration);
        break;
    }
    default:
        error("Invalid socket type\r\n");
    }

    if (avs_is_err(err)) {
        cleanup_net(socket);
    }
    return err;
}

int get_other_family(avs_net_af_t *out, avs_net_af_t in) {
    switch (in) {
    case AVS_NET_AF_INET4:
        *out = AVS_NET_AF_INET6;
        return 0;
    case AVS_NET_AF_INET6:
        *out = AVS_NET_AF_INET4;
        return 0;
    default:
        return -1;
    }
}

struct PollSocketEntry {
    Socket *mbed_socket;
    avs::List<avs_net_socket_t *> avs_sockets;
};

static int poll_nonblocking(avs::List<avs_net_socket_t *> &out,
                            avs::List<PollSocketEntry> &entries) {
    for (avs::ListIterator<PollSocketEntry> it = entries.begin();
         it != entries.end();
         ++it) {
        avs::ListIterator<avs_net_socket_t *> avs_it = it->avs_sockets.begin();
        while (avs_it != it->avs_sockets.end()) {
            if (reinterpret_cast<const AvsSocket *>(
                        avs_net_socket_get_system(*avs_it))
                        ->ready_to_receive()) {
                if (out.push_back(*avs_it) == out.end()) {
                    // out of memory
                    return -1;
                }
                avs_it = it->avs_sockets.erase(avs_it);
            } else {
                ++avs_it;
            }
        }
    }
    return 0;
}

} // namespace

NetworkInterface *AvsSocketGlobal::INTERFACE = NULL;
uint8_t AvsSocketGlobal::MAX_DNS_RESULTS = 0;
size_t AvsSocketGlobal::RECV_BUFFER_SIZE = 0;
avs_net_af_t AvsSocketGlobal::PREFERRED_FAMILY = AVS_NET_AF_UNSPEC;

AvsSocketGlobal::AvsSocketGlobal(NetworkInterface *interface,
                                 uint8_t max_dns_results,
                                 size_t recv_buffer_size,
                                 avs_net_af_t preferred_family) {
    MBED_ASSERT(!INTERFACE);
    MBED_ASSERT(preferred_family != AVS_NET_AF_UNSPEC);
    INTERFACE = interface;
    MAX_DNS_RESULTS = max_dns_results;
    RECV_BUFFER_SIZE = recv_buffer_size;
    PREFERRED_FAMILY = preferred_family;
}

AvsSocketGlobal::~AvsSocketGlobal() {
    INTERFACE = NULL;
}

NetworkInterface &AvsSocketGlobal::get_interface() {
    MBED_ASSERT(INTERFACE);
    return *INTERFACE;
}

uint8_t AvsSocketGlobal::max_dns_result() {
    MBED_ASSERT(INTERFACE);
    return MAX_DNS_RESULTS;
}

size_t AvsSocketGlobal::recv_buffer_size() {
    MBED_ASSERT(INTERFACE);
    return RECV_BUFFER_SIZE;
}

avs_net_af_t AvsSocketGlobal::preferred_family() {
    MBED_ASSERT(INTERFACE);
    return PREFERRED_FAMILY;
}

int AvsSocketGlobal::poll(
        avs::List<avs_net_socket_t *> &out,
        const avs::ListView<avs_net_socket_t *const> &avs_sockets,
        uint32_t timeout_ms) {
    out.clear();
    avs::List<PollSocketEntry> entries;
    avs::ListIterator<PollSocketEntry> it;

    for (avs::ListIterator<avs_net_socket_t *const> avs_it =
                 avs_sockets.begin();
         avs_it != avs_sockets.end();
         ++avs_it) {
        Socket *mbed_socket = reinterpret_cast<const AvsSocket *>(
                                      avs_net_socket_get_system(*avs_it))
                                      ->mbed_socket();
        it = entries.begin();
        while (it != entries.end()
               && (uintptr_t) it->mbed_socket < (uintptr_t) mbed_socket) {
            ++it;
        }
        if (it == entries.end() || it->mbed_socket != mbed_socket) {
            it = entries.allocate(it);
            if (it == entries.end()) {
                // out of memory
                return -1;
            }
            (new (&*it) PollSocketEntry())->mbed_socket = mbed_socket;
        }
        if (it->avs_sockets.push_back(*avs_it) == it->avs_sockets.end()) {
            // out of memory
            return -1;
        }
    }

    reset_poll_flag();

    // any of the sockets might actually have data already buffered
    if (poll_nonblocking(out, entries)) {
        return -1;
    } else if (!out.empty()) {
        return 0;
    }

    // if not, then wait for some event
    wait_on_poll_flag(timeout_ms);
    return poll_nonblocking(out, entries);
}

namespace avs_mbed_impl {

avs_errno_t nsapi_error_to_errno(nsapi_size_or_error_t error) {
    switch (error) {
    case NSAPI_ERROR_OK:
        return AVS_NO_ERROR;
    case NSAPI_ERROR_WOULD_BLOCK:
#if PREREQ_MBED_OS(5, 5, 0)
    case NSAPI_ERROR_CONNECTION_TIMEOUT:
#endif
        return AVS_ETIMEDOUT;
    case NSAPI_ERROR_UNSUPPORTED:
        return AVS_ENOSYS;
    case NSAPI_ERROR_PARAMETER:
        return AVS_EINVAL;
    case NSAPI_ERROR_NO_CONNECTION:
        return AVS_ECONNRESET;
    case NSAPI_ERROR_NO_SOCKET:
        return AVS_EBADF;
    case NSAPI_ERROR_NO_ADDRESS:
        return AVS_ENXIO;
    case NSAPI_ERROR_NO_MEMORY:
        return AVS_ENOMEM;
    case NSAPI_ERROR_NO_SSID:
    case NSAPI_ERROR_DNS_FAILURE:
    case NSAPI_ERROR_DHCP_FAILURE:
        return AVS_EPROTO;
    case NSAPI_ERROR_AUTH_FAILURE:
        return AVS_EACCES;
    case NSAPI_ERROR_DEVICE_ERROR:
        return AVS_ENODEV;
    case NSAPI_ERROR_IN_PROGRESS:
        return AVS_EINPROGRESS;
    case NSAPI_ERROR_ALREADY:
        return AVS_EALREADY;
    case NSAPI_ERROR_IS_CONNECTED:
        return AVS_EISCONN;
#if PREREQ_MBED_OS(5, 5, 0)
    case NSAPI_ERROR_CONNECTION_LOST:
        return AVS_ECONNRESET;
#endif
#if PREREQ_MBED_OS(5, 7, 0)
    case NSAPI_ERROR_ADDRESS_IN_USE:
        return AVS_EADDRINUSE;
#endif
    default:
        return AVS_EIO;
    }
}

int port_from_string(uint16_t *out, const char *port) {
    if (!port || !*port) {
        *out = 0;
        return 0;
    }
    char *endptr = NULL;
    long result = strtol(port, &endptr, 10);
    if (result < 0 || result > UINT16_MAX || !endptr || *endptr) {
        LOG(ERROR, "Invalid port: %s", port);
        return -1;
    }
    *out = (uint16_t) result;
    return 0;
}

int next_socket_address(avs_net_addrinfo_t *addrinfo, SocketAddress *out) {
    avs_net_resolved_endpoint_t endpoint;
    int result = avs_net_addrinfo_next(addrinfo, &endpoint);
    if (result) {
        return result;
    }
    MBED_ASSERT(endpoint.size == sizeof(SocketAddress));
    memcpy(out, &endpoint.data, sizeof(SocketAddress));
    return 0;
}

void store_resolved_endpoint(avs_net_resolved_endpoint_t *out,
                             const SocketAddress &address) {
    AVS_STATIC_ASSERT(sizeof(out->data) >= sizeof(SocketAddress),
                      resolved_enpoint_size);
    out->size = sizeof(SocketAddress);
    memcpy(&out->data, &address, sizeof(SocketAddress));
}

bool addresses_equal(const SocketAddress &left, const SocketAddress &right) {
    // operator ==() on SocketAddress objects is insane.
    // IT DOES NOT COMPARE PORTS, FOR HECK'S SAKE. BLOODY HELL.
    return left == right && left.get_port() == right.get_port();
}

void reset_poll_flag() {
#if PREREQ_MBED_OS(5, 6, 0)
    AVS_SOCKET_POLL_FLAG.clear();
#else
    // reset the semaphore taking all the tokens
    while (AVS_SOCKET_POLL_SEM.wait(0) > 0)
        ;
#endif
}

void trigger_poll_flag() {
#if PREREQ_MBED_OS(5, 6, 0)
    AVS_SOCKET_POLL_FLAG.set(1);
#else
    AVS_SOCKET_POLL_SEM.release();
#endif
}

void wait_on_poll_flag(uint32_t timeout_ms) {
#if PREREQ_MBED_OS(5, 6, 0)
    AVS_SOCKET_POLL_FLAG.wait_any(1, timeout_ms);
#else
    AVS_SOCKET_POLL_SEM.wait(timeout_ms);
#endif
}

void wait_on_poll_flag(const avs_time_monotonic_t &deadline) {
    avs_time_duration_t timeout =
            avs_time_monotonic_diff(deadline, avs_time_monotonic_now());
    int64_t timeout_ms;
    if (!avs_time_duration_to_scalar(&timeout_ms, AVS_TIME_MS, timeout)
            && timeout_ms > 0) {
        wait_on_poll_flag((uint32_t) min(timeout_ms, (int64_t) UINT32_MAX));
    }
}

int AvsSocket::get_family_for_name_resolution(
        avs_net_af_t *out,
        preferred_family_mode_t preferred_family_mode) const {
    switch (configuration_.address_family) {
    case AVS_NET_AF_UNSPEC: {
        // If we only have "soft" family preference,
        // use it as the preferred one, and later try the "opposite" setting
        avs_net_af_t preferred_family = configuration_.preferred_family;
        if (preferred_family == AVS_NET_AF_UNSPEC) {
            preferred_family = AvsSocketGlobal::preferred_family();
        }
        switch (preferred_family_mode) {
        case PREFERRED_FAMILY_ONLY:
            *out = preferred_family;
            return 0;
        case PREFERRED_FAMILY_BLOCKED:
            return get_other_family(out, preferred_family);
        }
        break;
    }
    default:
        // If we have "hard" address_family setting,
        // it is the preferred one, and there is nothing else
        switch (preferred_family_mode) {
        case PREFERRED_FAMILY_ONLY:
            *out = configuration_.address_family;
            return 0;
        case PREFERRED_FAMILY_BLOCKED:
            return -1;
        }
    }
    ::error("Invalid value of preferred_family_mode");
    return -1;
}

avs_net_af_t AvsSocket::socket_family() const {
    MBED_STATIC_ASSERT(NSAPI_UNSPEC == 0 && NSAPI_UNSPEC < NSAPI_IPv4
                               && NSAPI_IPv4 < NSAPI_IPv6,
                       "nsapi_version_t has insane values");
    switch (max(remote_address_.get_ip_version(),
                local_address_.get_ip_version())) {
    case NSAPI_IPv4:
        return AVS_NET_AF_INET4;
    case NSAPI_IPv6:
        return AVS_NET_AF_INET6;
    default:
        return AVS_NET_AF_UNSPEC;
    }
}

auto_ptr<avs_net_addrinfo_t>
AvsSocket::resolve_addrinfo(const char *host,
                            const char *port,
                            bool use_preferred_endpoint,
                            preferred_family_mode_t preferred_family_mode,
                            int resolve_flags) const {
    auto_ptr<avs_net_addrinfo_t> result;

    avs_net_af_t family = AVS_NET_AF_UNSPEC;
    if (get_family_for_name_resolution(&family, preferred_family_mode)) {
        return result;
    }

    MBED_ASSERT(family != AVS_NET_AF_UNSPEC);
    avs_net_af_t socket_family = this->socket_family();
    if (socket_family == AVS_NET_AF_INET6) {
        if (family != AVS_NET_AF_INET6) {
            // If we have an already created socket that is bound to IPv6,
            // but the requested family is something else, use v4-mapping
            resolve_flags |= AVS_NET_ADDRINFO_RESOLVE_F_V4MAPPED;
        }
    } else if (socket_family != AVS_NET_AF_UNSPEC && socket_family != family) {
        // If we have an already created socket, we cannot use
        // IPv6-to-IPv4 mapping, and the requested family is different
        // than the socket's bound one - we're screwed, just give up
        return result;
    }

    // avs_net_socket_type_t is ignored in avs_net_addrinfo_resolve_ex() anyway
    // also, it's safe to use auto_ptr because avs_net_addrinfo_delete() just
    // calls operator delete
    result.reset(avs_net_addrinfo_resolve_ex(
            avs_net_socket_type_t(), family, host, port, resolve_flags,
            use_preferred_endpoint ? configuration_.preferred_endpoint : NULL));
    return result;
}

void AvsSocket::update_remote_endpoint(const char *hostname,
                                       SocketAddress address) {
    if (!hostname || !*hostname) {
        remote_hostname_[0] = '\0';
    } else if (avs_simple_snprintf(remote_hostname_, sizeof(remote_hostname_),
                                   "%s", hostname)
               < 0) {
        LOG(WARNING, "Hostname %s is too long, not storing", hostname);
        remote_hostname_[0] = '\0';
    }
    remote_address_ = address;
}

avs_error_t
AvsSocket::initialize(const avs_net_socket_configuration_t *configuration) {
    if (*configuration->interface_name) {
        LOG(ERROR, "Configuring interface name is not supported");
        return avs_errno(AVS_EINVAL);
    }
    if (configuration->dscp >= 64) {
        LOG(ERROR, "bad DSCP value <%x>", (unsigned) configuration->dscp);
        return avs_errno(AVS_EINVAL);
    }
    if (configuration->priority > 7) {
        LOG(ERROR, "bad priority value <%d>",
            (unsigned) configuration->priority);
        return avs_errno(AVS_EINVAL);
    }
    configuration_ = *configuration;
    return AVS_OK;
}

avs_error_t AvsSocket::try_bind(avs_net_addrinfo_t *info) {
    SocketAddress address;
    avs_error_t err = avs_errno(AVS_EINVAL);
    if (info) {
        while (!next_socket_address(info, &address)) {
            if (avs_is_ok((err = try_bind(address)))) {
                return AVS_OK;
            }
        }
    }
    return err;
}

avs_error_t AvsSocket::bind(const char *localaddr, const char *port_str) {
    auto_ptr<avs_net_addrinfo_t> info =
            resolve_addrinfo(localaddr, port_str, false, PREFERRED_FAMILY_ONLY,
                             AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE);
    avs_error_t err = try_bind(info.get());
    if (avs_is_err(err)) {
        info = resolve_addrinfo(localaddr, port_str, false,
                                PREFERRED_FAMILY_BLOCKED,
                                AVS_NET_ADDRINFO_RESOLVE_F_PASSIVE);
        err = try_bind(info.get());
    }
    return err;
}

avs_error_t AvsSocket::connect(const char *host, const char *port) {
    if (state_ != AVS_NET_SOCKET_STATE_CLOSED
            && state_ != AVS_NET_SOCKET_STATE_BOUND) {
        LOG(ERROR, "socket is already connected");
        return avs_errno(AVS_EISCONN);
    }

    LOG(TRACE, "connecting to [%s]:%s", host, port);

    avs_error_t err = avs_errno(AVS_EADDRNOTAVAIL);
    auto_ptr<avs_net_addrinfo_t> info =
            resolve_addrinfo(host, port, true, PREFERRED_FAMILY_ONLY);
    SocketAddress address;
    if (info.get()) {
        while (!next_socket_address(info.get(), &address)) {
            if (avs_is_ok((err = try_connect(address)))) {
                goto success;
            }
        }
    }
    info = resolve_addrinfo(host, port, true, PREFERRED_FAMILY_BLOCKED);
    if (info.get()) {
        while (!next_socket_address(info.get(), &address)) {
            if (avs_is_ok((err = try_connect(address)))) {
                goto success;
            }
        }
    }
    LOG(ERROR, "cannot establish connection to [%s]:%s", host, port);
    assert(avs_is_err(err));
    return err;
success:
    state_ = AVS_NET_SOCKET_STATE_CONNECTED;
    if (configuration_.preferred_endpoint) {
        store_resolved_endpoint(configuration_.preferred_endpoint, address);
    }
    update_remote_endpoint(host, address);
    if (local_address_.get_ip_version() == NSAPI_UNSPEC) {
        local_address_.set_ip_address(
                AvsSocketGlobal::get_interface().get_ip_address());
    }
    if (local_address_.get_port() == 0) {
        int32_t local_port = get_local_port(mbed_socket());
        if (local_port > 0) {
            local_address_.set_port(local_port);
        }
    }
    return AVS_OK;
}

avs_error_t AvsSocket::get_opt(avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t *out_option_value) {
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
        out_option_value->recv_timeout = recv_timeout_;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_STATE:
        out_option_value->state = state_;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_ADDR_FAMILY:
        out_option_value->addr_family = socket_family();
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_MTU:
        if (configuration_.forced_mtu > 0) {
            out_option_value->mtu = configuration_.forced_mtu;
            return AVS_OK;
        } else {
            return avs_errno(AVS_EINVAL);
        }
    default:
        LOG(ERROR, "get_opt_net: unknown or unsupported option key");
        return avs_errno(AVS_EINVAL);
    }
}

avs_error_t AvsSocket::set_opt(avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t option_value) {
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT: {
        recv_timeout_ = option_value.recv_timeout;
        return AVS_OK;
    }
    default:
        LOG(ERROR, "set_opt_net: unknown or unsupported option key");
        return avs_errno(AVS_EINVAL);
    }
}

} // namespace avs_mbed_impl

extern "C" {

avs_error_t _avs_net_create_tcp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration) {
    return create_net_socket(socket, AVS_NET_TCP_SOCKET, socket_configuration);
}

avs_error_t _avs_net_create_udp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration) {
    return create_net_socket(socket, AVS_NET_UDP_SOCKET, socket_configuration);
}

avs_error_t avs_net_local_address_for_target_host(const char *target_host,
                                                  avs_net_af_t addr_family,
                                                  char *address_buffer,
                                                  size_t buffer_size) {
    (void) target_host; // we don't support more than one interface
    const char *ip_address = AvsSocketGlobal::get_interface().get_ip_address();
    if (!ip_address) {
        return avs_errno(AVS_EADDRNOTAVAIL);
    }
    if (addr_family != AVS_NET_AF_UNSPEC) {
        avs_net_af_t ip_family =
                (strchr(ip_address, ':') ? AVS_NET_AF_INET6 : AVS_NET_AF_INET4);
        if (addr_family != ip_family) {
            return avs_errno(AVS_EADDRNOTAVAIL);
        }
    }
    if (avs_simple_snprintf(address_buffer, buffer_size, "%s", ip_address)
            < 0) {
        return avs_errno(AVS_ERANGE);
    }
    return AVS_OK;
}

int avs_net_validate_ip_address(avs_net_af_t family, const char *ip_address) {
    SocketAddress addr;
    if (!addr.set_ip_address(ip_address)) {
        return -1;
    }
    return ((family == AVS_NET_AF_INET4 && addr.get_ip_version() != NSAPI_IPv4)
            || (family == AVS_NET_AF_INET6
                && addr.get_ip_version() != NSAPI_IPv6))
                   ? -1
                   : 0;
}

avs_error_t
avs_net_resolved_endpoint_get_host_port(const avs_net_resolved_endpoint_t *endp,
                                        char *host,
                                        size_t hostlen,
                                        char *serv,
                                        size_t servlen) {
    if (endp->size != sizeof(SocketAddress)) {
        return avs_errno(AVS_EINVAL);
    }
    const SocketAddress &addr =
            *reinterpret_cast<const SocketAddress *>(&endp->data);
    if (!addr.get_ip_address()) {
        return avs_errno(AVS_EINVAL);
    }
    if (avs_simple_snprintf(host, hostlen, "%s", addr.get_ip_address()) < 0
            || avs_simple_snprintf(serv, servlen, "%" PRIu16, addr.get_port())
                           < 0) {
        return avs_errno(AVS_ERANGE);
    }
    return AVS_OK;
}

int _avs_net_initialize_global_compat_state(void) {
    return 0;
}

void _avs_net_cleanup_global_compat_state(void) {}
}
