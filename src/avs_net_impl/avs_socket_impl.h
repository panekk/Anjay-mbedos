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

#ifndef AVS_SOCKET_IMPL_H
#define AVS_SOCKET_IMPL_H

#include <memory>

#include <inttypes.h>

#include <Socket.h>

#include <avsystem/commons/avs_commons_config.h>
#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_list_cxx.hpp>
#include <avsystem/commons/avs_log.h>
#include <avsystem/commons/avs_utils.h>

#include "avs_mbed_hacks.h"
#include "avs_socket_global.h"

#define NET_CONNECT_TIMEOUT_MS 10000
#define NET_ACCEPT_TIMEOUT_MS 5000
#define NET_SEND_TIMEOUT_MS 30000

#define NET_LISTEN_BACKLOG 1024

#define LOG(...) avs_log(mbed_sock, __VA_ARGS__)

namespace avs_mbed_impl {

avs_errno_t nsapi_error_to_errno(nsapi_size_or_error_t error);

int port_from_string(uint16_t *out, const char *port);

int next_socket_address(avs_net_addrinfo_t *addrinfo, SocketAddress *out);

void store_resolved_endpoint(avs_net_resolved_endpoint_t *out,
                             const SocketAddress &address);

bool addresses_equal(const SocketAddress &left, const SocketAddress &right);

void reset_poll_flag();

void trigger_poll_flag();

void wait_on_poll_flag(uint32_t timeout_ms);

void wait_on_poll_flag(const avs_time_monotonic_t &deadline);

// This is only an argument type for resolve_addrinfo() and
// get_family_for_name_resolution()
typedef enum {
    // return only addresses of the preferred family
    PREFERRED_FAMILY_ONLY,
    // return only addresses NOT of the preferred family
    PREFERRED_FAMILY_BLOCKED
} preferred_family_mode_t;

class AvsSocket {
    AvsSocket(const AvsSocket &);
    AvsSocket &operator=(const AvsSocket &);
    avs_error_t try_bind(avs_net_addrinfo_t *info);

protected:
    avs_net_socket_state_t state_;
    char remote_hostname_[256];
    SocketAddress remote_address_;
    SocketAddress local_address_;
    avs_net_socket_configuration_t configuration_;
    avs_time_duration_t recv_timeout_;

    int get_family_for_name_resolution(
            avs_net_af_t *out,
            preferred_family_mode_t preferred_family_mode) const;
    ::std::auto_ptr<avs_net_addrinfo_t>
    resolve_addrinfo(const char *host,
                     const char *port,
                     bool use_preferred_endpoint,
                     preferred_family_mode_t preferred_family_mode,
                     int resolve_flags = 0) const;
    void update_remote_endpoint(const char *hostname, SocketAddress address);
    avs_net_af_t socket_family() const;
    virtual avs_error_t try_connect(const SocketAddress &address) = 0;
    virtual avs_error_t try_bind(const SocketAddress &localaddr) = 0;

public:
    AvsSocket()
            : state_(AVS_NET_SOCKET_STATE_CLOSED),
              remote_hostname_(),
              remote_address_(),
              configuration_(),
              recv_timeout_(AVS_NET_SOCKET_DEFAULT_RECV_TIMEOUT) {}

    virtual ~AvsSocket() {}

    avs_error_t initialize(const avs_net_socket_configuration_t *configuration);

    avs_error_t receive(size_t *out_size, void *buffer, size_t buffer_length) {
        return receive_from(out_size, buffer, buffer_length, NULL, 0, NULL, 0);
    }

    avs_error_t bind(const char *localaddr, const char *port_str);

    avs_error_t remote_host(char *out_buffer, size_t out_buffer_size) {
        if (remote_address_.get_ip_version() == NSAPI_UNSPEC) {
            return avs_errno(AVS_EBADF);
        }
        MBED_ASSERT(out_buffer || !out_buffer_size);
        if (avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                                remote_address_.get_ip_address())
                < 0) {
            return avs_errno(AVS_ERANGE);
        }
        return AVS_OK;
    }

    avs_error_t remote_hostname(char *out_buffer, size_t out_buffer_size) {
        MBED_ASSERT(out_buffer || !out_buffer_size);
        if (avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                                remote_hostname_)
                < 0) {
            return avs_errno(AVS_ERANGE);
        }
        return AVS_OK;
    }

    avs_error_t remote_port(char *out_buffer, size_t out_buffer_size) {
        // we deliberately don't check for remote_address_ validity here;
        // see close() implementations for more information
        MBED_ASSERT(out_buffer || !out_buffer_size);
        if (avs_simple_snprintf(out_buffer, out_buffer_size, "%" PRIu16,
                                remote_address_.get_port())
                < 0) {
            return avs_errno(AVS_ERANGE);
        }
        return AVS_OK;
    }

    avs_error_t local_host(char *out_buffer, size_t out_buffer_size) {
        if (local_address_.get_ip_version() == NSAPI_UNSPEC) {
            return avs_errno(AVS_EBADF);
        }
        MBED_ASSERT(out_buffer || !out_buffer_size);
        if (avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                                local_address_.get_ip_address())
                < 0) {
            return avs_errno(AVS_ERANGE);
        }
        return AVS_OK;
    }

    avs_error_t local_port(char *out_buffer, size_t out_buffer_size) {
        if (local_address_.get_ip_version() == NSAPI_UNSPEC) {
            return avs_errno(AVS_EBADF);
        }
        MBED_ASSERT(out_buffer || !out_buffer_size);
        if (avs_simple_snprintf(out_buffer, out_buffer_size, "%" PRIu16,
                                local_address_.get_port())
                < 0) {
            return avs_errno(AVS_ERANGE);
        }
        return AVS_OK;
    }

    virtual bool ready_to_receive() const = 0;
    virtual InternetSocket *mbed_socket() const = 0;
    virtual avs_error_t connect(const char *host, const char *port);
    virtual avs_error_t send(const void *buffer, size_t length) = 0;
    virtual avs_error_t send_to(const void *buffer,
                                size_t length,
                                const char *host,
                                const char *port_str) = 0;
    virtual avs_error_t receive_from(size_t *out_size,
                                     void *buffer,
                                     size_t buffer_length,
                                     char *host,
                                     size_t host_size,
                                     char *port_str,
                                     size_t port_str_size) = 0;
    virtual avs_error_t accept(AvsSocket *new_socket) = 0;
    virtual void close() = 0;

    virtual avs_error_t shutdown() {
        // there is no shutdown, so close...
        close();
        state_ = AVS_NET_SOCKET_STATE_SHUTDOWN;
        return AVS_OK;
    }

    virtual avs_error_t get_opt(avs_net_socket_opt_key_t option_key,
                                avs_net_socket_opt_value_t *out_option_value);
    virtual avs_error_t set_opt(avs_net_socket_opt_key_t option_key,
                                avs_net_socket_opt_value_t option_value);
};

class AvsTcpSocket : public AvsSocket {
    std::auto_ptr<InternetSocket> socket_; // TCPSocket or TCPServer

    avs_error_t configure_socket();

protected:
    virtual avs_error_t try_connect(const SocketAddress &address);
    virtual avs_error_t try_bind(const SocketAddress &localaddr);

public:
    virtual bool ready_to_receive() const;

    virtual InternetSocket *mbed_socket() const {
        return socket_.get();
    }

    virtual avs_error_t connect(const char *host, const char *port);
    virtual avs_error_t send(const void *buffer, size_t length);

    virtual avs_error_t send_to(const void *buffer,
                                size_t length,
                                const char *host,
                                const char *port_str) {
        // mimicking the POSIX behaviour:
        // "If the socket is connection-mode, dest_addr shall be ignored."
        (void) host;
        (void) port_str;
        return send(buffer, length);
    }

    virtual avs_error_t receive_from(size_t *out_size,
                                     void *buffer,
                                     size_t buffer_length,
                                     char *host,
                                     size_t host_size,
                                     char *port_str,
                                     size_t port_str_size);
    virtual avs_error_t accept(AvsSocket *new_socket);
    virtual void close();
};

class AvsUdpRouter;
class AvsUdpRouterHandle;

struct AvsUdpReceivedMessage {
    SocketAddress peer;
    size_t data_size;
    uint8_t data[1]; // actually a FAM
};

class AvsUdpSocket : public AvsSocket {
    friend class AvsUdpRouter;
    avs::List<AvsUdpReceivedMessage> recvd_msgs_;

    void get_router(AvsUdpRouterHandle &out) const;
    avs_error_t ensure_router(AvsUdpRouterHandle &out);
    avs_error_t get_udp_overhead(int *out);
    int get_fallback_inner_mtu() const;

protected:
    virtual avs_error_t try_connect(const SocketAddress &address);
    virtual avs_error_t try_bind(const SocketAddress &localaddr);

public:
    virtual ~AvsUdpSocket() {
        close();
    }

    virtual bool ready_to_receive() const;
    virtual InternetSocket *mbed_socket() const;
    virtual avs_error_t send(const void *buffer, size_t length);
    virtual avs_error_t send_to(const void *buffer,
                                size_t length,
                                const char *host,
                                const char *port_str);
    virtual avs_error_t receive_from(size_t *out_size,
                                     void *buffer,
                                     size_t buffer_length,
                                     char *host,
                                     size_t host_size,
                                     char *port_str,
                                     size_t port_str_size);
    virtual avs_error_t accept(AvsSocket *new_socket);
    virtual void close();
    virtual avs_error_t get_opt(avs_net_socket_opt_key_t option_key,
                                avs_net_socket_opt_value_t *out_option_value);
};

} // namespace avs_mbed_impl

#endif /* AVS_SOCKET_IMPL_H */
