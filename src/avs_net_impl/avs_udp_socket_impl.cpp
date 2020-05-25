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

#include <UDPSocket.h>
#include <mbed_error.h>

#include <avsystem/commons/avs_commons_config.h>
#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_list_cxx.hpp>

#include "avs_mbed_hacks.h"
#include "avs_socket_impl.h"

using namespace avs_mbed_hacks;
using namespace avs_mbed_impl;
using namespace mbed;
using namespace std;

namespace avs_mbed_impl {

// mbed OS' UDP sockets only have sendto() and recvfrom() APIs. We want to be
// able to use connect() and use multiple logical sockets for connections to
// different endpoints, so we need this router to multiplex mbed sockets.
class AvsUdpRouter {
    friend class avs_mbed_impl::AvsUdpRouterHandle;
    static avs::List<AvsUdpRouterHandle> ROUTERS;

    UDPSocket backend_;
    size_t recv_buffer_size_;
    uint8_t *recv_buffer_;
    avs::List<AvsUdpSocket *> sockets_;

    AvsUdpRouter(SocketAddress &inout_addr)
            : backend_(),
              recv_buffer_size_(AvsSocketGlobal::recv_buffer_size()),
              recv_buffer_(new (nothrow) uint8_t[recv_buffer_size_]) {}

    AvsUdpRouter(const AvsUdpRouter &);
    AvsUdpRouter &operator=(const AvsUdpRouter &);

    bool socket_registered(AvsUdpSocket *socket) const {
        return find(sockets_.begin(), sockets_.end(), socket) != sockets_.end();
    }

    AvsUdpSocket *find_socket_by_peer(const SocketAddress &peer) {
        avs::ListIterator<AvsUdpSocket *> it;
        for (it = sockets_.begin(); it != sockets_.end(); ++it) {
            if (addresses_equal((*it)->remote_address_, peer)) {
                return *it;
            }
        }
        return NULL;
    }

    AvsUdpSocket *find_unconnected_socket() {
        return find_socket_by_peer(SocketAddress());
    }

public:
    ~AvsUdpRouter() {
        delete[] recv_buffer_;
    }

    static void get(AvsUdpRouterHandle &out, const SocketAddress &local_addr);
    static void get(AvsUdpRouterHandle &out, const AvsUdpSocket *socket);
    static avs_error_t get_or_create(AvsUdpRouterHandle &out,
                                     SocketAddress local_addr);

    InternetSocket *get_socket() {
        return &backend_;
    }

    avs_error_t register_socket(AvsUdpSocket *socket, bool allow_reuse) {
        MBED_ASSERT(addresses_equal(socket->remote_address_, SocketAddress()));
        if (!allow_reuse && find_unconnected_socket()) {
            return avs_errno(AVS_EISCONN);
        }

        MBED_ASSERT(!socket_registered(socket));
        if (sockets_.insert(sockets_.end(), socket) == sockets_.end()) {
            return avs_errno(AVS_ENOMEM);
        }
        return AVS_OK;
    }

    avs_error_t check_connection_possibility(const SocketAddress &peer) {
        if (!peer || !peer.get_port()) {
            return avs_errno(AVS_EFAULT);
        }
        if (find_socket_by_peer(peer)) {
            return avs_errno(AVS_EADDRINUSE);
        }
        return AVS_OK;
    }

    void unregister_socket(AvsUdpSocket *socket) {
        avs::ListIterator<AvsUdpSocket *> it;
        for (it = sockets_.begin(); it != sockets_.end(); ++it) {
            if (*it == socket) {
                sockets_.erase(it);
                break;
            }
        }
    }

    avs_error_t
    send_to(const void *buffer, size_t length, const SocketAddress &dest) {
        backend_.set_timeout(NET_SEND_TIMEOUT_MS);
        nsapi_size_or_error_t result = backend_.sendto(dest, buffer, length);
        if (result < 0) {
            return avs_errno(nsapi_error_to_errno(result));
        } else if ((size_t) result < length) {
            LOG(ERROR, "sending fail (%lu/%lu)", (unsigned long) result,
                (unsigned long) length);
            return avs_errno(AVS_EIO);
        }
        return AVS_OK;
    }

    avs_error_t try_recv(const avs_time_monotonic_t &deadline) {
        while (true) {
            int64_t timeout_ms;
            if (avs_time_duration_to_scalar(
                        &timeout_ms, AVS_TIME_MS,
                        avs_time_monotonic_diff(deadline,
                                                avs_time_monotonic_now()))) {
                timeout_ms = -1;
            } else if (timeout_ms < 0) {
                timeout_ms = 0;
            }
            SocketAddress peer;
            backend_.set_blocking(!avs_time_monotonic_valid(deadline));
            reset_poll_flag();
            nsapi_size_or_error_t result =
                    backend_.recvfrom(&peer, recv_buffer_, recv_buffer_size_);
            while (result == NSAPI_ERROR_WOULD_BLOCK
                   && avs_time_monotonic_before(avs_time_monotonic_now(),
                                                deadline)) {
                wait_on_poll_flag(deadline);
                result = backend_.recvfrom(&peer, recv_buffer_,
                                           recv_buffer_size_);
                reset_poll_flag();
            }
            if (result < 0) {
                return avs_errno(nsapi_error_to_errno(result));
            }
            AvsUdpSocket *socket = find_socket_by_peer(peer);
            if (!socket) {
                socket = find_unconnected_socket();
            }
            if (!socket) {
                if (avs_time_monotonic_before(avs_time_monotonic_now(),
                                              deadline)) {
                    continue;
                } else {
                    return avs_errno(AVS_ETIMEDOUT);
                }
            }
            avs::ListIterator<AvsUdpReceivedMessage> it =
                    socket->recvd_msgs_.allocate(
                            socket->recvd_msgs_.end(),
                            offsetof(AvsUdpReceivedMessage, data) + result);
            if (it == socket->recvd_msgs_.end()) {
                return avs_errno(AVS_ENOMEM);
            }
            new (&it->peer) SocketAddress(peer);
            it->data_size = result;
            memcpy(it->data, recv_buffer_, it->data_size);
            return avs_errno(AVS_NO_ERROR);
        }
    }
};

class AvsUdpRouterHandle {
    friend class avs_mbed_impl::AvsUdpRouter;
    SocketAddress local_address_;
    AvsUdpRouter *router_;

    void update(const SocketAddress &local_address, AvsUdpRouter *router) {
        if (router == router_) {
            MBED_ASSERT(addresses_equal(local_address, local_address_));
        } else {
            clear();
            local_address_ = local_address;
            router_ = router;
        }
    }

    AvsUdpRouterHandle(const AvsUdpRouterHandle &);
    AvsUdpRouterHandle &operator=(const AvsUdpRouterHandle &);

public:
    AvsUdpRouterHandle() : local_address_(), router_(NULL) {}

    ~AvsUdpRouterHandle() {
        clear();
    }

    void clear() {
        if (router_ && router_->sockets_.empty()) {
            // If we're getting rid of a handle to a router that has no sockets
            // registered, we get rid of it.
            //
            // We can do that, because AvsUdpRouterHandles are basically used in
            // two contexts:
            //
            // - AvsUdpRouter::ROUTERS - well, we're removing it from there, so
            //   we won't break anything
            // - methods of AvsUdpSocket - if a socket is able to retrieve a
            //   router handle, it means it's associated with the router, so it
            //   will be present on the sockets lists, i.e. it won't be empty,
            //   unless something goes wrong during e.g. bind() or connect(),
            //   or when doing close(), and these are places where we may want
            //   to delete the router
            //
            // Dangling handles won't happen unless multiple sockets bound to
            // the same port will be used in multiple concurrently running
            // threads.
            //
            // But the code in this file IS CURRENTLY NOT THREAD SAFE anyway.

            avs::ListIterator<AvsUdpRouterHandle> it;
            for (it = AvsUdpRouter::ROUTERS.begin();
                 it != AvsUdpRouter::ROUTERS.end();
                 ++it) {
                if (it->router_ == router_) {
                    it->router_ = NULL;
                    AvsUdpRouter::ROUTERS.erase(it);
                    break;
                }
            }
            delete router_;
        }
        local_address_ = SocketAddress();
        router_ = NULL;
    }

    SocketAddress local_address() const {
        return local_address_;
    }

    operator bool() const {
        return router_;
    }

    AvsUdpRouter &operator*() const {
        return *router_;
    }

    AvsUdpRouter *operator->() const {
        return router_;
    }
};

avs::List<AvsUdpRouterHandle> AvsUdpRouter::ROUTERS;

void AvsUdpRouter::get(AvsUdpRouterHandle &out,
                       const SocketAddress &local_addr) {
    MBED_ASSERT(local_addr.get_ip_version() != NSAPI_UNSPEC
                && local_addr.get_port() != 0);
    avs::ListIterator<AvsUdpRouterHandle> it;
    for (it = ROUTERS.begin(); it != ROUTERS.end(); ++it) {
        if (addresses_equal(it->local_address(), local_addr)) {
            out.update(local_addr, &**it);
            return;
        }
    }
    out.clear();
}

void AvsUdpRouter::get(AvsUdpRouterHandle &out, const AvsUdpSocket *socket) {
    avs::ListIterator<AvsUdpRouterHandle> it;
    for (it = ROUTERS.begin(); it != ROUTERS.end(); ++it) {
        avs::ListIterator<AvsUdpSocket *> sit;
        for (sit = it->router_->sockets_.begin();
             sit != it->router_->sockets_.end();
             ++sit) {
            if (*sit == socket) {
                out.update(it->local_address(), &**it);
                return;
            }
        }
    }
    out.clear();
}

avs_error_t AvsUdpRouter::get_or_create(AvsUdpRouterHandle &out,
                                        SocketAddress local_addr) {
    MBED_ASSERT(local_addr.get_ip_version() != NSAPI_UNSPEC);
    if (local_addr.get_port() != 0) {
        get(out, local_addr);
        if (out) {
            return AVS_OK;
        }
    }

    auto_ptr<AvsUdpRouter> router(new (nothrow) AvsUdpRouter(local_addr));
    if (!router.get() || !router->recv_buffer_) {
        return AVS_OK;
    }
    nsapi_error_t err =
            router->backend_.open(&AvsSocketGlobal::get_interface());
    if (err) {
        return avs_errno(nsapi_error_to_errno(err));
    }
    router->backend_.sigio(callback(trigger_poll_flag));

    // mbed OS automatically assigns a random port on socket creation
    // Note: SocketAddress::operator bool tests if IP address is all-zeros, but
    // does not check if port is 0
    if (local_addr.get_port() != 0 || local_addr) {
        err = router->backend_.bind(local_addr);
        if (err) {
            return avs_errno(nsapi_error_to_errno(err));
        }
    } else {
        int32_t port = get_local_port(&router->backend_);
        if (port > 0) {
            local_addr.set_port(port);
        }
    }
    avs::ListIterator<AvsUdpRouterHandle> it = ROUTERS.allocate(
            local_addr.get_port() > 0 ? ROUTERS.end() : ROUTERS.begin());
    if (it == ROUTERS.end()) {
        return avs_errno(AVS_ENOMEM);
    }
    (new (&*it) AvsUdpRouterHandle())->update(local_addr, router.release());
    out.update(local_addr, &**it);
    return AVS_OK;
}

void AvsUdpSocket::get_router(AvsUdpRouterHandle &out) const {
    if (local_address_.get_ip_version() == NSAPI_UNSPEC) {
        out.clear();
    } else if (local_address_.get_port() != 0) {
        AvsUdpRouter::get(out, local_address_);
    } else {
        AvsUdpRouter::get(out, this);
    }
}

avs_error_t AvsUdpSocket::ensure_router(AvsUdpRouterHandle &out) {
    get_router(out);
    if (!out) {
        avs_error_t err = AvsSocket::bind(NULL, NULL);
        if (avs_is_err(err)) {
            return err;
        }
        get_router(out);
        MBED_ASSERT(out);
    }
    return AVS_OK;
}

avs_error_t AvsUdpSocket::get_udp_overhead(int *out) {
    switch (socket_family()) {
    case AVS_NET_AF_INET4:
        *out = 28; /* 20 for IP + 8 for UDP */
        return AVS_OK;
    case AVS_NET_AF_INET6:
        *out = 48; /* 40 for IPv6 + 8 for UDP */
        return AVS_OK;
    default:
        return avs_errno(AVS_EINVAL);
    }
}

int AvsUdpSocket::get_fallback_inner_mtu() const {
    static const uint8_t V4MAPPED_ADDR_HEADER[] = { 0, 0, 0, 0, 0,    0,
                                                    0, 0, 0, 0, 0xFF, 0xFF };
    if (remote_address_.get_ip_version() == NSAPI_IPv6
            && memcmp(remote_address_.get_ip_bytes(), V4MAPPED_ADDR_HEADER,
                      sizeof(V4MAPPED_ADDR_HEADER))
                           != 0) { // IPv6
        return 1232;               // 1280 - 48
    } else {                       // probably IPv4
        return 548;                // 576 - 28
    }
}

InternetSocket *AvsUdpSocket::mbed_socket() const {
    AvsUdpRouterHandle router;
    get_router(router);
    return router ? router->get_socket() : NULL;
}

avs_error_t AvsUdpSocket::try_connect(const SocketAddress &address) {
    AvsUdpRouterHandle router;
    avs_error_t err = ensure_router(router);
    if (!router) {
        MBED_ASSERT(avs_is_err(err));
        return err;
    }
    if (avs_is_err((err = router->check_connection_possibility(address)))) {
        return err;
    }
    // the call site (AvsSocket::connect()) will update this->remote_address_,
    // which is what the routing is based on
    return AVS_OK;
}

bool AvsUdpSocket::ready_to_receive() const {
    if (!recvd_msgs_.empty()) {
        return true;
    }
    AvsUdpRouterHandle router;
    get_router(router);
    if (!router) {
        return false;
    }
    avs_time_monotonic_t deadline = avs_time_monotonic_now();
    while (avs_is_ok(router->try_recv(deadline))) {
        if (!recvd_msgs_.empty()) {
            return true;
        }
    }
    return false;
}

avs_error_t AvsUdpSocket::send(const void *buffer, size_t length) {
    AvsUdpRouterHandle router;
    get_router(router);
    if (!router || remote_address_.get_ip_version() == NSAPI_UNSPEC) {
        LOG(ERROR, "Attempted send() on an unconnected socket");
        return avs_errno(AVS_ENOTCONN);
    }
    return router->send_to(buffer, length, remote_address_);
}

avs_error_t AvsUdpSocket::send_to(const void *buffer,
                                  size_t length,
                                  const char *host,
                                  const char *port) {
    AvsUdpRouterHandle router;
    avs_error_t err = ensure_router(router);
    if (!router) {
        MBED_ASSERT(avs_is_err(err));
        return err;
    }
    SocketAddress address;
    auto_ptr<avs_net_addrinfo_t> info =
            resolve_addrinfo(host, port, false, PREFERRED_FAMILY_ONLY);
    if (!info.get()) {
        info = resolve_addrinfo(host, port, false, PREFERRED_FAMILY_BLOCKED);
    }
    if (!info.get() || next_socket_address(info.get(), &address)) {
        return avs_errno(AVS_EADDRNOTAVAIL);
    }
    return router->send_to(buffer, length, address);
}

avs_error_t AvsUdpSocket::receive_from(size_t *out_size,
                                       void *buffer,
                                       size_t buffer_length,
                                       char *host,
                                       size_t host_size,
                                       char *port_str,
                                       size_t port_str_size) {
    AvsUdpRouterHandle router;
    get_router(router);
    if (!router) {
        return avs_errno(AVS_ENOTCONN);
    }
    avs_time_monotonic_t deadline =
            avs_time_monotonic_add(avs_time_monotonic_now(), recv_timeout_);
    avs_error_t err = AVS_OK;
    while (recvd_msgs_.empty()) {
        if (avs_is_err((err = router->try_recv(deadline)))) {
            return err;
        }
    }
    avs::ListIterator<AvsUdpReceivedMessage> it = recvd_msgs_.begin();
    *out_size = it->data_size;
    if (buffer_length < *out_size) {
        *out_size = buffer_length;
        err = avs_errno(AVS_EMSGSIZE);
    }
    memcpy(buffer, it->data, *out_size);
    if (host_size
            && avs_simple_snprintf(host, host_size, "%s",
                                   it->peer.get_ip_address())
                           < 0
            && avs_is_ok(err)) {
        err = avs_errno(AVS_ERANGE);
    }
    if (port_str_size
            && avs_simple_snprintf(port_str, port_str_size, "%" PRIu16,
                                   it->peer.get_port())
                           < 0
            && avs_is_ok(err)) {
        err = avs_errno(AVS_ERANGE);
    }
    recvd_msgs_.erase(it);
    return err;
}

avs_error_t AvsUdpSocket::try_bind(const SocketAddress &localaddr) {
    AvsUdpRouterHandle router;
    get_router(router);
    if (router) {
        LOG(ERROR, "socket is already bound");
        return avs_errno(AVS_EISCONN);
    }

    MBED_ASSERT(localaddr.get_ip_version() != NSAPI_UNSPEC);
    avs_error_t err = AvsUdpRouter::get_or_create(router, localaddr);
    if (avs_is_ok(err)) {
        remote_address_ = SocketAddress();
        err = router->register_socket(this, configuration_.reuse_addr);
    }
    if (avs_is_ok(err)) {
        state_ = AVS_NET_SOCKET_STATE_BOUND;
        local_address_ = router.local_address();
    }
    return err;
}

avs_error_t AvsUdpSocket::accept(AvsSocket *new_socket) {
    return avs_errno(AVS_ENOTSUP);
}

void AvsUdpSocket::close() {
    AvsUdpRouterHandle router;
    get_router(router);
    if (router) {
        router->unregister_socket(this);
    }
    state_ = AVS_NET_SOCKET_STATE_CLOSED;
    local_address_ = SocketAddress();
    // avs_commons' contract requires that the remote port is not reset when
    // closing the socket; some software (e.g. Anjay) relies on that;
    // so we reset only the address but not the port
    remote_address_.set_addr(local_address_.get_addr());
}

avs_error_t
AvsUdpSocket::get_opt(avs_net_socket_opt_key_t option_key,
                      avs_net_socket_opt_value_t *out_option_value) {
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_INNER_MTU: {
        avs_error_t err =
                AvsSocket::get_opt(AVS_NET_SOCKET_OPT_MTU, out_option_value);
        if (avs_is_err(err)) {
            out_option_value->mtu = get_fallback_inner_mtu();
        } else {
            int udp_overhead;
            if (avs_is_err((err = get_udp_overhead(&udp_overhead)))) {
                return err;
            }
            out_option_value->mtu -= udp_overhead;
            if (out_option_value->mtu < 0) {
                out_option_value->mtu = 0;
            }
        }
        return AVS_OK;
    }
    default:
        return AvsSocket::get_opt(option_key, out_option_value);
    }
}

} // namespace avs_mbed_impl
