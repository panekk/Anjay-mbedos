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

#include <mbed.h>
#include <mbed_mem_trace.h>

#ifdef TARGET_GR_LYCHEE
#    include <ESP32Interface.h>
#endif // TARGET_GR_LYCHEE
#include <NetworkInterface.h>

#include <memory>

#include <inttypes.h>

#include <avsystem/commons/avs_list_cxx.hpp>
#include <avsystem/commons/avs_log.h>

#include <anjay/anjay.h>
#include <anjay/attr_storage.h>
#include <anjay/security.h>
#include <anjay/server.h>

#include "avs_socket_global.h"

#define ENDPOINT_NAME "urn:dev:os:anjay-mbedos-test"

#define LWM2M_NOSEC_ADDR "coap://192.168.1.150:5683"
#define LWM2M_DTLS_ADDR "coaps://192.168.1.150:5684"
#define LWM2M_BS_NOSEC_ADDR "coap://192.168.1.150:5693"
#define LWM2M_BS_DTLS_ADDR "coaps://192.168.1.150:5684"

#define WITH_LWM2M_SERVER 1
#define WITH_BOOTSTRAP_SERVER 0
#define WITH_DTLS 1

#define PSK_IDENTITY "1234"
#define PSK_KEY "1234"

#define WIFI_SSID "test"
#define WIFI_PASSWORD "password123"

#if WITH_DTLS
#    define LWM2M_URI LWM2M_DTLS_ADDR
#    define LWM2M_BS_URI LWM2M_BS_DTLS_ADDR
#else
#    define LWM2M_URI LWM2M_NOSEC_ADDR
#    define LWM2M_BS_URI LWM2M_BS_NOSEC_ADDR
#endif

#if !WITH_LWM2M_SERVER && !WITH_BOOTSTRAP_SERVER
#    error "No LwM2M Server and no LwM2M Bootstrap Server enabled"
#endif

namespace {

void serve(anjay_t *anjay,
           AVS_LIST(avs_net_socket_t *const) sockets,
           uint32_t timeout_ms) {
    avs::List<avs_net_socket_t *> ready;
    AvsSocketGlobal::poll(
            ready, avs::ListView<avs_net_socket_t *const>(sockets), timeout_ms);

    avs::ListIterator<avs_net_socket_t *> it;
    for (it = ready.begin(); it != ready.end(); ++it) {
        if (anjay_serve(anjay, *it)) {
            avs_log(lwm2m, ERROR, "anjay_serve failed");
        }
    }
}

void serve_forever(anjay_t *anjay) {
    while (true) {
        AVS_LIST(avs_net_socket_t *const) sockets = anjay_get_sockets(anjay);
        int timeout_ms = anjay_sched_calculate_wait_time_ms(anjay, 100);
        serve(anjay, sockets, timeout_ms);
        anjay_sched_run(anjay);

        if (anjay_all_connections_failed(anjay)) {
            anjay_schedule_reconnect(anjay);
        }
    }
}

int setup_security_object(anjay_t *anjay) {
    int result = anjay_security_object_install(anjay);
    if (result) {
        avs_log(lwm2m, ERROR, "cannot initialize security object");
        return result;
    }

    anjay_iid_t iid;
    anjay_security_instance_t sec_instance;
    memset(&sec_instance, 0, sizeof(sec_instance));
    sec_instance.ssid = 1;
    sec_instance.client_holdoff_s = 0;
    sec_instance.bootstrap_timeout_s = 0;
    sec_instance.public_cert_or_psk_identity = (const uint8_t *) PSK_IDENTITY;
    sec_instance.public_cert_or_psk_identity_size = sizeof(PSK_IDENTITY) - 1;
    sec_instance.private_cert_or_psk_key = (const uint8_t *) PSK_KEY;
    sec_instance.private_cert_or_psk_key_size = sizeof(PSK_KEY) - 1;
#if WITH_DTLS
    sec_instance.security_mode = ANJAY_SECURITY_PSK;
#else
    sec_instance.security_mode = ANJAY_SECURITY_NOSEC;
#endif

#if WITH_BOOTSTRAP_SERVER
    iid = ANJAY_IID_INVALID;
    sec_instance.bootstrap_server = true;
    sec_instance.server_uri = LWM2M_BS_URI;

    result = anjay_security_object_add_instance(anjay, &sec_instance, &iid);
    if (result) {
        avs_log(lwm2m, ERROR, "cannot setup Bootstrap Server instance");
        return result;
    }
#endif

#if WITH_LWM2M_SERVER
    iid = ANJAY_ID_INVALID;
    sec_instance.bootstrap_server = false;
    sec_instance.server_uri = LWM2M_URI;

    result = anjay_security_object_add_instance(anjay, &sec_instance, &iid);
    if (result) {
        avs_log(lwm2m, ERROR, "cannot setup LwM2M Server instance");
        return result;
    }
#endif

    return 0;
}

int setup_server_object(anjay_t *anjay) {
    anjay_iid_t server_iid = 1;
    anjay_server_instance_t serv_instance;
    memset(&serv_instance, 0, sizeof(serv_instance));
    serv_instance.ssid = 1;
    serv_instance.lifetime = 60;
    serv_instance.default_min_period = -1;
    serv_instance.default_max_period = -1;
    serv_instance.disable_timeout = -1;
    serv_instance.notification_storing = false;
    serv_instance.binding = "U";

    int result = anjay_server_object_install(anjay);
    if (result
#if !WITH_BOOTSTRAP_SERVER
            || anjay_server_object_add_instance(anjay, &serv_instance,
                                                &server_iid)
#endif
    ) {
        avs_log(lwm2m, ERROR, "cannot initialize server object");
        return -1;
    }

    return 0;
}

void log_handler(avs_log_level_t level,
                 const char *module,
                 const char *message) {
    (void) level;
    (void) module;
    printf("%s\r\n", message);
}

void lwm2m_serve(void) {
    avs_log_set_handler(log_handler);
    if (MBED_CONF_PLATFORM_STDIO_BAUD_RATE >= 38400) {
        avs_log_set_default_level(AVS_LOG_TRACE);
        avs_log_set_level(anjay_sched, AVS_LOG_DEBUG);
    }
    avs_log(lwm2m, INFO, "lwm2m_task starting up");

    static const char endpoint_name[] = ENDPOINT_NAME;
    // clang-format off
    anjay_configuration_t CONFIG;
    memset(&CONFIG, 0, sizeof(CONFIG));
    CONFIG.endpoint_name = endpoint_name;
    CONFIG.in_buffer_size = 1024;
    CONFIG.out_buffer_size = 1024;
    CONFIG.udp_listen_port = 5683;
    // clang-format on

    anjay_t *anjay = anjay_new(&CONFIG);

    if (!anjay) {
        avs_log(lwm2m, ERROR, "could not create anjay object");
        goto finish;
    }

    if (anjay_attr_storage_install(anjay)) {
        avs_log(lwm2m, ERROR, "cannot initialize attribute storage module");
        goto finish;
    }

    if (setup_security_object(anjay) || setup_server_object(anjay)) {
        avs_log(lwm2m, ERROR, "cannot register data model objects");
        goto finish;
    }

    serve_forever(anjay);

finish:
    avs_log(lwm2m, ERROR, "lwm2m_task finished unexpectedly");

    if (anjay) {
        anjay_delete(anjay);
        anjay = NULL;
    }
}

static const int STATS_SAMPLE_TIME_MS = 15000;

static float cpu_usage_percent(uint64_t idle_diff, uint64_t sample_time) {
    float usage_percent =
            100.0f
            - (static_cast<float>(idle_diff) / static_cast<float>(sample_time))
                      * 100.0f;
    return std::max(0.0f, std::min(100.0f, usage_percent));
}

void print_stats(void) {
#if !MBED_MEM_TRACING_ENABLED || !MBED_STACK_STATS_ENABLED
#    warning "Thread stack statistics require MBED_STACK_STATS_ENABLED and " \
             "MBED_MEM_TRACING_ENABLED to be defined in mbed_app.json"
    printf("Thread stacks stats disabled\r\n");
#else
    int num_threads = osThreadGetCount();
    assert(num_threads >= 0);
    std::unique_ptr<mbed_stats_stack_t[]> stack_stats{ new (
            std::nothrow) mbed_stats_stack_t[num_threads] };
    if (!stack_stats) {
        printf("out of memory\r\n");
        return;
    }
    num_threads = mbed_stats_stack_get_each(stack_stats.get(), num_threads);

    printf("Thread stacks:\r\n");
    for (int i = 0; i < num_threads; ++i) {
        const auto &stats = stack_stats[i];
        printf("- thread %#08" PRIx32 ": %5lu / %5lu B used\r\n",
               stats.thread_id, stats.max_size, stats.reserved_size);
    }
#endif

#if !MBED_MEM_TRACING_ENABLED || !MBED_HEAP_STATS_ENABLED
#    warning "Thread stack statistics require MBED_HEAP_STATS_ENABLED and " \
             "MBED_MEM_TRACING_ENABLED to be defined in mbed_app.json"
    printf("Heap usage stats disabled\r\n");
#else
    mbed_stats_heap_t heap_stats;
    mbed_stats_heap_get(&heap_stats);
    printf("Heap: %lu/%lu B used\r\n", heap_stats.current_size,
           heap_stats.reserved_size);
#endif

#if !MBED_CPU_STATS_ENABLED
#    warning "CPU usage statistics require MBED_CPU_STATS_ENABLED to be " \
             "defined in mbed_app.json"
    printf("CPU usage stats disabled\r\n");
#else
    static mbed_stats_cpu_t prev_cpu_stats;
    mbed_stats_cpu_t cpu_stats;
    mbed_stats_cpu_get(&cpu_stats);

    static uint64_t samples_gathered = 0;
    ++samples_gathered;

    printf("CPU usage: %.4f%% current, %.4f%% average\r\n",
           cpu_usage_percent(cpu_stats.idle_time - prev_cpu_stats.idle_time,
                             STATS_SAMPLE_TIME_MS * 1000),
           cpu_usage_percent(cpu_stats.idle_time,
                             STATS_SAMPLE_TIME_MS * 1000 * samples_gathered));

    prev_cpu_stats = cpu_stats;
#endif
}

Thread thread(osPriorityNormal, 16384);

} // namespace

int main() {
#if MBED_MEM_TRACING_ENABLED                                     \
        || (MBED_STACK_STATS_ENABLED && MBED_HEAP_STATS_ENABLED) \
        || (MBED_HEAP_STATS_ENABLED && MBED_HEAP_STATS_ENABLED)
    mbed_event_queue()->call_every(STATS_SAMPLE_TIME_MS, print_stats);
#else
    printf("All stats disabled\r\n");
#endif

#if TARGET_DISCO_L496AG
    printf("Selecting plastic SIM slot\r\n");
    DigitalOut sim_select0(PC_2);
    DigitalOut sim_select1(PI_3);

    sim_select0 = false;
    sim_select1 = false;
    printf("Plastic SIM slot selected\r\n");
    ThisThread::sleep_for(100);
#endif

    // See https://github.com/ARMmbed/mbed-os/issues/7069. In general this is
    // required to initialize hardware RNG used by default.
    mbedtls_platform_setup(NULL);

#ifdef TARGET_GR_LYCHEE
    printf("Hello, world. Initializing network (WPA2, SSID: %s, PSK: "
           "%s)...\r\n",
           WIFI_SSID, WIFI_PASSWORD);
    ESP32Interface network(P5_3, P3_14, P7_1, P0_1);
    network.set_credentials(WIFI_SSID, WIFI_PASSWORD, NSAPI_SECURITY_WPA_WPA2);
#else
    NetworkInterface &network = *NetworkInterface::get_default_instance();
#endif

    for (int retry = 0;
         network.get_connection_status() != NSAPI_STATUS_GLOBAL_UP;
         ++retry) {
        printf("connect, retry = %d\r\n", retry);
        nsapi_error_t err = network.connect();
        printf("connect result = %d\r\n", err);
    }

    const char *ip = network.get_ip_address();
    const char *mac = network.get_mac_address();
    printf("IP: %s\r\n", ip ? ip : "NONE");
    printf("MAC: %s\r\n", mac ? mac : "NONE");

    {
        AvsSocketGlobal avs(&network, 32, 1536, AVS_NET_AF_INET4);

        thread.start(callback(lwm2m_serve));
        for (;;) {
            ThisThread::sleep_for(1);
        }
    }
}
