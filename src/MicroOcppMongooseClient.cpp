// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2023
// GPL-3.0 License (see LICENSE)

#include "MicroOcppMongooseClient.h"
#include "base64.hpp"
#include <MicroOcpp/Core/Configuration.h>
#include <MicroOcpp/Debug.h>

#define DEBUG_MSG_INTERVAL 5000UL
#define WS_UNRESPONSIVE_THRESHOLD_MS 15000UL

#if defined(MOCPP_MG_VERSION_614)
#define MOCPP_MG_F_IS_MOcppMongooseClient MG_F_USER_2
#endif

using namespace MicroOcpp;

void ws_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data);

MOcppMongooseClient::MOcppMongooseClient(struct mg_mgr *mgr,
            const char *backend_url_factory, 
            const char *charge_box_id_factory,
            const char *auth_key_factory,
            const char *CA_cert_factory,
            std::shared_ptr<FilesystemAdapter> filesystem) : mgr(mgr) {
    
    bool readonly;
    
    if (filesystem) {
        configuration_init(filesystem);

        //all credentials are persistent over reboots
        readonly = false;
    } else {
        //make the credentials non-persistent
        MOCPP_DBG_WARN("Credentials non-persistent. Use MicroOcpp::makeDefaultFilesystemAdapter(...) for persistency");
        readonly = true;
    }

    setting_backend_url_str = declareConfiguration<const char*>(
        MOCPP_CONFIG_EXT_PREFIX "BackendUrl", backend_url_factory, MOCPP_WSCONN_FN, readonly, true);
    setting_cb_id_str = declareConfiguration<const char*>(
        MOCPP_CONFIG_EXT_PREFIX "ChargeBoxId", charge_box_id_factory, MOCPP_WSCONN_FN, readonly, true);
    setting_auth_key_str = declareConfiguration<const char*>(
        "AuthorizationKey", auth_key_factory, MOCPP_WSCONN_FN, readonly, true);
#if !MOCPP_CA_CERT_LOCAL
    setting_ca_cert_str = declareConfiguration<const char*>(
        MOCPP_CONFIG_EXT_PREFIX "CaCert", CA_cert_factory, MOCPP_WSCONN_FN, readonly, true);
#endif

    ws_ping_interval_int = declareConfiguration<int>(
        "WebSocketPingInterval", 5, MOCPP_WSCONN_FN);
    reconnect_interval_int = declareConfiguration<int>(
        MOCPP_CONFIG_EXT_PREFIX "ReconnectInterval", 10, MOCPP_WSCONN_FN);
    stale_timeout_int = declareConfiguration<int>(
        MOCPP_CONFIG_EXT_PREFIX "StaleTimeout", 300, MOCPP_WSCONN_FN);

    configuration_load(MOCPP_WSCONN_FN);

    backend_url = setting_backend_url_str ? setting_backend_url_str->getString() : "";
    cb_id = setting_cb_id_str ? setting_cb_id_str->getString() : "";
    auth_key = setting_auth_key_str ?  setting_auth_key_str->getString() : "";
    
#if !MOCPP_CA_CERT_LOCAL
    ca_cert = setting_ca_cert_str ? setting_ca_cert_str->getString()  : "";
#else
    ca_cert = CA_cert_factory ? CA_cert_factory : "";
#endif

#if defined(MOCPP_MG_VERSION_614)
    MOCPP_DBG_DEBUG("use MG version %s (tested with 6.14)", MG_VERSION);
#else
    MOCPP_DBG_DEBUG("use MG version %s (tested with 7.8)", MG_VERSION);
#endif

    maintainWsConn();
}

MOcppMongooseClient::~MOcppMongooseClient() {
    MOCPP_DBG_DEBUG("destruct MOcppMongooseClient");
    if (websocket) {
        reconnect(); //close WS connection, won't be reopened
#if defined(MOCPP_MG_VERSION_614)
        websocket->flags &= ~MOCPP_MG_F_IS_MOcppMongooseClient;
        websocket->user_data = nullptr;
#else
        websocket->fn_data = nullptr;
#endif
    }
}

void MOcppMongooseClient::loop() {
    maintainWsConn();
}

bool MOcppMongooseClient::sendTXT(const char *msg, size_t length) {
    if (!websocket || !isConnectionOpen()) {
        return false;
    }
    size_t sent;
#if defined(MOCPP_MG_VERSION_614)
    if (websocket->send_mbuf.len > 0) {
        sent = 0;
        return false;
    } else {
        mg_send_websocket_frame(websocket, WEBSOCKET_OP_TEXT, msg, length);
        sent = length;
    }
#else
    sent = mg_ws_send(websocket, msg, length, WEBSOCKET_OP_TEXT);
#endif
    if (sent < length) {
        MOCPP_DBG_WARN("mg_ws_send did only accept %zu out of %zu bytes", sent, length);
        //flush broken package and wait for next retry
        (void)0;
    }

    return true;
}

void MOcppMongooseClient::maintainWsConn() {
    if (mocpp_tick_ms() - last_status_dbg_msg >= DEBUG_MSG_INTERVAL) {
        last_status_dbg_msg = mocpp_tick_ms();

        //WS successfully connected?
        if (!isConnectionOpen()) {
            MOCPP_DBG_DEBUG("WS unconnected");
        } else if (mocpp_tick_ms() - last_recv >= (ws_ping_interval_int && ws_ping_interval_int->getInt() > 0 ? (ws_ping_interval_int->getInt() * 1000UL) : 0UL) + WS_UNRESPONSIVE_THRESHOLD_MS) {
            //WS connected but unresponsive
            MOCPP_DBG_DEBUG("WS unresponsive");
        }
    }

    if (websocket && isConnectionOpen() &&
            stale_timeout_int && stale_timeout_int->getInt() > 0 && mocpp_tick_ms() - last_recv >= (stale_timeout_int->getInt() * 1000UL)) {
        MOCPP_DBG_INFO("connection %s -- stale, reconnect", url.c_str());
        reconnect();
        return;
    }

    if (websocket && isConnectionOpen() &&
            ws_ping_interval_int && ws_ping_interval_int->getInt() > 0 && mocpp_tick_ms() - last_hb >= (ws_ping_interval_int->getInt() * 1000UL)) {
        last_hb = mocpp_tick_ms();
#if defined(MOCPP_MG_VERSION_614)
        mg_send_websocket_frame(websocket, WEBSOCKET_OP_PING, "", 0);
#else
        mg_ws_send(websocket, "", 0, WEBSOCKET_OP_PING);
#endif
    }

    if (websocket != nullptr) { //connection pointer != nullptr means that the socket is still open
        return;
    }

    if (credentials_changed) {
        reload_credentials();
        credentials_changed = false;
    }

    if (url.empty()) {
        //cannot open OCPP connection: credentials missing
        return;
    }

    if (reconnect_interval_int && reconnect_interval_int->getInt() > 0 && mocpp_tick_ms() - last_reconnection_attempt < (reconnect_interval_int->getInt() * 1000UL)) {
        return;
    }

    MOCPP_DBG_DEBUG("(re-)connect to %s", url.c_str());

    last_reconnection_attempt = mocpp_tick_ms();

#if defined(MOCPP_MG_VERSION_614)

    struct mg_connect_opts opts;
    memset(&opts, 0, sizeof(opts));

    const char *ca_string = ca_cert.empty() ? "*" : ca_cert.c_str();

    //Check if SSL is disabled, i.e. if URL starts with "ws:"
    if (url.length() >= strlen("ws:") &&
            tolower(url.c_str()[0]) == 'w' &&
            tolower(url.c_str()[1]) == 's' &&
            url.c_str()[2] == ':') {
        //yes, disable SSL
        ca_string = nullptr;
        MOCPP_DBG_WARN("Insecure connection (WS)");
    }

    opts.ssl_ca_cert = ca_string;

    char extra_headers [128] = {'\0'};

    if (!auth_key.empty()) {
        auto ret = snprintf(extra_headers, 128, "Authorization: Basic %s\r\n", basic_auth64.c_str());
        if (ret < 0 || ret >= 128) {
            MOCPP_DBG_ERR("Basic Authentication failed: %d", ret);
            (void)0;
        }
    }

    websocket = mg_connect_ws_opt(
        mgr,
        ws_cb,
        this,
        opts,
        url.c_str(),
        "ocpp1.6",
        *extra_headers ? extra_headers : nullptr);

    if (websocket) {
        websocket->flags |= MOCPP_MG_F_IS_MOcppMongooseClient;
    }

#else

    websocket = mg_ws_connect(
        mgr, 
        url.c_str(), 
        ws_cb, 
        this, 
        "%s%s%s\r\n", "Sec-WebSocket-Protocol: ocpp1.6",
                      basic_auth64.empty() ? "" : "\r\nAuthorization: Basic ", 
                      basic_auth64.empty() ? "" : basic_auth64.c_str());     // Create client
#endif

}

void MOcppMongooseClient::reload_credentials() {
    url.clear();
    basic_auth64.clear();

    if (backend_url.empty()) {
        MOCPP_DBG_DEBUG("empty URL closes connection");
        return;
    } else {
        url = backend_url;

        if (url.back() != '/' && !cb_id.empty()) {
            url.append("/");
        }

        url.append(cb_id);
    }

    if (!auth_key.empty()) {
        std::string token = cb_id + ":" + auth_key;

        MOCPP_DBG_DEBUG("auth Token=%s", token.c_str());

        unsigned int base64_length = encode_base64_length(token.length());
        std::vector<unsigned char> base64 (base64_length + 1);

        // encode_base64() places a null terminator automatically, because the output is a string
        base64_length = encode_base64((const unsigned char*) token.c_str(), token.length(), &base64[0]);

        MOCPP_DBG_DEBUG("auth64 len=%u, auth64 Token=%s", base64_length, &base64[0]);

        basic_auth64 = (const char*) &base64[0];
    } else {
        MOCPP_DBG_DEBUG("no authentication");
        (void) 0;
    }
}

void MOcppMongooseClient::setBackendUrl(const char *backend_url_cstr) {
    if (!backend_url_cstr) {
        MOCPP_DBG_ERR("invalid argument");
        return;
    }
    backend_url = backend_url_cstr;

    if (setting_backend_url_str) {
        setting_backend_url_str->setString(backend_url_cstr);
        configuration_save();
    }

    credentials_changed = true; //reload composed credentials when reconnecting the next time

    reconnect();
}

void MOcppMongooseClient::setChargeBoxId(const char *cb_id_cstr) {
    if (!cb_id_cstr) {
        MOCPP_DBG_ERR("invalid argument");
        return;
    }
    cb_id = cb_id_cstr;

    if (setting_cb_id_str) {
        setting_cb_id_str->setString(cb_id_cstr);
        configuration_save();
    }

    credentials_changed = true; //reload composed credentials when reconnecting the next time

    reconnect();
}

void MOcppMongooseClient::setAuthKey(const char *auth_key_cstr) {
    if (!auth_key_cstr) {
        MOCPP_DBG_ERR("invalid argument");
        return;
    }
    auth_key = auth_key_cstr;

    if (setting_auth_key_str) {
        setting_auth_key_str->setString(auth_key_cstr);
        configuration_save();
    }

    credentials_changed = true; //reload composed credentials when reconnecting the next time

    reconnect();
}

void MOcppMongooseClient::setCaCert(const char *ca_cert_cstr) {
    if (!ca_cert_cstr) {
        MOCPP_DBG_ERR("invalid argument");
        return;
    }
    ca_cert = ca_cert_cstr;

#if !MOCPP_CA_CERT_LOCAL
    if (setting_ca_cert_str) {
        setting_ca_cert_str->setString(ca_cert_cstr);
        configuration_save();
    }
#endif

    credentials_changed = true; //reload composed credentials when reconnecting the next time

    reconnect();
}

void MOcppMongooseClient::reconnect() {
    if (!websocket) {
        return;
    }
#if defined(MOCPP_MG_VERSION_614)
    if (!connection_closing) {
        const char *msg = "socket closed by client";
        mg_send_websocket_frame(websocket, WEBSOCKET_OP_CLOSE, msg, strlen(msg));
    }
#else
    websocket->is_closing = 1; //Mongoose will close the socket and the following maintainWsConn() call will open it again
#endif
    setConnectionOpen(false);
}

void MOcppMongooseClient::setConnectionOpen(bool open) {
    if (open) {
        connection_established = true;
        last_connection_established = mocpp_tick_ms();
    } else {
        connection_closing = true;
    }
}

void MOcppMongooseClient::cleanConnection() {
    connection_established = false;
    connection_closing = false;
    websocket = nullptr;
}

void MOcppMongooseClient::updateRcvTimer() {
    last_recv = mocpp_tick_ms();
}

unsigned long MOcppMongooseClient::getLastRecv() {
    return last_recv;
}

unsigned long MOcppMongooseClient::getLastConnected() {
    return last_connection_established;
}

#if defined(MOCPP_MG_VERSION_614)

void ws_cb(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {

    MOcppMongooseClient *osock = nullptr;
    
    if (user_data && nc->flags & MG_F_IS_WEBSOCKET && nc->flags & MOCPP_MG_F_IS_MOcppMongooseClient) {
        osock = reinterpret_cast<MOcppMongooseClient*>(user_data);
    } else {
        return;
    }

    switch (ev) {
        case MG_EV_CONNECT: {
            int status = *((int *) ev_data);
            if (status != 0) {
                MOCPP_DBG_WARN("connection %s -- error %d", osock->getUrl(), status);
                (void)0;
            }
            break;
        }
        case MG_EV_WEBSOCKET_HANDSHAKE_DONE: {
            struct http_message *hm = (struct http_message *) ev_data;
            if (hm->resp_code == 101) {
                MOCPP_DBG_INFO("connection %s -- connected!", osock->getUrl());
                osock->setConnectionOpen(true);
            } else {
                MOCPP_DBG_WARN("connection %s -- HTTP error %d", osock->getUrl(), hm->resp_code);
                (void)0;
                /* Connection will be closed after this. */
            }
            osock->updateRcvTimer();
            break;
        }
        case MG_EV_POLL: {
            /* Nothing to do here. OCPP engine has own loop-function */
            break;
        }
        case MG_EV_WEBSOCKET_FRAME: {
            struct websocket_message *wm = (struct websocket_message *) ev_data;

            if (!osock->getReceiveTXTcallback()((const char *) wm->data, wm->size)) { //forward message to Context
                MOCPP_DBG_ERR("processing WS input failed");
                (void)0;
            }
            osock->updateRcvTimer();
            break;
        }
        case MG_EV_WEBSOCKET_CONTROL_FRAME: {
            osock->updateRcvTimer();
            break;
        }
        case MG_EV_CLOSE: {
            MOCPP_DBG_INFO("connection %s -- closed", osock->getUrl());
            osock->cleanConnection();
            break;
        }
    }
}

#else

void ws_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev != 2) {
        MOCPP_DBG_VERBOSE("Cb fn with event: %d\n", ev);
        (void)0;
    }

    MOcppMongooseClient *osock = reinterpret_cast<MOcppMongooseClient*>(fn_data);
    if (!osock) {
        if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
            MOCPP_DBG_INFO("connection %s", ev == MG_EV_CLOSE ? "closed" : "error");
            (void)0;
        } else {
            MOCPP_DBG_ERR("invalid state %d", ev);
            (void)0;
        }
        return;
    }

    if (ev == MG_EV_ERROR) {
        // On error, log error message
        MG_ERROR(("%p %s", c->fd, (char *) ev_data));
    } else if (ev == MG_EV_CONNECT) {
        // If target URL is SSL/TLS, command client connection to use TLS
        if (mg_url_is_ssl(osock->getUrl())) {
            const char *ca_string = osock->getCaCert();
            if (ca_string && *ca_string == '\0') { //check if certificate validation is disabled by passing an empty string
                //yes, disabled
                ca_string = nullptr;
            }
            struct mg_tls_opts opts = {.ca = ca_string};
            mg_tls_init(c, &opts);
        } else {
            MOCPP_DBG_WARN("Insecure connection (WS)");
        }
    } else if (ev == MG_EV_WS_OPEN) {
        // WS connection established. Perform MQTT login
        MOCPP_DBG_INFO("connection %s -- connected!", osock->getUrl());
        osock->setConnectionOpen(true);
        osock->updateRcvTimer();
    } else if (ev == MG_EV_WS_MSG) {
        struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
        if (!osock->getReceiveTXTcallback()((const char*) wm->data.ptr, wm->data.len)) {
            MOCPP_DBG_WARN("processing input message failed");
        }
        osock->updateRcvTimer();
    } else if (ev == MG_EV_WS_CTL) {
        osock->updateRcvTimer();
    }

    if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
        MOCPP_DBG_INFO("connection %s -- %s", osock->getUrl(), ev == MG_EV_CLOSE ? "closed" : "error");
        osock->cleanConnection();
    }
}
#endif
