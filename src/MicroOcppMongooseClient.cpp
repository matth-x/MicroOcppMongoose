// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2024
// GPL-3.0 License (see LICENSE)

#include "MicroOcppMongooseClient.h"
#include "base64.hpp"
#include <MicroOcpp/Core/Configuration.h>
#include <MicroOcpp/Debug.h>

#define DEBUG_MSG_INTERVAL 5000UL
#define WS_UNRESPONSIVE_THRESHOLD_MS 15000UL

#if defined(MO_MG_VERSION_614)
#define MO_MG_F_IS_MOcppMongooseClient MG_F_USER_2
#endif

using namespace MicroOcpp;

void ws_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data);

MOcppMongooseClient::MOcppMongooseClient(struct mg_mgr *mgr,
            const char *backend_url_factory, 
            const char *charge_box_id_factory,
            const char *auth_key_factory,
            const char *ca_certificate,
            std::shared_ptr<FilesystemAdapter> filesystem,
            ProtocolVersion protocolVersion) : mgr(mgr), protocolVersion(protocolVersion) {
    
    bool readonly;
    
    if (filesystem) {
        configuration_init(filesystem);

        //all credentials are persistent over reboots
        readonly = false;
    } else {
        //make the credentials non-persistent
        MO_DBG_WARN("Credentials non-persistent. Use MicroOcpp::makeDefaultFilesystemAdapter(...) for persistency");
        readonly = true;
    }

    setting_backend_url_str = declareConfiguration<const char*>(
        MO_CONFIG_EXT_PREFIX "BackendUrl", backend_url_factory, MO_WSCONN_FN, readonly, true);
    setting_cb_id_str = declareConfiguration<const char*>(
        MO_CONFIG_EXT_PREFIX "ChargeBoxId", charge_box_id_factory, MO_WSCONN_FN, readonly, true);
    setting_auth_key_str = declareConfiguration<const char*>(
        "AuthorizationKey", auth_key_factory, MO_WSCONN_FN, readonly, true);
    ws_ping_interval_int = declareConfiguration<int>(
        "WebSocketPingInterval", 5, MO_WSCONN_FN);
    reconnect_interval_int = declareConfiguration<int>(
        MO_CONFIG_EXT_PREFIX "ReconnectInterval", 10, MO_WSCONN_FN);
    stale_timeout_int = declareConfiguration<int>(
        MO_CONFIG_EXT_PREFIX "StaleTimeout", 300, MO_WSCONN_FN);

    configuration_load(MO_WSCONN_FN); //load configs with values stored on flash

    ca_cert = ca_certificate;

    reloadConfigs(); //load WS creds with configs values

#if defined(MO_MG_VERSION_614)
    MO_DBG_DEBUG("use MG version %s (tested with 6.14)", MG_VERSION);
#else
    MO_DBG_DEBUG("use MG version %s (tested with 7.8)", MG_VERSION);
#endif

    maintainWsConn();
}

MOcppMongooseClient::~MOcppMongooseClient() {
    MO_DBG_DEBUG("destruct MOcppMongooseClient");
    if (websocket) {
        reconnect(); //close WS connection, won't be reopened
#if defined(MO_MG_VERSION_614)
        websocket->flags &= ~MO_MG_F_IS_MOcppMongooseClient;
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
#if defined(MO_MG_VERSION_614)
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
        MO_DBG_WARN("mg_ws_send did only accept %zu out of %zu bytes", sent, length);
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
            MO_DBG_DEBUG("WS unconnected");
        } else if (mocpp_tick_ms() - last_recv >= (ws_ping_interval_int && ws_ping_interval_int->getInt() > 0 ? (ws_ping_interval_int->getInt() * 1000UL) : 0UL) + WS_UNRESPONSIVE_THRESHOLD_MS) {
            //WS connected but unresponsive
            MO_DBG_DEBUG("WS unresponsive");
        }
    }

    if (websocket && isConnectionOpen() &&
            stale_timeout_int && stale_timeout_int->getInt() > 0 && mocpp_tick_ms() - last_recv >= (stale_timeout_int->getInt() * 1000UL)) {
        MO_DBG_INFO("connection %s -- stale, reconnect", url.c_str());
        reconnect();
        return;
    }

    if (websocket && isConnectionOpen() &&
            ws_ping_interval_int && ws_ping_interval_int->getInt() > 0 && mocpp_tick_ms() - last_hb >= (ws_ping_interval_int->getInt() * 1000UL)) {
        last_hb = mocpp_tick_ms();
#if defined(MO_MG_VERSION_614)
        mg_send_websocket_frame(websocket, WEBSOCKET_OP_PING, "", 0);
#else
        mg_ws_send(websocket, "", 0, WEBSOCKET_OP_PING);
#endif
    }

    if (websocket != nullptr) { //connection pointer != nullptr means that the socket is still open
        return;
    }

    if (url.empty()) {
        //cannot open OCPP connection: credentials missing
        return;
    }

    if (reconnect_interval_int && reconnect_interval_int->getInt() > 0 && mocpp_tick_ms() - last_reconnection_attempt < (reconnect_interval_int->getInt() * 1000UL)) {
        return;
    }

    MO_DBG_DEBUG("(re-)connect to %s", url.c_str());

    last_reconnection_attempt = mocpp_tick_ms();

#if defined(MO_MG_VERSION_614)

    struct mg_connect_opts opts;
    memset(&opts, 0, sizeof(opts));

    const char *ca_string = ca_cert ? ca_cert : "*"; //"*" enables TLS but disables CA verification

    //Check if SSL is disabled, i.e. if URL starts with "ws:"
    if (url.length() >= strlen("ws:") &&
            tolower(url.c_str()[0]) == 'w' &&
            tolower(url.c_str()[1]) == 's' &&
            url.c_str()[2] == ':') {
        //yes, disable SSL
        ca_string = nullptr;
        MO_DBG_WARN("Insecure connection (WS)");
    }

    opts.ssl_ca_cert = ca_string;

    char extra_headers [128] = {'\0'};

    if (!auth_key.empty()) {
        auto ret = snprintf(extra_headers, 128, "Authorization: Basic %s\r\n", basic_auth64.c_str());
        if (ret < 0 || ret >= 128) {
            MO_DBG_ERR("Basic Authentication failed: %d", ret);
            (void)0;
        }
    }

    websocket = mg_connect_ws_opt(
        mgr,
        ws_cb,
        this,
        opts,
        url.c_str(),
        protocolVersion.major == 2 ? "ocpp2.0.1" : "ocpp1.6",
        *extra_headers ? extra_headers : nullptr);

    if (websocket) {
        websocket->flags |= MO_MG_F_IS_MOcppMongooseClient;
    }

#else

    websocket = mg_ws_connect(
        mgr, 
        url.c_str(), 
        ws_cb, 
        this, 
        "Sec-WebSocket-Protocol: %s%s%s\r\n",
                      protocolVersion.major == 2 ? "ocpp2.0.1" : "ocpp1.6",
                      basic_auth64.empty() ? "" : "\r\nAuthorization: Basic ", 
                      basic_auth64.empty() ? "" : basic_auth64.c_str());     // Create client
#endif

}

void MOcppMongooseClient::reconnect() {
    if (!websocket) {
        return;
    }
#if defined(MO_MG_VERSION_614)
    if (!connection_closing) {
        const char *msg = "socket closed by client";
        mg_send_websocket_frame(websocket, WEBSOCKET_OP_CLOSE, msg, strlen(msg));
    }
#else
    websocket->is_closing = 1; //Mongoose will close the socket and the following maintainWsConn() call will open it again
#endif
    setConnectionOpen(false);
}

void MOcppMongooseClient::setBackendUrl(const char *backend_url_cstr) {
    if (!backend_url_cstr) {
        MO_DBG_ERR("invalid argument");
        return;
    }

    if (setting_backend_url_str) {
        setting_backend_url_str->setString(backend_url_cstr);
        configuration_save();
    }
}

void MOcppMongooseClient::setChargeBoxId(const char *cb_id_cstr) {
    if (!cb_id_cstr) {
        MO_DBG_ERR("invalid argument");
        return;
    }

    if (setting_cb_id_str) {
        setting_cb_id_str->setString(cb_id_cstr);
        configuration_save();
    }
}

void MOcppMongooseClient::setAuthKey(const char *auth_key_cstr) {
    if (!auth_key_cstr) {
        MO_DBG_ERR("invalid argument");
        return;
    }

    if (setting_auth_key_str) {
        setting_auth_key_str->setString(auth_key_cstr);
        configuration_save();
    }
}

void MOcppMongooseClient::setCaCert(const char *ca_cert_cstr) {
    ca_cert = ca_cert_cstr; //updated ca_cert takes immediate effect
}

void MOcppMongooseClient::reloadConfigs() {

    reconnect(); //closes WS connection; will be reopened in next maintainWsConn execution

    /*
     * reload WS credentials from configs
     */
    if (setting_backend_url_str) {
        backend_url = setting_backend_url_str->getString();
    }

    if (setting_cb_id_str) {
        cb_id = setting_cb_id_str->getString();
    }

    if (setting_auth_key_str) {
        auth_key = setting_auth_key_str->getString();
    }

    /*
     * determine new URL and auth token with updated WS credentials
     */

    url.clear();
    basic_auth64.clear();

    if (backend_url.empty()) {
        MO_DBG_DEBUG("empty URL closes connection");
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

        MO_DBG_DEBUG("auth Token=%s", token.c_str());

        unsigned int base64_length = encode_base64_length(token.length());
        std::vector<unsigned char> base64 (base64_length + 1);

        // encode_base64() places a null terminator automatically, because the output is a string
        base64_length = encode_base64((const unsigned char*) token.c_str(), token.length(), &base64[0]);

        MO_DBG_DEBUG("auth64 len=%u, auth64 Token=%s", base64_length, &base64[0]);

        basic_auth64 = (const char*) &base64[0];
    } else {
        MO_DBG_DEBUG("no authentication");
        (void) 0;
    }
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

#if defined(MO_MG_VERSION_614)

void ws_cb(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {

    MOcppMongooseClient *osock = nullptr;
    
    if (user_data && nc->flags & MG_F_IS_WEBSOCKET && nc->flags & MO_MG_F_IS_MOcppMongooseClient) {
        osock = reinterpret_cast<MOcppMongooseClient*>(user_data);
    } else {
        return;
    }

    switch (ev) {
        case MG_EV_CONNECT: {
            int status = *((int *) ev_data);
            if (status != 0) {
                MO_DBG_WARN("connection %s -- error %d", osock->getUrl(), status);
                (void)0;
            }
            break;
        }
        case MG_EV_WEBSOCKET_HANDSHAKE_DONE: {
            struct http_message *hm = (struct http_message *) ev_data;
            if (hm->resp_code == 101) {
                MO_DBG_INFO("connection %s -- connected!", osock->getUrl());
                osock->setConnectionOpen(true);
            } else {
                MO_DBG_WARN("connection %s -- HTTP error %d", osock->getUrl(), hm->resp_code);
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
                MO_DBG_ERR("processing WS input failed");
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
            MO_DBG_INFO("connection %s -- closed", osock->getUrl());
            osock->cleanConnection();
            break;
        }
    }
}

#else

void ws_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev != 2) {
        MO_DBG_VERBOSE("Cb fn with event: %d\n", ev);
        (void)0;
    }

    MOcppMongooseClient *osock = reinterpret_cast<MOcppMongooseClient*>(fn_data);
    if (!osock) {
        if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
            MO_DBG_INFO("connection %s", ev == MG_EV_CLOSE ? "closed" : "error");
            (void)0;
        } else {
            MO_DBG_ERR("invalid state %d", ev);
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
            if (ca_string && *ca_string == '\0') { //check if certificate verification is disabled (cert string is empty)
                //yes, disabled
                ca_string = nullptr;
            }
            struct mg_tls_opts opts;
            memset(&opts, 0, sizeof(struct mg_tls_opts));
            opts.ca = ca_string;
            opts.srvname = mg_url_host(osock->getUrl());
            mg_tls_init(c, &opts);
        } else {
            MO_DBG_WARN("Insecure connection (WS)");
        }
    } else if (ev == MG_EV_WS_OPEN) {
        // WS connection established. Perform MQTT login
        MO_DBG_INFO("connection %s -- connected!", osock->getUrl());
        osock->setConnectionOpen(true);
        osock->updateRcvTimer();
    } else if (ev == MG_EV_WS_MSG) {
        struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
        if (!osock->getReceiveTXTcallback()((const char*) wm->data.ptr, wm->data.len)) {
            MO_DBG_WARN("processing input message failed");
        }
        osock->updateRcvTimer();
    } else if (ev == MG_EV_WS_CTL) {
        osock->updateRcvTimer();
    }

    if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
        MO_DBG_INFO("connection %s -- %s", osock->getUrl(), ev == MG_EV_CLOSE ? "closed" : "error");
        osock->cleanConnection();
    }
}
#endif
