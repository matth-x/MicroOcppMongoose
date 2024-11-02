// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2024
// GPL-3.0 License (see LICENSE)

#include "MicroOcppMongooseClient.h"
#include <MicroOcpp/Core/Configuration.h>
#include <MicroOcpp/Debug.h>

#if MO_ENABLE_V201
#include <MicroOcpp/Model/Variables/VariableContainer.h>
#endif

#define DEBUG_MSG_INTERVAL 5000UL
#define WS_UNRESPONSIVE_THRESHOLD_MS 15000UL

#define MO_MG_V614 614
#define MO_MG_V708 708
#define MO_MG_V713 713
#define MO_MG_V714 714
#define MO_MG_V715 715

#ifndef MO_MG_USE_VERSION
#if defined(MO_MG_VERSION_614)
#define MO_MG_USE_VERSION MO_MG_V614
#else
#define MO_MG_USE_VERSION MO_MG_V708
#endif
#endif

#if MO_MG_USE_VERSION == MO_MG_V614
#define MO_MG_F_IS_MOcppMongooseClient MG_F_USER_2
#endif

namespace MicroOcpp {
bool validateAuthorizationKeyHex(const char *auth_key_hex);
}

using namespace MicroOcpp;

#if MO_MG_USE_VERSION <= MO_MG_V708
void ws_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data);
#else
void ws_cb(struct mg_connection *c, int ev, void *ev_data);
#endif

MOcppMongooseClient::MOcppMongooseClient(struct mg_mgr *mgr,
            const char *backend_url_factory, 
            const char *charge_box_id_factory,
            unsigned char *auth_key_factory, size_t auth_key_factory_len,
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

    if (auth_key_factory_len > MO_AUTHKEY_LEN_MAX) {
        MO_DBG_WARN("auth_key_factory too long - will be cropped");
        auth_key_factory_len = MO_AUTHKEY_LEN_MAX;
    }

#if MO_ENABLE_V201
    if (protocolVersion.major == 2) {
        websocketSettings = std::unique_ptr<VariableContainerOwning>(new VariableContainerOwning());
        if (filesystem) {
            websocketSettings->enablePersistency(filesystem, MO_WSCONN_FN_V201);
        }

        auto csmsUrl = makeVariable(Variable::InternalDataType::String, Variable::AttributeType::Actual);
        csmsUrl->setComponentId("SecurityCtrlr");
        csmsUrl->setName("CsmsUrl");
        csmsUrl->setString(backend_url_factory ? backend_url_factory : "");
        csmsUrl->setPersistent();
        v201csmsUrlString = csmsUrl.get();
        websocketSettings->add(std::move(csmsUrl));

        auto identity = makeVariable(Variable::InternalDataType::String, Variable::AttributeType::Actual);
        identity->setComponentId("SecurityCtrlr");
        identity->setName("Identity");
        identity->setString(charge_box_id_factory ? charge_box_id_factory : "");
        identity->setPersistent();
        v201identityString = identity.get();
        websocketSettings->add(std::move(identity));

        auto basicAuthPassword = makeVariable(Variable::InternalDataType::String, Variable::AttributeType::Actual);
        basicAuthPassword->setComponentId("SecurityCtrlr");
        basicAuthPassword->setName("BasicAuthPassword");
        char basicAuthPasswordVal [MO_AUTHKEY_LEN_MAX + 1];
        snprintf(basicAuthPasswordVal, sizeof(basicAuthPasswordVal), "%.*s", (int)auth_key_factory_len, auth_key_factory ? (const char*)auth_key_factory : "");
        basicAuthPassword->setString(basicAuthPasswordVal);
        basicAuthPassword->setPersistent();
        v201basicAuthPasswordString = basicAuthPassword.get();
        websocketSettings->add(std::move(basicAuthPassword));

        websocketSettings->load(); //if settings on flash already exist, this overwrites factory defaults
    } else
#endif
    {
        setting_backend_url_str = declareConfiguration<const char*>(
            MO_CONFIG_EXT_PREFIX "BackendUrl", backend_url_factory, MO_WSCONN_FN, readonly, true);
        setting_cb_id_str = declareConfiguration<const char*>(
            MO_CONFIG_EXT_PREFIX "ChargeBoxId", charge_box_id_factory, MO_WSCONN_FN, readonly, true);

        char auth_key_hex [2 * MO_AUTHKEY_LEN_MAX + 1];
        auth_key_hex[0] = '\0';
        if (auth_key_factory) {
            for (size_t i = 0; i < auth_key_factory_len; i++) {
                snprintf(auth_key_hex + 2 * i, 3, "%02X", auth_key_factory[i]);
            }
        }
        setting_auth_key_hex_str = declareConfiguration<const char*>(
            "AuthorizationKey", auth_key_hex, MO_WSCONN_FN, readonly, true);
        registerConfigurationValidator("AuthorizationKey", validateAuthorizationKeyHex);
    }

    ws_ping_interval_int = declareConfiguration<int>(
        "WebSocketPingInterval", 5, MO_WSCONN_FN);
    reconnect_interval_int = declareConfiguration<int>(
        MO_CONFIG_EXT_PREFIX "ReconnectInterval", 10, MO_WSCONN_FN);
    stale_timeout_int = declareConfiguration<int>(
        MO_CONFIG_EXT_PREFIX "StaleTimeout", 300, MO_WSCONN_FN);

    configuration_load(MO_WSCONN_FN); //load configs with values stored on flash

    ca_cert = ca_certificate;

    reloadConfigs(); //load WS creds with configs values

#if MO_MG_USE_VERSION == MO_MG_V614
    MO_DBG_DEBUG("use MG version %s (tested with 6.14)", MG_VERSION);
#elif MO_MG_USE_VERSION == MO_MG_V708
    MO_DBG_DEBUG("use MG version %s (tested with 7.8)", MG_VERSION);
#elif MO_MG_USE_VERSION == MO_MG_V713
    MO_DBG_DEBUG("use MG version %s (tested with 7.13)", MG_VERSION);
#endif

    maintainWsConn();
}

MOcppMongooseClient::MOcppMongooseClient(struct mg_mgr *mgr,
            const char *backend_url_factory, 
            const char *charge_box_id_factory,
            const char *auth_key_factory,
            const char *ca_certificate,
            std::shared_ptr<FilesystemAdapter> filesystem,
            ProtocolVersion protocolVersion) :

    MOcppMongooseClient(mgr,
            backend_url_factory,
            charge_box_id_factory,
            (unsigned char *)auth_key_factory, auth_key_factory ? strlen(auth_key_factory) : 0,
            ca_certificate,
            filesystem,
            protocolVersion) {

}

MOcppMongooseClient::~MOcppMongooseClient() {
    MO_DBG_DEBUG("destruct MOcppMongooseClient");
    if (websocket) {
        reconnect(); //close WS connection, won't be reopened
#if MO_MG_USE_VERSION == MO_MG_V614
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
#if MO_MG_USE_VERSION == MO_MG_V614
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
#if MO_MG_USE_VERSION == MO_MG_V614
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

    /*
     * determine auth token
     */

    std::string basic_auth64;

    if (auth_key_len > 0) {

        #if MO_DBG_LEVEL >= MO_DL_DEBUG
        {
            char auth_key_hex [2 * MO_AUTHKEY_LEN_MAX + 1];
            auth_key_hex[0] = '\0';
            for (size_t i = 0; i < auth_key_len; i++) {
                snprintf(auth_key_hex + 2 * i, 3, "%02X", auth_key[i]);
            }
            MO_DBG_DEBUG("auth Token=%s:%s (key will be converted to non-hex)", cb_id.c_str(), auth_key_hex);
        }
        #endif //MO_DBG_LEVEL >= MO_DL_DEBUG

        unsigned char *token = new unsigned char[cb_id.length() + 1 + auth_key_len]; //cb_id:auth_key
        if (!token) {
            //OOM
            return;
        }
        size_t len = 0;
        memcpy(token, cb_id.c_str(), cb_id.length());
        len += cb_id.length();
        token[len++] = (unsigned char) ':';
        memcpy(token + len, auth_key, auth_key_len);
        len += auth_key_len;

        int base64_length = ((len + 2) / 3) * 4; //3 bytes base256 get encoded into 4 bytes base64. --> base64_len = ceil(len/3) * 4
        char *base64 = new char[base64_length + 1];
        if (!base64) {
            //OOM
            delete[] token;
            return;
        }

        // mg_base64_encode() places a null terminator automatically, because the output is a c-string
        #if MO_MG_USE_VERSION <= MO_MG_V708
        mg_base64_encode(token, len, base64);
        #else
        mg_base64_encode(token, len, base64, base64_length + 1);
        #endif
        delete[] token;

        MO_DBG_DEBUG("auth64 len=%u, auth64 Token=%s", base64_length, base64);

        basic_auth64 = &base64[0];

        delete[] base64;
    } else {
        MO_DBG_DEBUG("no authentication");
        (void) 0;
    }

#if MO_MG_USE_VERSION == MO_MG_V614

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

    if (!basic_auth64.empty()) {
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
#if MO_MG_USE_VERSION == MO_MG_V614
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

#if MO_ENABLE_V201
    if (protocolVersion.major == 2) {
        if (v201csmsUrlString) {
            v201csmsUrlString->setString(backend_url_cstr);
            websocketSettings->commit();
        }
    } else
#endif
    {
        if (setting_backend_url_str) {
            setting_backend_url_str->setString(backend_url_cstr);
            configuration_save();
        }
    }

}

void MOcppMongooseClient::setChargeBoxId(const char *cb_id_cstr) {
    if (!cb_id_cstr) {
        MO_DBG_ERR("invalid argument");
        return;
    }

#if MO_ENABLE_V201
    if (protocolVersion.major == 2) {
        if (v201identityString) {
            v201identityString->setString(cb_id_cstr);
            websocketSettings->commit();
        }
    } else
#endif
    {
        if (setting_cb_id_str) {
            setting_cb_id_str->setString(cb_id_cstr);
            configuration_save();
        }
    }

}

void MOcppMongooseClient::setAuthKey(const char *auth_key_cstr) {
    if (!auth_key_cstr) {
        MO_DBG_ERR("invalid argument");
        return;
    }

    return setAuthKey((const unsigned char*)auth_key_cstr, strlen(auth_key_cstr));
}

void MOcppMongooseClient::setAuthKey(const unsigned char *auth_key, size_t len) {
    if (!auth_key || len > MO_AUTHKEY_LEN_MAX) {
        MO_DBG_ERR("invalid argument");
        return;
    }


#if MO_ENABLE_V201
    if (protocolVersion.major == 2) {
        char basicAuthPassword [MO_AUTHKEY_LEN_MAX + 1];
        snprintf(basicAuthPassword, sizeof(basicAuthPassword), "%.*s", (int)len, auth_key ? (const char*)auth_key : "");
        if (v201basicAuthPasswordString) {
            v201basicAuthPasswordString->setString(basicAuthPassword);
        }
    } else
#endif
    {
        char auth_key_hex [2 * MO_AUTHKEY_LEN_MAX + 1];
        auth_key_hex[0] = '\0';
        for (size_t i = 0; i < len; i++) {
            snprintf(auth_key_hex + 2 * i, 3, "%02X", auth_key[i]);
        }
        if (setting_auth_key_hex_str) {
            setting_auth_key_hex_str->setString(auth_key_hex);
            configuration_save();
        }
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

#if MO_ENABLE_V201
    if (protocolVersion.major == 2) {
        if (v201csmsUrlString) {
            backend_url = v201csmsUrlString->getString();
        }

        if (v201identityString) {
            cb_id = v201identityString->getString();
        }

        if (v201basicAuthPasswordString) {
            snprintf((char*)auth_key, sizeof(auth_key), "%s", v201basicAuthPasswordString->getString());
            auth_key_len = strlen((char*)auth_key);
        }
    } else
#endif
    {
        if (setting_backend_url_str) {
            backend_url = setting_backend_url_str->getString();
        }

        if (setting_cb_id_str) {
            cb_id = setting_cb_id_str->getString();
        }

        if (setting_auth_key_hex_str) {
            auto auth_key_hex = setting_auth_key_hex_str->getString();
            auto auth_key_hex_len = strlen(setting_auth_key_hex_str->getString());
            if (!validateAuthorizationKeyHex(auth_key_hex)) {
                MO_DBG_ERR("AuthorizationKey stored with format error. Disable Basic Auth");
                auth_key_hex_len = 0;
            }

            auth_key_len = auth_key_hex_len / 2;

            #if MO_MG_VERSION_614
            cs_from_hex((char*)auth_key, auth_key_hex, auth_key_hex_len);
            #elif MO_MG_USE_VERSION <= MO_MG_V713
            mg_unhex(auth_key_hex, auth_key_hex_len, auth_key);
            #else
            for (size_t i = 0; i < auth_key_len; i++) {
                mg_str_to_num(mg_str_n(auth_key_hex + 2*i, 2), 16, auth_key + i, sizeof(uint8_t));
            }
            #endif

            auth_key[auth_key_len] = '\0'; //need null-termination as long as deprecated `const char *getAuthKey()` exists
        }
    }

    /*
     * determine new URL with updated WS credentials
     */

    url.clear();

    if (backend_url.empty()) {
        MO_DBG_DEBUG("empty URL closes connection");
        return;
    }

    url = backend_url;

    if (url.back() != '/' && !cb_id.empty()) {
        url.append("/");
    }
    url.append(cb_id);
}

int MOcppMongooseClient::printAuthKey(unsigned char *buf, size_t size) {
    if (!buf || size < auth_key_len) {
        MO_DBG_ERR("invalid argument");
        return -1;
    }

    memcpy(buf, auth_key, auth_key_len);
    return (int)auth_key_len;
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

#if MO_ENABLE_V201
VariableContainer *MOcppMongooseClient::getVariableContainer() {
    return websocketSettings.get();
}
#endif

#if MO_MG_USE_VERSION == MO_MG_V614

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

#if MO_MG_USE_VERSION <= MO_MG_V708
void ws_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
#else
void ws_cb(struct mg_connection *c, int ev, void *ev_data) {
    void *fn_data = c->fn_data;
#endif
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
            #if MO_MG_USE_VERSION <= MO_MG_V708
            opts.ca = ca_string;
            opts.srvname = mg_url_host(osock->getUrl());
            #else
            opts.ca = mg_str(ca_string);
            opts.name = mg_url_host(osock->getUrl());
            #endif
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
#if MO_MG_USE_VERSION <= MO_MG_V713
        if (!osock->getReceiveTXTcallback()((const char*) wm->data.ptr, wm->data.len)) {
#else
        if (!osock->getReceiveTXTcallback()((const char*) wm->data.buf, wm->data.len)) {
#endif
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

bool MicroOcpp::validateAuthorizationKeyHex(const char *auth_key_hex) {
    if (!auth_key_hex) {
        return true; //nullptr (or "") means disable Auth
    }
    bool valid = true;
    size_t i = 0;
    while (i <= 2 * MO_AUTHKEY_LEN_MAX && auth_key_hex[i] != '\0') {
        //check if character is in 0-9, a-f, or A-F
        if ( (auth_key_hex[i] >= '0' && auth_key_hex[i] <= '9') ||
             (auth_key_hex[i] >= 'a' && auth_key_hex[i] <= 'f') ||
             (auth_key_hex[i] >= 'A' && auth_key_hex[i] <= 'F')) {
            //yes, it is
            i++;
        } else {
            //no, it isn't
            valid = false;
            break;
        }
    }
    valid &= auth_key_hex[i] == '\0';
    valid &= (i % 2) == 0;
    if (!valid) {
        MO_DBG_ERR("AuthorizationKey must be hex with at most 20 octets");
        (void)0;
    }
    return valid;
}
