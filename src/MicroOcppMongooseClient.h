// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2023
// GPL-3.0 License (see LICENSE)

#ifndef AOCPPMONGOOSECLIENT_H
#define AOCPPMONGOOSECLIENT_H

#if defined(ARDUINO) //fix for conflicting defitions of IPAddress on Arduino
#include <Arduino.h>
#include <IPAddress.h>
#endif

#include "mongoose.h"
#include <MicroOcpp/Core/Connection.h>

#include <string>
#include <memory>

#ifndef MO_WSCONN_FN
#define MO_WSCONN_FN (MO_FILENAME_PREFIX "ws-conn.jsn")
#endif

/*
 * If you prefer not to have the TLS-certificate managed by OCPP, store it into
 * a file on the flash filesystem, define the following build flag as 1 and
 * pass the filename to the constructor instead of a default plain-text certificate.
*/
#ifndef MO_CA_CERT_LOCAL
#define MO_CA_CERT_LOCAL 0
#endif

namespace MicroOcpp {

class FilesystemAdapter;
class Configuration;

class MOcppMongooseClient : public MicroOcpp::Connection {
private:
    struct mg_mgr *mgr {nullptr};
    struct mg_connection *websocket {nullptr};
    std::string backend_url;
    std::string cb_id;
    std::string url; //url = backend_url + '/' + cb_id
    std::string auth_key;
    std::string basic_auth64;
    std::string ca_cert;
    std::shared_ptr<Configuration> setting_backend_url_str;
    std::shared_ptr<Configuration> setting_cb_id_str;
    std::shared_ptr<Configuration> setting_auth_key_str;
#if !MO_CA_CERT_LOCAL
    std::shared_ptr<Configuration> setting_ca_cert_str;
#endif
    unsigned long last_status_dbg_msg {0}, last_recv {0};
    std::shared_ptr<Configuration> reconnect_interval_int; //minimum time between two connect trials in s
    unsigned long last_reconnection_attempt {-1UL / 2UL};
    std::shared_ptr<Configuration> stale_timeout_int; //inactivity period after which the connection will be closed
    std::shared_ptr<Configuration> ws_ping_interval_int; //heartbeat intervall in s. 0 sets hb off
    unsigned long last_hb {0};
    bool connection_established {false};
    unsigned long last_connection_established {-1UL / 2UL};
    bool connection_closing {false};
    ReceiveTXTcallback receiveTXTcallback = [] (const char *, size_t) {return false;};

    void reconnect();

    void maintainWsConn();

public:
    MOcppMongooseClient(struct mg_mgr *mgr, 
            const char *backend_url_factory = nullptr, 
            const char *charge_box_id_factory = nullptr,
            const char *auth_key_factory = nullptr,
            const char *CA_cert_factory = nullptr, //forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)
            std::shared_ptr<MicroOcpp::FilesystemAdapter> filesystem = nullptr);

    ~MOcppMongooseClient();

    void loop() override;

    bool sendTXT(const char *msg, size_t length) override;

    void setReceiveTXTcallback(MicroOcpp::ReceiveTXTcallback &receiveTXT) override {
        this->receiveTXTcallback = receiveTXT;
    }

    MicroOcpp::ReceiveTXTcallback &getReceiveTXTcallback() {
        return receiveTXTcallback;
    }

    //update WS configs. To apply the updates, call `reloadConfigs()` afterwards
    void setBackendUrl(const char *backend_url);
    void setChargeBoxId(const char *cb_id);
    void setAuthKey(const char *auth_key);
    void setCaCert(const char *ca_cert); //forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)

    void reloadConfigs();

    const char *getBackendUrl() {return backend_url.c_str();}
    const char *getChargeBoxId() {return cb_id.c_str();}
    const char *getAuthKey() {return auth_key.c_str();}
    const char *getCaCert() {return ca_cert.c_str();}

    const char *getUrl() {return url.c_str();}

    void setConnectionOpen(bool open);
    bool isConnectionOpen() {return connection_established && !connection_closing;}
    void cleanConnection();

    void updateRcvTimer();
    unsigned long getLastRecv(); //get time of last successful receive in millis
    unsigned long getLastConnected(); //get time of last connection establish
    unsigned long getLastConnAttempt(); //get time of last reconnect attempt
};

}

#endif
