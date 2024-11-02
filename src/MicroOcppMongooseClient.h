// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2024
// GPL-3.0 License (see LICENSE)

#ifndef MO_MONGOOSECLIENT_H
#define MO_MONGOOSECLIENT_H

#if defined(ARDUINO) //fix for conflicting definitions of IPAddress on Arduino
#include <Arduino.h>
#include <IPAddress.h>
#endif

#include "mongoose.h"
#include <MicroOcpp/Core/Connection.h>
#include <MicroOcpp/Version.h>

#include <string>
#include <memory>

#ifndef MO_WSCONN_FN
#define MO_WSCONN_FN (MO_FILENAME_PREFIX "ws-conn.jsn")
#define MO_WSCONN_FN_V201 (MO_FILENAME_PREFIX "ws-conn-v201.jsn")
#endif

#if MO_ENABLE_V201
#define MO_AUTHKEY_LEN_MAX 40 //BasicAuthPassword length
#else
#define MO_AUTHKEY_LEN_MAX 20 //AuthKey in Bytes. Hex value has double length
#endif

namespace MicroOcpp {

class FilesystemAdapter;
class Configuration;

#if MO_ENABLE_V201
class Variable;
class VariableContainer;
class VariableContainerOwning;
#endif

class MOcppMongooseClient : public MicroOcpp::Connection {
private:
    struct mg_mgr *mgr {nullptr};
    struct mg_connection *websocket {nullptr};
    std::string backend_url;
    std::string cb_id;
    std::string url; //url = backend_url + '/' + cb_id
    unsigned char auth_key [MO_AUTHKEY_LEN_MAX + 1]; //OCPP 2.0.1: BasicAuthPassword. OCPP 1.6: AuthKey in bytes encoding ("FF01" = {0xFF, 0x01}). Both versions append a terminating '\0'
    size_t auth_key_len;
    const char *ca_cert; //zero-copy. The host system must ensure that this pointer remains valid during the lifetime of this class
    std::shared_ptr<Configuration> setting_backend_url_str;
    std::shared_ptr<Configuration> setting_cb_id_str;
    std::shared_ptr<Configuration> setting_auth_key_hex_str;
    unsigned long last_status_dbg_msg {0}, last_recv {0};
    std::shared_ptr<Configuration> reconnect_interval_int; //minimum time between two connect trials in s
    unsigned long last_reconnection_attempt {-1UL / 2UL};
    std::shared_ptr<Configuration> stale_timeout_int; //inactivity period after which the connection will be closed
    std::shared_ptr<Configuration> ws_ping_interval_int; //heartbeat intervall in s. 0 sets hb off
    unsigned long last_hb {0};
#if MO_ENABLE_V201
    std::unique_ptr<VariableContainerOwning> websocketSettings;
    Variable *v201csmsUrlString = nullptr;
    Variable *v201identityString = nullptr;
    Variable *v201basicAuthPasswordString = nullptr;
#endif
    bool connection_established {false};
    unsigned long last_connection_established {-1UL / 2UL};
    bool connection_closing {false};
    ReceiveTXTcallback receiveTXTcallback = [] (const char *, size_t) {return false;};

    ProtocolVersion protocolVersion;

    void reconnect();

    void maintainWsConn();

public:
    MOcppMongooseClient(struct mg_mgr *mgr, 
            const char *backend_url_factory, 
            const char *charge_box_id_factory,
            unsigned char *auth_key_factory, size_t auth_key_factory_len,
            const char *ca_cert = nullptr, //zero-copy, the string must outlive this class and mg_mgr. Forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)
            std::shared_ptr<MicroOcpp::FilesystemAdapter> filesystem = nullptr,
            ProtocolVersion protocolVersion = ProtocolVersion(1,6));
    
    //DEPRECATED: will be removed in a future release
    MOcppMongooseClient(struct mg_mgr *mgr, 
            const char *backend_url_factory = nullptr, 
            const char *charge_box_id_factory = nullptr,
            const char *auth_key_factory = nullptr,
            const char *ca_cert = nullptr, //zero-copy, the string must outlive this class and mg_mgr. Forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)
            std::shared_ptr<MicroOcpp::FilesystemAdapter> filesystem = nullptr,
            ProtocolVersion protocolVersion = ProtocolVersion(1,6));

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
    void setAuthKey(const char *auth_key); //DEPRECATED: will be removed in a future release
    void setAuthKey(const unsigned char *auth_key, size_t len); //set the auth key in bytes-encoded format
    void setCaCert(const char *ca_cert); //forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)

    void reloadConfigs();

    const char *getBackendUrl() {return backend_url.c_str();}
    const char *getChargeBoxId() {return cb_id.c_str();}
    const char *getAuthKey() {return (const char*)auth_key;} //DEPRECATED: will be removed in a future release
    int printAuthKey(unsigned char *buf, size_t size);
    const char *getCaCert() {return ca_cert ? ca_cert : "";}

    const char *getUrl() {return url.c_str();}

    void setConnectionOpen(bool open);
    bool isConnectionOpen() {return connection_established && !connection_closing;}
    bool isConnected() {return isConnectionOpen();}
    void cleanConnection();

    void updateRcvTimer();
    unsigned long getLastRecv(); //get time of last successful receive in millis
    unsigned long getLastConnected(); //get time of last connection establish

#if MO_ENABLE_V201
    //WS client creates and manages its own Variables. This getter function is a temporary solution, in future
    //the WS client will be initialized with a Context reference for registering the Variables directly
    VariableContainer *getVariableContainer();
#endif
};

}

#endif
