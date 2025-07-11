// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2024
// GPL-3.0 License (see LICENSE)

#include <MicroOcppMongooseClient.h>

#include <MicroOcpp/Core/Memory.h>
#include <MicroOcpp/Core/FilesystemAdapter.h>
#include <MicroOcpp/Model/Configuration/ConfigurationService.h>
#include <MicroOcpp/Model/Variables/VariableService.h>
#include <MicroOcpp/Debug.h>

#define DEBUG_MSG_INTERVAL_S 5
#define WS_UNRESPONSIVE_THRESHOLD_S 15

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

#define MO_MG_WSADAPTER_MEMTAG "MicroOcppMongooseClient.cpp"

struct MOcppMongooseClient : public MicroOcpp::Connection, public MicroOcpp::MemoryManaged {
    struct mg_mgr *mgr = nullptr;
    struct mg_connection *websocket = nullptr;
    MicroOcpp::Clock *clock = nullptr;
    MicroOcpp::String backend_url;
    MicroOcpp::String cb_id;
    MicroOcpp::String url; //url = backend_url + '/' + cb_id
    unsigned char auth_key [MO_AUTHKEY_LEN_MAX + 1]; //OCPP 2.0.1: BasicAuthPassword. OCPP 1.6: AuthKey in bytes encoding ("FF01" = {0xFF, 0x01}). Both versions append a terminating '\0'
    size_t auth_key_len;
    const char *ca_cert; //zero-copy. The host system must ensure that this pointer remains valid during the lifetime of this class

#if MO_ENABLE_V16
    MicroOcpp::v16::ConfigurationService *configService = nullptr;
    std::unique_ptr<MicroOcpp::v16::ConfigurationContainerOwning> urlConfigs;
    MicroOcpp::v16::Configuration *setting_backend_url_str = nullptr;
    MicroOcpp::v16::Configuration *setting_cb_id_str = nullptr;
    MicroOcpp::v16::Configuration *setting_auth_key_hex_str = nullptr;
    MicroOcpp::v16::Configuration *reconnect_interval_int = nullptr; //minimum time between two connect trials in s
    MicroOcpp::v16::Configuration *stale_timeout_int = nullptr; //inactivity period after which the connection will be closed
    MicroOcpp::v16::Configuration *ws_ping_interval_int = nullptr; //heartbeat intervall in s. 0 sets hb off
#endif //MO_ENABLE_V16
#if MO_ENABLE_V201
    MicroOcpp::v201::VariableService *varService = nullptr;
    std::unique_ptr<MicroOcpp::v201::VariableContainerOwning> urlVariables;
    MicroOcpp::v201::Variable *v201csmsUrlString = nullptr;
    MicroOcpp::v201::Variable *v201identityString = nullptr;
    MicroOcpp::v201::Variable *v201basicAuthPasswordString = nullptr;
    MicroOcpp::v201::Variable *v201retryBackOffWaitMinimumInt = nullptr;
    MicroOcpp::v201::Variable *v201staleTimeoutInt = nullptr;
    MicroOcpp::v201::Variable *v201webSocketPingIntervalInt = nullptr;
#endif //MO_ENABLE_V201

    int32_t last_status_dbg_msg {0}, last_recv {0};
    int32_t last_reconnection_attempt = -1;
    int32_t last_hb {0};

    bool connection_established {false};
    int32_t last_connection_established {-1};
    bool connection_closing {false};

    int ocppVersion = -1;

    void reconnect();

    void maintainWsConn();

    MOcppMongooseClient();

    ~MOcppMongooseClient();

    bool setupConnection(MicroOcpp::Context *context,
        MO_FilesystemAdapter *filesystem,
        struct mg_mgr *mgr, 
        const char *backend_url_factory, 
        const char *charge_box_id_factory,
        const unsigned char *auth_key_factory, size_t auth_key_factory_len,
        const char *ca_cert = nullptr); //zero-copy, the string must outlive this class and mg_mgr. Forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)

    void loop() override;

    bool sendTXT(const char *msg, size_t length) override;

    void reloadUrl();

    const char *getAuthKey() {return (const char*)auth_key;} //DEPRECATED: will be removed in a future release
    int printAuthKey(unsigned char *buf, size_t size);

    void setConnectionOpen(bool open);
    bool isConnectionOpen() {return connection_established && !connection_closing;}
    bool isConnected() override {return isConnectionOpen();}
    void cleanConnection();

    void updateRcvTimer();

    static bool validateAuthorizationKeyHex(const char *auth_key_hex, void *userData = nullptr);

    #if MO_MG_USE_VERSION <= MO_MG_V708
    static void mongoose_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data);
    #else
    static void mongoose_cb(struct mg_connection *c, int ev, void *ev_data);
    #endif
};

MOcppMongooseClient::MOcppMongooseClient() :
        MicroOcpp::MemoryManaged(MO_MG_WSADAPTER_MEMTAG),
        backend_url(MicroOcpp::makeString(getMemoryTag())),
        cb_id(MicroOcpp::makeString(getMemoryTag())),
        url(MicroOcpp::makeString(getMemoryTag())) {

}

bool MOcppMongooseClient::setupConnection(
            MicroOcpp::Context *context,
            MO_FilesystemAdapter *filesystem,
            struct mg_mgr *mgr,
            const char *backend_url_factory, 
            const char *charge_box_id_factory,
            const unsigned char *auth_key_factory, size_t auth_key_factory_len,
            const char *ca_certificate) {
    
    this->mgr = mgr;
    this->clock = &context->getClock();

    ocppVersion = context->getOcppVersion();
    if (ocppVersion < 0) {
        MO_DBG_ERR("Protocol negotiation not supported. Need to call `mo_setOcppVersion()` before");
        return false;
    }

    if (ocppVersion != MO_OCPP_V16 && ocppVersion != MO_OCPP_V201) {
        MO_DBG_ERR("Unsupported OCPP version: %i", ocppVersion);
        return false;
    }

    if (auth_key_factory_len > MO_AUTHKEY_LEN_MAX) {
        MO_DBG_WARN("auth_key_factory too long - will be cropped");
        auth_key_factory_len = MO_AUTHKEY_LEN_MAX;
    }

    #if MO_ENABLE_V16
    if (ocppVersion == MO_OCPP_V16) {

    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (ocppVersion == MO_OCPP_V201) {
        
    }
    #endif //MO_ENABLE_V201

    MicroOcpp::Mutability mutability;
    if (filesystem) {
        mutability = MicroOcpp::Mutability::ReadWrite;
    } else {
        mutability = MicroOcpp::Mutability::ReadOnly;
    }

    #if MO_ENABLE_V16
    if (ocppVersion == MO_OCPP_V16) {
        configService = context->getModel16().getConfigurationService();
        if (!configService) {
            MO_DBG_ERR("setup failure");
            return false;
        }

        urlConfigs = std::unique_ptr<MicroOcpp::v16::ConfigurationContainerOwning>(new MicroOcpp::v16::ConfigurationContainerOwning());
        if (!urlConfigs) {
            MO_DBG_ERR("OOM");
            return false;
        }
        if (filesystem) {
            urlConfigs->setFilesystem(filesystem);
        }
        urlConfigs->setFilename(MO_WSCONN_FN);

        setting_backend_url_str = configService->getConfiguration(MO_CONFIG_EXT_PREFIX "BackendUrl");
        if (!setting_backend_url_str) {
            auto config = MicroOcpp::v16::makeConfiguration(MicroOcpp::v16::Configuration::Type::String);
            if (!config) {
                MO_DBG_ERR("OOM");
                return false;
            }
            config->setKey(MO_CONFIG_EXT_PREFIX "BackendUrl");
            config->setString(backend_url_factory ? backend_url_factory : "");
            config->setMutability(mutability);
            config->setRebootRequired();
            setting_backend_url_str = config.get();
            urlConfigs->add(std::move(config));
        }

        setting_cb_id_str = configService->getConfiguration(MO_CONFIG_EXT_PREFIX "ChargeBoxId");
        if (!setting_cb_id_str) {
            auto config = MicroOcpp::v16::makeConfiguration(MicroOcpp::v16::Configuration::Type::String);
            if (!config) {
                MO_DBG_ERR("OOM");
                return false;
            }
            config->setKey(MO_CONFIG_EXT_PREFIX "ChargeBoxId");
            config->setString(charge_box_id_factory ? charge_box_id_factory : "");
            config->setMutability(mutability);
            config->setRebootRequired();
            setting_cb_id_str = config.get();
            urlConfigs->add(std::move(config));
        }

        setting_auth_key_hex_str = configService->getConfiguration("AuthorizationKey");
        if (!setting_auth_key_hex_str) {
            auto config = MicroOcpp::v16::makeConfiguration(MicroOcpp::v16::Configuration::Type::String);
            if (!config) {
                MO_DBG_ERR("OOM");
                return false;
            }
            config->setKey("AuthorizationKey");
            char auth_key_hex [2 * MO_AUTHKEY_LEN_MAX + 1];
            auth_key_hex[0] = '\0';
            if (auth_key_factory) {
                for (size_t i = 0; i < auth_key_factory_len; i++) {
                    snprintf(auth_key_hex + 2 * i, 3, "%02X", auth_key_factory[i]);
                }
            }
            config->setString(auth_key_hex);
            config->setMutability(mutability);
            config->setRebootRequired();
            setting_auth_key_hex_str = config.get();
            urlConfigs->add(std::move(config));
        }

        if (urlConfigs->size() > 0) {
            urlConfigs->load(); //if settings on flash already exist, this overwrites factory defaults
            configService->addContainer(urlConfigs.get());
        } else {
            //All variables have been set previously - `urlVariables` is obsolete
            urlConfigs.reset();
        }

        configService->registerValidator<const char*>("AuthorizationKey", validateAuthorizationKeyHex);

        ws_ping_interval_int = configService->declareConfiguration<int>("WebSocketPingInterval", 5);
        reconnect_interval_int = configService->declareConfiguration<int>(MO_CONFIG_EXT_PREFIX "ReconnectInterval", 10);
        stale_timeout_int = configService->declareConfiguration<int>(MO_CONFIG_EXT_PREFIX "StaleTimeout", 300);

        if (!setting_backend_url_str ||
                !setting_cb_id_str ||
                !setting_auth_key_hex_str ||
                !ws_ping_interval_int ||
                !reconnect_interval_int ||
                !stale_timeout_int) {
            
            MO_DBG_ERR("setup failure");
            return false;
        }
    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (ocppVersion == MO_OCPP_V201) {
        varService = context->getModel201().getVariableService();
        if (!varService) {
            MO_DBG_ERR("setup failure");
            return false;
        }

        /* Create dedicated container for connection URL variables. The server can change the URL variables using SetVariables.
         * Usually, it needs to update multiple values at once (e.g. CsmsUrl and Identity). This update needs to be atomic, i.e.
         * if the update fails due to a controller crash, either all values have been written to flash or none. This can be
         * ensured by forcing all variables into the same container.
         * To customize this behavior, declare the variables at the VariableService before executing this code. */

        urlVariables = std::unique_ptr<MicroOcpp::v201::VariableContainerOwning>(new MicroOcpp::v201::VariableContainerOwning());
        if (!urlVariables) {
            MO_DBG_ERR("OOM");
            return false;
        }
        if (filesystem) {
            urlVariables->enablePersistency(filesystem, MO_WSCONN_FN_V201);
        }

        v201csmsUrlString = varService->getVariable("SecurityCtrlr", "CsmsUrl");
        if (!v201csmsUrlString) {
            auto csmsUrl = MicroOcpp::v201::makeVariable(MicroOcpp::v201::Variable::InternalDataType::String, MicroOcpp::v201::Variable::AttributeType::Actual);
            if (!csmsUrl) {
                MO_DBG_ERR("OOM");
                return false;
            }
            csmsUrl->setComponentId("SecurityCtrlr");
            csmsUrl->setName("CsmsUrl");
            csmsUrl->setString(backend_url_factory ? backend_url_factory : "");
            csmsUrl->setMutability(mutability);
            csmsUrl->setPersistent();
            csmsUrl->setRebootRequired();
            v201csmsUrlString = csmsUrl.get();
            urlVariables->add(std::move(csmsUrl));
        }

        v201identityString = varService->getVariable("SecurityCtrlr", "Identity");
        if (!v201identityString) {
            auto identity = MicroOcpp::v201::makeVariable(MicroOcpp::v201::Variable::InternalDataType::String, MicroOcpp::v201::Variable::AttributeType::Actual);
            if (!identity) {
                MO_DBG_ERR("OOM");
                return false;
            }
            identity->setComponentId("SecurityCtrlr");
            identity->setName("Identity");
            identity->setString(charge_box_id_factory ? charge_box_id_factory : "");
            identity->setMutability(mutability);
            identity->setPersistent();
            identity->setRebootRequired();
            v201identityString = identity.get();
            urlVariables->add(std::move(identity));
        }

        v201basicAuthPasswordString = varService->getVariable("SecurityCtrlr", "BasicAuthPassword");
        if (!v201basicAuthPasswordString) {
            auto basicAuthPassword = MicroOcpp::v201::makeVariable(MicroOcpp::v201::Variable::InternalDataType::String, MicroOcpp::v201::Variable::AttributeType::Actual);
            if (!basicAuthPassword) {
                MO_DBG_ERR("OOM");
                return false;
            }
            basicAuthPassword->setComponentId("SecurityCtrlr");
            basicAuthPassword->setName("BasicAuthPassword");
            char basicAuthPasswordVal [MO_AUTHKEY_LEN_MAX + 1];
            snprintf(basicAuthPasswordVal, sizeof(basicAuthPasswordVal), "%.*s", (int)auth_key_factory_len, auth_key_factory ? (const char*)auth_key_factory : "");
            basicAuthPassword->setString(basicAuthPasswordVal);
            basicAuthPassword->setMutability(mutability);
            basicAuthPassword->setPersistent();
            basicAuthPassword->setRebootRequired();
            v201basicAuthPasswordString = basicAuthPassword.get();
            urlVariables->add(std::move(basicAuthPassword));
        }

        if (urlVariables->size() > 0) {
            urlVariables->load(); //if settings on flash already exist, this overwrites factory defaults
            varService->addContainer(urlVariables.get());
        } else {
            //All variables have been set previously - `urlVariables` is obsolete
            urlVariables.reset();
        }
        
        v201retryBackOffWaitMinimumInt = varService->declareVariable<int>("OCPPCommCtrlr", "RetryBackOffWaitMinimum", 10);
        v201staleTimeoutInt = varService->declareVariable<int>("CustomizationCtrlr", "StaleTimeout", 300);
        v201webSocketPingIntervalInt = varService->declareVariable<int>("OCPPCommCtrlr", "WebSocketPingInterval", 5);

        if (!v201retryBackOffWaitMinimumInt ||
                !v201staleTimeoutInt ||
                !v201webSocketPingIntervalInt) {
            MO_DBG_ERR("setup failure");
            return false;
        }
    }
    #endif //MO_ENABLE_V201

    ca_cert = ca_certificate;

    reloadUrl(); //load WS creds from configs / vars into local copy

#if MO_MG_USE_VERSION == MO_MG_V614
    MO_DBG_DEBUG("use MG version %s (tested with 6.14)", MG_VERSION);
#elif MO_MG_USE_VERSION == MO_MG_V708
    MO_DBG_DEBUG("use MG version %s (tested with 7.8)", MG_VERSION);
#elif MO_MG_USE_VERSION == MO_MG_V713
    MO_DBG_DEBUG("use MG version %s (tested with 7.13)", MG_VERSION);
#elif MO_MG_USE_VERSION == MO_MG_V714
    MO_DBG_DEBUG("use MG version %s (tested with 7.14)", MG_VERSION);
#elif MO_MG_USE_VERSION == MO_MG_V715
    MO_DBG_DEBUG("use MG version %s (tested with 7.15)", MG_VERSION);
#endif

    maintainWsConn();

    context->setConnection(this);

    return true;
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

MO_MG_Connection *mo_createMongooseWsClient(
        MO_Context *ctx, 
        MO_FilesystemAdapter *filesystem,
        struct mg_mgr *mgr,
        const char *backendUrlFactory, 
        const char *chargeBoxIdFactory, 
        const char *authKeyFactory, 
        const char *CA_cert) {

    return mo_createMongooseWsClient2(
        ctx,
        filesystem,
        mgr,
        backendUrlFactory,
        chargeBoxIdFactory,
        (unsigned char *)authKeyFactory, authKeyFactory ? strlen(authKeyFactory) : 0,
        CA_cert);
}

MO_MG_Connection *mo_createMongooseWsClient2(
        MO_Context *ctx,
        MO_FilesystemAdapter *filesystem,
        struct mg_mgr *mgr,
        const char *backendUrlFactory,
        const char *chargeBoxIdFactory,
        const unsigned char *authKeyFactory, size_t authKeyFactoryLen,
        const char *CA_cert) {

    if (!ctx) {
        MO_DBG_ERR("OCPP uninitialized"); //need to call mocpp_initialize before
        return nullptr;
    }
    auto context = reinterpret_cast<MicroOcpp::Context*>(ctx);

    auto connection = new MOcppMongooseClient();
    if (!connection) {
        MO_DBG_ERR("OOM");
        return nullptr;
    }

    bool success = connection->setupConnection(
        context,
        filesystem,
        mgr, 
        backendUrlFactory, 
        chargeBoxIdFactory,
        authKeyFactory, authKeyFactoryLen,
        CA_cert);
    
    if (!success) {
        MO_DBG_ERR("setup failure");
        delete connection;
        return nullptr;
    }

    return reinterpret_cast<MO_MG_Connection*>(connection);
}

void mo_freeMongooseWsClient(MO_MG_Connection *connection) {
    delete reinterpret_cast<MOcppMongooseClient*>(connection);
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

    int wsPingInterval = 0;

    #if MO_ENABLE_V16
    if (ocppVersion == MO_OCPP_V16) {
        wsPingInterval = ws_ping_interval_int->getInt();
    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (ocppVersion == MO_OCPP_V201) {
        wsPingInterval = v201webSocketPingIntervalInt->getInt();
    }
    #endif //MO_ENABLE_V201

    int32_t uptime = clock->getUptimeInt();

    if (uptime - last_status_dbg_msg >= DEBUG_MSG_INTERVAL_S) {
        last_status_dbg_msg = uptime;

        //WS successfully connected?
        if (!isConnectionOpen()) {
            MO_DBG_DEBUG("WS unconnected");
        } else if (wsPingInterval > 0 && uptime - last_recv >= wsPingInterval + WS_UNRESPONSIVE_THRESHOLD_S) {
            //WS connected but unresponsive
            MO_DBG_DEBUG("WS unresponsive");
        }
    }

    int staleTimeout = 0;

    #if MO_ENABLE_V16
    if (ocppVersion == MO_OCPP_V16) {
        staleTimeout = stale_timeout_int->getInt();
    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (ocppVersion == MO_OCPP_V201) {
        staleTimeout = v201staleTimeoutInt->getInt();
    }
    #endif //MO_ENABLE_V201

    if (websocket && isConnectionOpen() &&
            staleTimeout > 0 && uptime - last_recv >= staleTimeout) {
        MO_DBG_INFO("connection stale, reconnect");
        MO_DBG_DEBUG("(connection %s)", url.c_str());
        reconnect();
        return;
    }

    if (websocket && isConnectionOpen() &&
            wsPingInterval > 0 && uptime - last_hb >= wsPingInterval) {
        last_hb = uptime;
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

    int reconnectInterval = 0;

    #if MO_ENABLE_V16
    if (ocppVersion == MO_OCPP_V16) {
        reconnectInterval = reconnect_interval_int->getInt();
    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (ocppVersion == MO_OCPP_V201) {
        reconnectInterval = v201retryBackOffWaitMinimumInt->getInt();
    }
    #endif //MO_ENABLE_V201

    if (reconnectInterval > 0 && uptime - last_reconnection_attempt < reconnectInterval && last_reconnection_attempt >= 0) {
        return;
    }

    MO_DBG_DEBUG("(re-)connect to %s", url.c_str());

    last_reconnection_attempt = uptime;

    /*
     * determine auth token
     */

    MicroOcpp::String basic_auth64 = MicroOcpp::makeString(getMemoryTag());

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
        mongoose_cb,
        this,
        opts,
        url.c_str(),
        ocppVersion == MO_OCPP_V16 ? "ocpp1.6" : "ocpp2.0.1",
        *extra_headers ? extra_headers : nullptr);

    if (websocket) {
        websocket->flags |= MO_MG_F_IS_MOcppMongooseClient;
    }

#else

    websocket = mg_ws_connect(
        mgr, 
        url.c_str(), 
        mongoose_cb, 
        this, 
        "Sec-WebSocket-Protocol: %s%s%s\r\n",
                      ocppVersion == MO_OCPP_V16 ? "ocpp1.6" : "ocpp2.0.1",
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

bool mo_setBackendUrl(MO_MG_Connection *connection, const char *backendUrl) {
    if (!backendUrl) {
        MO_DBG_ERR("invalid argument");
        return false;
    }

    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);

    #if MO_ENABLE_V16
    if (conn->ocppVersion == MO_OCPP_V16) {
        conn->setting_backend_url_str->setString(backendUrl);
        conn->configService->commit();
    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (conn->ocppVersion == MO_OCPP_V201) {
        conn->v201csmsUrlString->setString(backendUrl);
        conn->varService->commit();
    }
    #endif //MO_ENABLE_V201
    
    return true;
}

bool mo_setChargeBoxId(MO_MG_Connection *connection, const char *chargeBoxId) {
    if (!chargeBoxId) {
        MO_DBG_ERR("invalid argument");
        return false;
    }

    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);

    #if MO_ENABLE_V16
    if (conn->ocppVersion == MO_OCPP_V16) {
        conn->setting_cb_id_str->setString(chargeBoxId);
        conn->configService->commit();
    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (conn->ocppVersion == MO_OCPP_V201) {
        conn->v201identityString->setString(chargeBoxId);
        conn->varService->commit();
    }
    #endif //MO_ENABLE_V201

    return true;
}

bool mo_setAuthKey(MO_MG_Connection *connection, const char *authKey) {
    return mo_setAuthKey2(connection, (const unsigned char*)authKey, strlen(authKey));
}

bool mo_setAuthKey2(MO_MG_Connection *connection, const unsigned char *authKey, size_t authKeyLen) {
    if (!authKey || authKeyLen > MO_AUTHKEY_LEN_MAX) {
        MO_DBG_ERR("invalid argument");
        return false;
    }

    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);

    #if MO_ENABLE_V16
    if (conn->ocppVersion == MO_OCPP_V16) {
        char authKey_hex [2 * MO_AUTHKEY_LEN_MAX + 1];
        authKey_hex[0] = '\0';
        for (size_t i = 0; i < authKeyLen; i++) {
            snprintf(authKey_hex + 2 * i, 3, "%02X", authKey[i]);
        }
        conn->setting_auth_key_hex_str->setString(authKey_hex);
        conn->configService->commit();
    }
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (conn->ocppVersion == MO_OCPP_V201) {
        char basicAuthPassword [MO_AUTHKEY_LEN_MAX + 1];
        snprintf(basicAuthPassword, sizeof(basicAuthPassword), "%.*s", (int)authKeyLen, authKey ? (const char*)authKey : "");
        conn->v201basicAuthPasswordString->setString(basicAuthPassword);
        conn->varService->commit();
    }
    #endif //MO_ENABLE_V201

    return true;
}

bool mo_setCaCert(MO_MG_Connection *connection, const char *CA_cert) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    conn->ca_cert = CA_cert; //updated ca_cert takes immediate effect
    return true;
}

void MOcppMongooseClient::reloadUrl() {

    reconnect(); //closes WS connection; will be reopened in next maintainWsConn execution

    /*
     * reload WS credentials from configs
     */

    #if MO_ENABLE_V16
    if (ocppVersion == MO_OCPP_V16) {
        backend_url = setting_backend_url_str->getString();
        cb_id = setting_cb_id_str->getString();

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
    #endif //MO_ENABLE_V16
    #if MO_ENABLE_V201
    if (ocppVersion == MO_OCPP_V201) {
        backend_url = v201csmsUrlString->getString();
        cb_id = v201identityString->getString();

        snprintf((char*)auth_key, sizeof(auth_key), "%s", v201basicAuthPasswordString->getString());
        auth_key_len = strlen((char*)auth_key);
    }
    #endif //MO_ENABLE_V201

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
        last_connection_established = clock->getUptimeInt();
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
    last_recv = clock->getUptimeInt();
}

void mo_reloadUrl(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    conn->reloadUrl();
}

const char *mo_getBackendUrl(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    return conn->backend_url.c_str();
}

const char *mo_getChargeBoxId(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    return conn->cb_id.c_str();
}

const char *mo_getAuthKey(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    return (const char*)conn->auth_key;
}

const char *mo_getCaCert(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    return conn->ca_cert ? conn->ca_cert : "";
}

bool mo_isConnected(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    return conn->isConnected();
}

int32_t mo_getLastRecv(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    return conn->last_recv;
}

int32_t mo_getLastConnected(MO_MG_Connection *connection) {
    auto conn = reinterpret_cast<MOcppMongooseClient*>(connection);
    return conn->last_connection_established;
}

#if MO_MG_USE_VERSION == MO_MG_V614

void MOcppMongooseClient::mongoose_cb(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {

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
                MO_DBG_WARN("connection error %d", status);
                MO_DBG_DEBUG("(connection %s)", osock->url.c_str());
                (void)0;
            }
            break;
        }
        case MG_EV_WEBSOCKET_HANDSHAKE_DONE: {
            struct http_message *hm = (struct http_message *) ev_data;
            if (hm->resp_code == 101) {
                MO_DBG_INFO("connection connected!");
                MO_DBG_DEBUG("(connection %s)", osock->url.c_str());
                osock->setConnectionOpen(true);
            } else {
                MO_DBG_WARN("HTTP error %d", hm->resp_code);
                MO_DBG_DEBUG("(connection %s)", osock->url.c_str());
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

            if (!osock->receiveTXT((const char *) wm->data, wm->size)) { //forward message to Context
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
            MO_DBG_INFO("connection closed");
            MO_DBG_DEBUG("(connection %s)", osock->url.c_str());
            osock->cleanConnection();
            break;
        }
    }
}

#else

#if MO_MG_USE_VERSION <= MO_MG_V708
void MOcppMongooseClient::mongoose_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
#else
void MOcppMongooseClient::mongoose_cb(struct mg_connection *c, int ev, void *ev_data) {
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
        if (mg_url_is_ssl(osock->url.c_str())) {
            const char *ca_string = osock->ca_cert;
            if (ca_string && *ca_string == '\0') { //check if certificate verification is disabled (cert string is empty)
                //yes, disabled
                ca_string = nullptr;
            }
            struct mg_tls_opts opts;
            memset(&opts, 0, sizeof(struct mg_tls_opts));
            #if MO_MG_USE_VERSION <= MO_MG_V708
            opts.ca = ca_string;
            opts.srvname = mg_url_host(osock->url.c_str());
            #else
            opts.ca = mg_str(ca_string);
            opts.name = mg_url_host(osock->url.c_str());
            #endif
            mg_tls_init(c, &opts);
        } else {
            MO_DBG_WARN("Insecure connection (WS)");
        }
    } else if (ev == MG_EV_WS_OPEN) {
        // WS connection established. Perform MQTT login
        MO_DBG_INFO("connected!");
        MO_DBG_DEBUG("(connection %s)", osock->url.c_str());
        osock->setConnectionOpen(true);
        osock->updateRcvTimer();
    } else if (ev == MG_EV_WS_MSG) {
        struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
#if MO_MG_USE_VERSION <= MO_MG_V713
        if (!osock->receiveTXT((const char*) wm->data.ptr, wm->data.len)) {
#else
        if (!osock->receiveTXT((const char*) wm->data.buf, wm->data.len)) {
#endif
            MO_DBG_WARN("processing input message failed");
        }
        osock->updateRcvTimer();
    } else if (ev == MG_EV_WS_CTL) {
        osock->updateRcvTimer();
    }

    if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE) {
        MO_DBG_INFO("connection %s", ev == MG_EV_CLOSE ? "closed" : "error");
        MO_DBG_DEBUG("(connection %s)", osock->url.c_str());
        osock->cleanConnection();
    }
}
#endif

bool MOcppMongooseClient::validateAuthorizationKeyHex(const char *auth_key_hex, void *userData) {
    (void)userData;

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
