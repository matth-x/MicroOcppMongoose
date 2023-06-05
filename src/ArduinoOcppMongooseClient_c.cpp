// matth-x/ArduinoOcppMongoose
// Copyright Matthias Akstaller 2019 - 2023
// GPL-3.0 License (see LICENSE)

#include "ArduinoOcppMongooseClient_c.h"
#include "ArduinoOcppMongooseClient.h"

#include <ArduinoOcpp/Core/FilesystemAdapter.h>
#include <ArduinoOcpp/Debug.h>

using namespace ArduinoOcpp;

AO_Connection *ao_makeConnection(struct mg_mgr *mgr,
        const char *backend_url_default,
        const char *charge_box_id_default,
        const char *auth_key_default,
        const char *CA_cert_default,
        AO_FilesystemOpt fsopt) {
    
    std::shared_ptr<ArduinoOcpp::FilesystemAdapter> filesystem;
    
#ifndef AO_DEACTIVATE_FLASH
    filesystem = makeDefaultFilesystemAdapter(fsopt);
#endif

    auto sock = new AOcppMongooseClient(mgr,
            backend_url_default,
            charge_box_id_default,
            auth_key_default,
            CA_cert_default,
            filesystem);
    
    return reinterpret_cast<AO_Connection*>(sock);;
}

void ao_deinitConnection(AO_Connection *sock) {
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    delete mgsock;
}

void ao_setBackendUrl(AO_Connection *sock, const char *backend_url) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setBackendUrl(backend_url);
}

void ao_setChargeBoxId(AO_Connection *sock, const char *cb_id) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setChargeBoxId(cb_id);
}

void ao_setAuthKey(AO_Connection *sock, const char *auth_key) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setAuthKey(auth_key);
}

void ao_setCaCert(AO_Connection *sock, const char *ca_cert) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setCaCert(ca_cert);
}

void ao_reconnect(AO_Connection *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->reconnect();
}

const char *ao_getBackendUrl(AO_Connection *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getBackendUrl();
}

const char *ao_getChargeBoxId(AO_Connection *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getChargeBoxId();
}

const char *ao_getAuthKey(AO_Connection *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getAuthKey();
}

const char *ao_getCaCert(AO_Connection *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getCaCert();
}

bool ao_isConnectionOpen(AO_Connection *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return false;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->isConnectionOpen();
}
