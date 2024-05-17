// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2024
// GPL-3.0 License (see LICENSE)

#include "MicroOcppMongooseClient_c.h"
#include "MicroOcppMongooseClient.h"

#include <MicroOcpp/Core/FilesystemAdapter.h>
#include <MicroOcpp/Debug.h>

using namespace MicroOcpp;

OCPP_Connection *ocpp_makeConnection(struct mg_mgr *mgr,
        const char *backend_url_default,
        const char *charge_box_id_default,
        const char *auth_key_default,
        const char *CA_cert_default,
        OCPP_FilesystemOpt fsopt) {
    
    std::shared_ptr<MicroOcpp::FilesystemAdapter> filesystem;
    
#ifndef MO_DEACTIVATE_FLASH
    filesystem = makeDefaultFilesystemAdapter(fsopt);
#endif

    auto sock = new MOcppMongooseClient(mgr,
            backend_url_default,
            charge_box_id_default,
            auth_key_default,
            CA_cert_default,
            filesystem);
    
    return reinterpret_cast<OCPP_Connection*>(sock);;
}

void ocpp_deinitConnection(OCPP_Connection *sock) {
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    delete mgsock;
}

void ocpp_setBackendUrl(OCPP_Connection *sock, const char *backend_url) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    mgsock->setBackendUrl(backend_url);
}

void ocpp_setChargeBoxId(OCPP_Connection *sock, const char *cb_id) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    mgsock->setChargeBoxId(cb_id);
}

void ocpp_setAuthKey(OCPP_Connection *sock, const char *auth_key) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    mgsock->setAuthKey(auth_key);
}

void ocpp_setCaCert(OCPP_Connection *sock, const char *ca_cert) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    mgsock->setCaCert(ca_cert);
}

void ocpp_reloadConfigs(OCPP_Connection *sock) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    mgsock->reloadConfigs();
}

const char *ocpp_getBackendUrl(OCPP_Connection *sock) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    return mgsock->getBackendUrl();
}

const char *ocpp_getChargeBoxId(OCPP_Connection *sock) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    return mgsock->getChargeBoxId();
}

const char *ocpp_getAuthKey(OCPP_Connection *sock) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    return mgsock->getAuthKey();
}

const char *ocpp_getCaCert(OCPP_Connection *sock) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    return mgsock->getCaCert();
}

bool ocpp_isConnectionOpen(OCPP_Connection *sock) {
    if (!sock) {
        MO_DBG_ERR("invalid argument");
        return false;
    }
    auto mgsock = reinterpret_cast<MOcppMongooseClient*>(sock);
    return mgsock->isConnectionOpen();
}
