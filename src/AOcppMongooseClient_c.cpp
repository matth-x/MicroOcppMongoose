// matth-x/AOcppMongoose
// Copyright Matthias Akstaller 2019 - 2022
// GPL-3.0 License (see LICENSE)

#include "AOcppMongooseClient_c.h"
#include "AOcppMongooseClient.h"

#include <ArduinoOcpp/Core/FilesystemAdapter.h>
#include <ArduinoOcpp/Debug.h>

using namespace ArduinoOcpp;

AOcppSocketHandle *ao_makeOcppSocket(struct mg_mgr *mgr,
        const char *backend_url_default,
        const char *charge_box_id_default,
        const char *auth_key_default,
        const char *CA_cert_default,
        AO_FilesystemOpt fsopt) {
    
    auto filesystem = makeDefaultFilesystemAdapter(fsopt);

    auto sock = new AOcppMongooseClient(mgr,
            backend_url_default,
            charge_box_id_default,
            auth_key_default,
            CA_cert_default,
            filesystem);
    
    return reinterpret_cast<AOcppSocketHandle*>(sock);;
}

void ao_setBackendUrl(AOcppSocketHandle *sock, const char *backend_url) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setBackendUrl(backend_url);
}

void ao_setChargeBoxId(AOcppSocketHandle *sock, const char *cb_id) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setChargeBoxId(cb_id);
}

void ao_setAuthKey(AOcppSocketHandle *sock, const char *auth_key) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setAuthKey(auth_key);
}

void ao_setCaCert(AOcppSocketHandle *sock, const char *ca_cert) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->setCaCert(ca_cert);
}

void ao_reconnect(AOcppSocketHandle *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    mgsock->reconnect();
}

const char *ao_getBackendUrl(AOcppSocketHandle *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getBackendUrl();
}

const char *ao_getChargeBoxId(AOcppSocketHandle *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getChargeBoxId();
}

const char *ao_getAuthKey(AOcppSocketHandle *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getAuthKey();
}

const char *ao_getCaCert(AOcppSocketHandle *sock) {
    if (!sock) {
        AO_DBG_ERR("invalid argument");
        return nullptr;
    }
    auto mgsock = reinterpret_cast<AOcppMongooseClient*>(sock);
    return mgsock->getCaCert();
}
