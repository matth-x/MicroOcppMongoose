// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2024
// GPL-3.0 License (see LICENSE)

#ifndef MO_MONGOOSECLIENT_C_H
#define MO_MONGOOSECLIENT_C_H

#if defined(__cplusplus) && defined(ARDUINO) //fix for conflicting defitions of IPAddress on Arduino
#include <Arduino.h>
#include <IPAddress.h>
#endif

#include "mongoose.h"
#include <MicroOcpp/Core/ConfigurationOptions.h>

#ifdef __cplusplus
extern "C" {
#endif

struct OCPP_Connection;
typedef struct OCPP_Connection OCPP_Connection;

OCPP_Connection *ocpp_makeConnection(struct mg_mgr *mgr,
        const char *backend_url_default,   //all cstrings can be NULL
        const char *charge_box_id_default,
        const char *auth_key_default,
        const char *CA_cert_default,
        struct OCPP_FilesystemOpt fsopt);

void ocpp_deinitConnection(OCPP_Connection *sock);

//update WS configs. To apply the updates, call `ocpp_reloadConfigs()` afterwards
void ocpp_setBackendUrl(OCPP_Connection *sock, const char *backend_url);
void ocpp_setChargeBoxId(OCPP_Connection *sock, const char *cb_id);
void ocpp_setAuthKey(OCPP_Connection *sock, const char *auth_key);
void ocpp_setCaCert(OCPP_Connection *sock, const char *ca_cert);

void ocpp_reloadConfigs(OCPP_Connection *sock);

const char *ocpp_getBackendUrl(OCPP_Connection *sock);
const char *ocpp_getChargeBoxId(OCPP_Connection *sock);
const char *ocpp_getAuthKey(OCPP_Connection *sock);
const char *ocpp_getCaCert(OCPP_Connection *sock);

bool ocpp_isConnectionOpen(OCPP_Connection *sock);

#ifdef __cplusplus
}
#endif

#endif
