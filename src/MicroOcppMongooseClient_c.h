// matth-x/ArduinoOcppMongoose
// Copyright Matthias Akstaller 2019 - 2023
// GPL-3.0 License (see LICENSE)

#ifndef AOCPPMONGOOSECLIENT_C_H
#define AOCPPMONGOOSECLIENT_C_H

#if defined(__cplusplus) && defined(ARDUINO) //fix for conflicting defitions of IPAddress on Arduino
#include <Arduino.h>
#include <IPAddress.h>
#endif

#include "mongoose.h"
#include <ArduinoOcpp/Core/ConfigurationOptions.h>

#ifdef __cplusplus
extern "C" {
#endif

struct AO_Connection;
typedef struct AO_Connection AO_Connection;

AO_Connection *ao_makeConnection(struct mg_mgr *mgr,
        const char *backend_url_default,   //all cstrings can be NULL
        const char *charge_box_id_default,
        const char *auth_key_default,
        const char *CA_cert_default,
        struct AO_FilesystemOpt fsopt);

void ao_deinitConnection(AO_Connection *sock);

void ao_setBackendUrl(AO_Connection *sock, const char *backend_url);
void ao_setChargeBoxId(AO_Connection *sock, const char *cb_id);
void ao_setAuthKey(AO_Connection *sock, const char *auth_key);
void ao_setCaCert(AO_Connection *sock, const char *ca_cert);

void ao_reconnect(AO_Connection *sock); //after updating all credentials, reconnect to apply them

const char *ao_getBackendUrl(AO_Connection *sock);
const char *ao_getChargeBoxId(AO_Connection *sock);
const char *ao_getAuthKey(AO_Connection *sock);
const char *ao_getCaCert(AO_Connection *sock);

bool ao_isConnectionOpen(AO_Connection *sock);

#ifdef __cplusplus
}
#endif

#endif
