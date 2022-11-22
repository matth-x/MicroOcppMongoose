// matth-x/AOcppMongoose
// Copyright Matthias Akstaller 2019 - 2022
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

struct AOcppSocketHandle;
typedef struct AOcppSocketHandle AOcppSocketHandle;

AOcppSocketHandle *ao_makeOcppSocket(struct mg_mgr *mgr,
        const char *backend_url_default,   //all cstrings can be NULL
        const char *charge_box_id_default,
        const char *auth_key_default,
        const char *CA_cert_default, //if AO_CA_CERT_USE_FILE, then pass the filename, otherwise the plain-text CA_cert
        AO_FilesystemOpt fsopt);

void ao_setBackendUrl(AOcppSocketHandle *sock, const char *backend_url);
void ao_setChargeBoxId(AOcppSocketHandle *sock, const char *cb_id);
void ao_setAuthKey(AOcppSocketHandle *sock, const char *auth_key);
void ao_setCaCert(AOcppSocketHandle *sock, const char *ca_cert); //if AO_CA_CERT_USE_FILE, then pass the filename, otherwise the plain-text CA_cert

void ao_reconnect(AOcppSocketHandle *sock); //after updating all credentials, reconnect to apply them

const char *ao_getBackendUrl(AOcppSocketHandle *sock);
const char *ao_getChargeBoxId(AOcppSocketHandle *sock);
const char *ao_getAuthKey(AOcppSocketHandle *sock);
const char *ao_getCaCert(AOcppSocketHandle *sock);

#ifdef __cplusplus
}
#endif

#endif
