// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2024
// GPL-3.0 License (see LICENSE)

#ifndef MO_MONGOOSECLIENT_H
#define MO_MONGOOSECLIENT_H

#include <string>
#include <memory>

#if defined(ARDUINO) //fix for conflicting definitions of IPAddress on Arduino
#include <Arduino.h>
#include <IPAddress.h>
#endif

#include "mongoose.h"

#include <MicroOcpp/Core/Connection.h>
#include <MicroOcpp/Context.h>
#include <MicroOcpp/Core/FilesystemAdapter.h>
#include <MicroOcpp/Version.h>

#ifndef MO_WSCONN_FN
#define MO_WSCONN_FN  "ws-conn.jsn"
#define MO_WSCONN_FN_V201 "ws-conn-v201.jsn"
#endif

#if MO_ENABLE_V201
#define MO_AUTHKEY_LEN_MAX 40 //BasicAuthPassword length
#else
#define MO_AUTHKEY_LEN_MAX 20 //AuthKey in Bytes. Hex value has double length
#endif


#ifdef __cplusplus
extern "C" {
#endif

struct MO_MG_Connection;
typedef struct MO_MG_Connection MO_MG_Connection;

//Configure MO with Mongoose WS client. Do this after `mo_initialize()` and before `mo_setup()`.
//Returns a handle for the Mongoose WS Client which can be passed to other API functions here. If
//the operation fails, returns NULL. Need to free resources after `mo_deinitialize()`.
MO_MG_Connection *mo_createMongooseWsClient(
        MO_Context *ctx, //pass return value of `mo_getApiContext()`
        MO_FilesystemAdapter *filesystem, //pass return value `mo_getFilesystem()`. May need to use `mo_setDefaultFilesystemConfig()` before
        struct mg_mgr *mgr, //Mongoose context. Must outlive MO. MO does not take ownership of `mgr`
        const char *backendUrlFactory,   //e.g. "wss://example.com:8443/steve/websocket/CentralSystemService". Can be NULL
        const char *chargeBoxIdFactory, //e.g. "charger001". Can be NULL
        const char *authKeyFactory, //authorizationKey (as string) present in the websocket message header. Can be NULL. Set this to enable OCPP Security Profile 2
        const char *CA_cert); //zero-copy, the string must outlive this class and mg_mgr. Forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)

//Alternative version with authKey as bytes array (thus, allowing the key to contain 0-bytes)
MO_MG_Connection *mo_createMongooseWsClient2(
        MO_Context *ctx, //pass return value of `mo_getApiContext()`
        MO_FilesystemAdapter *filesystem, //pass return value `mo_getFilesystem()`. May need to use `mo_setDefaultFilesystemConfig()` before
        struct mg_mgr *mgr, //Mongoose context. Must outlive MO. MO does not take ownership of `mgr`
        const char *backendUrlFactory,   //e.g. "wss://example.com:8443/steve/websocket/CentralSystemService". Can be NULL
        const char *chargeBoxIdFactory, //e.g. "charger001". Can be NULL
        const unsigned char *authKeyFactory, //authorizationKey (as bytes) present in the websocket message header. Can be NULL. Set this to enable OCPP Security Profile 2
        size_t authKeyFactoryLen, //length of `authKeyFactory` in bytes
        const char *CA_cert); //zero-copy, the string must outlive this class and mg_mgr. Forwards this string to Mongoose as ssl_ca_cert (see https://github.com/cesanta/mongoose/blob/ab650ec5c99ceb52bb9dc59e8e8ec92a2724932b/mongoose.h#L4192)

//Free allocated resources. Need to call this after `mo_deinitialize()`, or manually unset connection
//in Context object if freeing before
void mo_freeMongooseWsClient(MO_MG_Connection *connection);

//update WS configs. To apply the updates, call `mo_reloadUrl()` afterwards
bool mo_setBackendUrl(MO_MG_Connection *connection, const char *backendUrl);
bool mo_setChargeBoxId(MO_MG_Connection *connection, const char *chargeBoxId);
bool mo_setAuthKey(MO_MG_Connection *connection, const char *authKey); //set the auth key as c-string
bool mo_setAuthKey2(MO_MG_Connection *connection, const unsigned char *authKey, size_t authKeyLen); //set the auth key as bytes array
bool mo_setCaCert(MO_MG_Connection *connection, const char *CA_cert);

void mo_reloadUrl(MO_MG_Connection *connection);

const char *mo_getBackendUrl(MO_MG_Connection *connection);
const char *mo_getChargeBoxId(MO_MG_Connection *connection);
const char *mo_getAuthKey(MO_MG_Connection *connection);
const char *mo_getCaCert(MO_MG_Connection *connection);

bool mo_isConnected(MO_MG_Connection *connection);

int32_t mo_getLastRecv(MO_MG_Connection *connection); //get time of last successful receive in seconds since boot
int32_t mo_getLastConnected(MO_MG_Connection *connection); //get time of last connection establish in seconds since boot or -1 if never connected

#ifdef __cplusplus
}
#endif

#endif
