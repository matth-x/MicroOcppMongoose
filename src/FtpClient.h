// matth-x/ArduinoOcppMongoose
// Copyright Matthias Akstaller 2019 - 2023
// GPL-3.0 License (see LICENSE)

#ifndef AO_FTPCLIENT_H
#define AO_FTPCLIENT_H

#if defined(ARDUINO) //fix for conflicting defitions of IPAddress on Arduino
#include <Arduino.h>
#include <IPAddress.h>
#endif

#include "mongoose.h"

#include <string>
#include <memory>
#include <functional>

namespace ArduinoOcpp {

class FtpClient {
public:
    struct mg_mgr *mgr {nullptr};
    struct mg_connection *ctrl_conn {nullptr};
    struct mg_connection *data_conn {nullptr};
    std::string file_location;
    std::string url;
    std::string user;
    std::string pass;
    std::string dir;
    std::string fname;

    std::string data_url;

    std::function<bool(const char *data, size_t len)> onReceiveChunk;
    std::function<void()> onClose;

    bool ctrl_opened = false;
    bool ctrl_closed = false;
    unsigned long ctrl_last_recv = 0;

    FtpClient(struct mg_mgr *mgr);
    ~FtpClient();

    bool getFile(const char *ftp_url, // ftp://[user[:pass]@]host:port/directory/filename)
            std::function<bool(const char *data, size_t len)> onReceiveChunk,
            std::function<void()> onClose);
};

} //end namespace ArduinoOcpp

#endif
