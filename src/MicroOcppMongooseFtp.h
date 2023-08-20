// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2023
// GPL-3.0 License (see LICENSE)

#ifndef MOCPP_MONGOOSEFTPCLIENT_H
#define MOCPP_MONGOOSEFTPCLIENT_H

#if defined(ARDUINO) //fix for conflicting defitions of IPAddress on Arduino
#include <Arduino.h>
#include <IPAddress.h>
#endif

#include "mongoose.h"

#include <string>
#include <memory>
#include <functional>

namespace MicroOcpp {

class MongooseFtpClient {
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

    bool readUrl(const char *ftp_url);

    std::function<size_t(unsigned char *data, size_t len)> fileWriter;
    std::function<size_t(unsigned char *out, size_t bufsize)> fileReader;
    std::function<void()> onClose;

    bool ctrl_opened = false;
    bool ctrl_closed = false;
    unsigned long ctrl_last_recv = 0;

    enum class Method {
        Retrieve,  //download file
        Append,    //upload file
        UNDEFINED
    };
    Method method = Method::UNDEFINED;

    bool data_conn_accepted = false;

    MongooseFtpClient(struct mg_mgr *mgr);
    ~MongooseFtpClient();

    bool getFile(const char *ftp_url, // ftp://[user[:pass]@]host[:port][/directory]/filename
            std::function<size_t(unsigned char *data, size_t len)> fileWriter,
            std::function<void()> onClose);
    
    //append file
    bool postFile(const char *ftp_url, // ftp://[user[:pass]@]host[:port][/directory]/filename
            std::function<size_t(unsigned char *out, size_t buffsize)> fileReader, //write at most buffsize bytes into out-buffer. Return number of bytes written
            std::function<void()> onClose);
};

} //end namespace MicroOcpp

#endif
