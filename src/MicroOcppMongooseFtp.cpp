// matth-x/MicroOcppMongoose
// Copyright Matthias Akstaller 2019 - 2023
// GPL-3.0 License (see LICENSE)

#include "MicroOcppMongooseFtp.h"
#include <MicroOcpp/Debug.h>
#include <MicroOcpp/Platform.h>

using namespace MicroOcpp;

void ftp_ctrl_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data);
void ftp_data_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data);

#define MG_COMPAT_NOSSL   0
#define MG_COMPAT_OPENSSL 1
#define MG_COMPAT_MBEDTLS 2

#if defined(MO_MG_VERSION_614)
void mg_compat_drain_conn(mg_connection *c) {
    c->flags |= MG_F_SEND_AND_CLOSE;
}

void mg_compat_iobuf_resize(struct mbuf *buf, size_t new_size) {
    mbuf_resize(buf, new_size);
};

//TLS lib internals not exposed in MG v6.14 interface. Cast them to copies of their definition (see mongoose.c)
#if MG_SSL_IF == MG_SSL_IF_OPENSSL
#define MG_COMPAT_TLS MG_COMPAT_OPENSSL
#include <openssl/ssl.h>
extern "C" struct MG_TLS_INTERNAL {
  SSL *ssl;
  SSL_CTX *ssl_ctx;
  struct mbuf psk;
  size_t identity_len;
};
SSL *mg_compat_get_tls(struct mg_connection *c) {
    return (SSL*) ((struct MG_TLS_INTERNAL*)c->ssl_if_data)->ssl;
}
#elif MG_SSL_IF == MG_SSL_IF_MBEDTLS
#define MG_COMPAT_TLS MG_COMPAT_MBEDTLS
#include <mbedtls/ssl.h>
extern "C" struct MG_TLS_INTERNAL {
  mbedtls_ssl_config *conf;
  mbedtls_ssl_context *ssl;
  mbedtls_x509_crt *cert;
  mbedtls_pk_context *key;
  mbedtls_x509_crt *ca_cert;
  struct mbuf cipher_suites;
  size_t saved_len;
};
mbedtls_ssl_context *mg_compat_get_tls(struct mg_connection *c) {
    return (mbedtls_ssl_context*) ((struct MG_TLS_INTERNAL*)c->ssl_if_data)->ssl;
}
#endif

#define MG_COMPAT_EV_READ MG_EV_RECV
#define MG_COMPAT_RECV recv_mbuf
#define MG_COMPAT_SEND send_mbuf
#define MG_COMPAT_FN_DATA user_data
#define MG_COMPAT_IS_TLS(c) ((c->flags & MG_F_SSL) == MG_F_SSL)
#define MG_COMPAT_EV_TLS_HS 100500 //event number not used by MG

#ifdef MO_FTP_OVERRIDE_CIPHERSUITES
#define MO_FTP_USE_CIPHERSUITES \
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:" \
    "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384:" \
    "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:" \
    "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256:" \
    "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256:" \
    "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256:" \
    "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:" \
    "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256:" \
    "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256:" \
    "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256:" \
    "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA:" \
    "TLS-ECDH-RSA-WITH-AES-128-GCM-SHA256:" \
    "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA256:" \
    "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA:" \
    "TLS-RSA-WITH-AES-128-GCM-SHA256:" \
    "TLS-RSA-WITH-AES-128-CBC-SHA256:" \
    "TLS-RSA-WITH-AES-128-CBC-SHA"
#else
#define MO_FTP_USE_CIPHERSUITES nullptr
#endif
#else
void mg_compat_drain_conn(mg_connection *c) {
    c->is_draining = 1;
}

void mg_compat_iobuf_resize(struct mg_iobuf *buf, size_t new_size) {
    mg_iobuf_resize(buf, new_size);
};

#if MG_ENABLE_OPENSSL
#define MG_COMPAT_TLS MG_COMPAT_OPENSSL
SSL *mg_compat_get_tls(struct mg_connection *c) {
    return (SSL*) ((struct mg_tls*)c->tls)->ssl;
}
#elif MG_ENABLE_MBEDTLS
#define MG_COMPAT_TLS MG_COMPAT_MBEDTLS
mbedtls_ssl_context *mg_compat_get_tls(struct mg_connection *c) {
    return (mbedtls_ssl_context*) &((struct mg_tls*)c->tls)->ssl;
}
#endif

#define MG_COMPAT_EV_READ MG_EV_READ
#define MG_COMPAT_RECV recv
#define MG_COMPAT_SEND send
#define MG_COMPAT_FN_DATA fn_data
#define MG_COMPAT_IS_TLS(c) (c->tls != nullptr)
#define MG_COMPAT_EV_TLS_HS MG_EV_TLS_HS
#endif

#ifndef MG_COMPAT_TLS
#define MG_COMPAT_TLS MG_COMPAT_NOSSL
#endif

MongooseFtpClient::MongooseFtpClient(struct mg_mgr *mgr) : mgr(mgr) {
    
}

MongooseFtpClient::~MongooseFtpClient() {
    if (data_conn) {
        data_conn->MG_COMPAT_FN_DATA = nullptr;
        mg_compat_drain_conn(data_conn);
        data_conn = nullptr;
    }

    if (ctrl_conn) {
        ctrl_conn->MG_COMPAT_FN_DATA = nullptr;
        mg_compat_drain_conn(ctrl_conn);
        ctrl_conn = nullptr;
    }

    if (onClose) {
        onClose();
        onClose = nullptr;
    }
}

int MongooseFtpClient::upgradeTls(struct mg_connection *conn) {
    #if defined(MO_MG_VERSION_614)
    const char *err_msg = nullptr;
    struct mg_ssl_if_conn_params params;
    memset(&params, 0, sizeof(params));
    params.ca_cert = "*"; //TODO cert
    params.cipher_suites = MO_FTP_USE_CIPHERSUITES;
    auto ret = mg_ssl_if_conn_init(conn,
        &params,
        &err_msg);
    MO_DBG_DEBUG("ssl init: %i %s", ret, err_msg ? err_msg : "");
    return ret;
    #else
    struct mg_tls_opts opts;
    memset(&opts, 0, sizeof(opts));
    //opts.ca = CERT; //TODO
    mg_tls_init(conn, &opts);
    return 0;
    #endif
}

int MongooseFtpClient::upgradeTlsCtrlConn() {
    if (!ctrl_conn) {
        MO_DBG_ERR("internal error");
        return -1;
    }

    return upgradeTls(ctrl_conn);
}

int MongooseFtpClient::upgradeTlsDataConn() {
    if (!ctrl_conn || !data_conn || !mg_compat_get_tls(ctrl_conn)) {
        MO_DBG_ERR("internal error");
        return -1;
    }

    int err;

    #if defined(MO_MG_VERSION_614)
    err = upgradeTls(data_conn);
    #else
    int save_is_connecting = data_conn->is_connecting;
    data_conn->is_connecting = 1; //do not perform tls_handshake during mg_tls_init
    err = upgradeTls(data_conn);
    data_conn->is_connecting = save_is_connecting;
    #endif

    if (err != 0) {
        MO_DBG_ERR("TLS error: %i", err);
        return err;
    }

    if (!mg_compat_get_tls(data_conn)) {
        MO_DBG_ERR("internal error");
        return -1;
    }

    //reuse ctrl conn session for data conn
    #if MG_COMPAT_TLS == MG_COMPAT_OPENSSL
    return SSL_set_session(
        mg_compat_get_tls(data_conn),
        SSL_get_session(mg_compat_get_tls(ctrl_conn)));
    #elif MG_COMPAT_TLS == MG_COMPAT_MBEDTLS
    return mbedtls_ssl_set_session(
        mg_compat_get_tls(data_conn),
        mbedtls_ssl_get_session_pointer(mg_compat_get_tls(ctrl_conn)));
    #endif
}

void MongooseFtpClient::loop() {
    #if defined(MO_MG_VERSION_614)
    //upgrade TLS in FtpClient::loop instead of mg_poll (MG flags cannot be manipulated during mg_poll in v6.14)
    if (ctrl_tls_want_upgrade) {
        ctrl_tls_want_upgrade = false;
        auto ret = upgradeTlsCtrlConn();
        if (ret != 0) {
            MO_DBG_ERR("TLS error: %i", ret);
            return;
        }
    } else if (data_tls_want_upgrade) {
        data_tls_want_upgrade = false;
        auto ret = upgradeTlsDataConn();
        if (ret != 0) {
            MO_DBG_ERR("TLS error: %i", ret);
            return;
        }

        //re-enter data cb to continue FTP sequence
        int ev_data = 0;
        ftp_data_cb(data_conn, MG_EV_CONNECT, &ev_data, (void*)this);
    }
    #endif
}

bool MongooseFtpClient::getFile(const char *ftp_url_raw, std::function<size_t(unsigned char *data, size_t len)> fileWriter, std::function<void()> onClose) {
    
    MO_DBG_WARN("FTP download experimental. Please test, evaluate and report the results on GitHub");
    
    if (!ftp_url_raw || !fileWriter) {
        MO_DBG_ERR("invalid args");
        return false;
    }

    MO_DBG_DEBUG("init download %s", ftp_url_raw);

    if (!readUrl(ftp_url_raw)) {
        return false;
    }

    if (ctrl_conn) {
        MO_DBG_WARN("close dangling ctrl channel");
        ctrl_conn->MG_COMPAT_FN_DATA = nullptr;
        mg_compat_drain_conn(ctrl_conn);
        ctrl_conn = nullptr;
    }

    ctrl_conn = mg_connect(mgr, url.c_str(), ftp_ctrl_cb, this);

    if (!ctrl_conn) {
        return false;
    }

    this->method = Method::Retrieve;
    this->fileWriter = fileWriter;
    this->onClose = onClose;

    return true;
}

bool MongooseFtpClient::postFile(const char *ftp_url_raw, std::function<size_t(unsigned char *out, size_t buffsize)> fileReader, std::function<void()> onClose) {
    
    MO_DBG_WARN("FTP upload experimental. Please test, evaluate and report the results on GitHub");
    
    if (!ftp_url_raw || !fileReader) {
        MO_DBG_ERR("invalid args");
        return false;
    }

    MO_DBG_DEBUG("init upload %s", ftp_url_raw);

    if (!readUrl(ftp_url_raw)) {
        return false;
    }

    if (ctrl_conn) {
        MO_DBG_WARN("close dangling ctrl channel");
        ctrl_conn->MG_COMPAT_FN_DATA = nullptr;
        mg_compat_drain_conn(ctrl_conn);
        ctrl_conn = nullptr;
    }

    ctrl_conn = mg_connect(mgr, url.c_str(), ftp_ctrl_cb, this);

    if (!ctrl_conn) {
        return false;
    }

    this->method = Method::Append;
    this->fileReader = fileReader;
    this->onClose = onClose;

    return true;
}

void ftp_ctrl_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev != MG_EV_POLL) {
        MO_DBG_DEBUG("Cb fn with event: %d\n", ev);
        (void)0;
    }

#if defined(MO_MG_VERSION_614)
    if (ev == MG_EV_CONNECT && *(int *) ev_data != 0) {
        MO_DBG_WARN("connection error %d", *(int *) ev_data);
        return;
    }
#else
    if (ev == MG_EV_ERROR) {
        MG_ERROR(("%p %s", c->fd, (char *) ev_data));
        MO_DBG_WARN("connection error");
        return;
    }
#endif

    if (!fn_data) {
        if (ev == MG_EV_CLOSE) {
            MO_DBG_DEBUG("connection closed");
            (void)0;
        } else {
            MO_DBG_ERR("invalid state %d", ev);
            mg_compat_drain_conn(c);
        }
        return;
    }

    //patch MG_COMPAT_EV_TLS_HS in MG v6.14
    #if defined(MO_MG_VERSION_614)
    if (ev == MG_EV_CONNECT && 
            MG_COMPAT_IS_TLS(c) &&
            ((c->flags & MG_F_SSL_HANDSHAKE_DONE) == MG_F_SSL_HANDSHAKE_DONE)) {
        ev = MG_COMPAT_EV_TLS_HS;
    }
    #endif

    MongooseFtpClient& session = *reinterpret_cast<MongooseFtpClient*>(fn_data);

    if (ev == MG_EV_CONNECT) {
        MO_DBG_DEBUG("connection %s -- connected!", session.url.c_str());
        session.ctrl_opened = true;
    } else if (ev == MG_EV_CLOSE) {
        MO_DBG_DEBUG("connection %s -- closed", session.url.c_str());
        session.ctrl_closed = true;
        if (session.onClose) {
            session.onClose();
            session.onClose = nullptr;
        }
        session.ctrl_conn = nullptr;
    } else if (ev == MG_COMPAT_EV_READ || ev == MG_COMPAT_EV_TLS_HS) {
        // read multi-line command
        char *line_next = (char*) c->MG_COMPAT_RECV.buf;
        while (line_next < (char*) c->MG_COMPAT_RECV.buf + c->MG_COMPAT_RECV.len) {

            // take current line
            char *line = line_next;

            // null-terminate current line and find begin of next line
            while (line_next + 1 < (char*)c->MG_COMPAT_RECV.buf + c->MG_COMPAT_RECV.len && *line_next != '\n') {
                line_next++;
            }
            *line_next = '\0';
            line_next++;

            MO_DBG_DEBUG("RECV: %s", line);

            if (!session.proto.compare("ftps://") && !MG_COMPAT_IS_TLS(c)) { //tls not initialized yet
                if (!strncmp("220", line, 3)) {
                    MO_DBG_VERBOSE("start AUTH TLS");
                    mg_printf(c, "AUTH TLS\r\n");
                    break;
                } else if (!strncmp("234", line, 3)) { // Proceed with TLS negotiation
                    MO_DBG_VERBOSE("upgrade to TLS");

                    #if defined(MO_MG_VERSION_614)
                    session.ctrl_tls_want_upgrade = true; //triggers TLS upgrade in FtpClient::loop() function (this "indirection" is needed for backwards compatibility with MG v6.14)
                    #else
                    session.upgradeTlsCtrlConn();
                    #endif

                    //keep msg in read buffer so that next poll will execute this state machine (enter case `ev == MG_COMPAT_EV_TLS_HS`)
                    return;
                } else {
                    MO_DBG_WARN("TLS negotiation failure: %s", line);
                    if (session.data_conn) {
                        mg_compat_drain_conn(session.data_conn);
                    }
                    mg_printf(c, "QUIT\r\n");
                    mg_compat_drain_conn(c);
                    break;
                }
            } else if (!strncmp("530", line, 3)     // Not logged in
                    || !strncmp("220", line, 3)     // Service ready for new user
                    || ev == MG_COMPAT_EV_TLS_HS) { // Just completed AUTH TLS handshake
                MO_DBG_DEBUG("select user %s", session.user.empty() ? "anonymous" : session.user.c_str());
                mg_printf(c, "USER %s\r\n", session.user.empty() ? "anonymous" : session.user.c_str());
                break;
            } else if (!strncmp("331", line, 3)) { // User name okay, need password
                MO_DBG_DEBUG("enter pass %.2s***", session.pass.empty() ? "-" : session.pass.c_str());
                mg_printf(c, "PASS %s\r\n", session.pass.c_str());
                break;
            } else if (!strncmp("230", line, 3)) { // User logged in, proceed
                MO_DBG_VERBOSE("select directory %s", session.dir.empty() ? "/" : session.dir.c_str());
                mg_printf(c, "CWD %s\r\n", session.dir.empty() ? "/" : session.dir.c_str());
                break;
            } else if (!strncmp("250", line, 3)) { // Requested file action okay, completed
                MO_DBG_VERBOSE("enter passive mode");
                mg_printf(c, "PBSZ 0\r\n");
                mg_printf(c, "PROT P\r\n");
                mg_printf(c, "PASV\r\n");
                break;
            } else if (!strncmp("227", line, 3)) { // Entering Passive Mode (h1,h2,h3,h4,p1,p2)

                // parse address field. Replace all non-digits by delimiter character ' '
                for (size_t i = 3; line + i < line_next; i++) {
                    if (line[i] < '0' || line[i] > '9') {
                        line[i] = (unsigned char) ' ';
                    }
                }

                unsigned int h1 = 0, h2 = 0, h3 = 0, h4 = 0, p1 = 0, p2 = 0;

                auto ret = sscanf((const char *)c->MG_COMPAT_RECV.buf + 3, "%u %u %u %u %u %u", &h1, &h2, &h3, &h4, &p1, &p2);
                if (ret == 6) {
                    unsigned int port = 256U * p1 + p2;

                    char url [64] = {'\0'};
                    auto ret = snprintf(url, 64, "tcp://%u.%u.%u.%u:%u", h1, h2, h3, h4, port);
                    if (ret < 0 || ret >= 64) {
                        MO_DBG_ERR("url format failure");
                        mg_printf(c, "QUIT\r\n");
                        mg_compat_drain_conn(c);
                        break;
                    }
                    MO_DBG_DEBUG("FTP upload address: %s", url);
                    session.data_url = url;

                    if (session.data_conn) {
                        MO_DBG_WARN("close dangling data channel");
                        session.data_conn->MG_COMPAT_FN_DATA = nullptr;
                        mg_compat_drain_conn(session.data_conn);
                        session.data_conn_accepted = false;
                        session.data_conn = nullptr;
                    }

                    session.data_conn = mg_connect(c->mgr, url, ftp_data_cb, &session);

                    if (!session.data_conn) {
                        MO_DBG_ERR("cannot open data ch");
                        mg_printf(c, "QUIT\r\n");
                        mg_compat_drain_conn(c);
                        break;
                    }

                    //success -> wait for data_conn to establish connection, ftp_data_cb will send next command
                } else {
                    MO_DBG_ERR("could not process ftp data address");
                    mg_printf(c, "QUIT\r\n");
                    mg_compat_drain_conn(c);
                    break;
                }

            } else if (!strncmp("150", line, 3)) { // File status okay; about to open data connection
                MO_DBG_DEBUG("data connection accepted");
                session.data_conn_accepted = true;
                (void)0;
            } else if (!strncmp("226", line, 3)) { // Closing data connection. Requested file action successful (for example, file transfer or file abort)
                MO_DBG_INFO("FTP success: %s", line);
                if (session.data_conn) {
                    mg_compat_drain_conn(session.data_conn);
                }
                mg_printf(c, "QUIT\r\n");
                mg_compat_drain_conn(c);
                break;
            } else if (!strncmp("55", line, 2)) { // Requested action not taken / aborted
                MO_DBG_WARN("FTP failure: %s", line);
                if (session.data_conn) {
                    mg_compat_drain_conn(session.data_conn);
                }
                mg_printf(c, "QUIT\r\n");
                mg_compat_drain_conn(c);
                break;
            } else if (!strncmp("200", line, 3)) { //PBSZ -> 0 and PROT -> P accepted
                MO_DBG_INFO("PBSZ/PROT success: %s", line);
            } else {
                MO_DBG_WARN("unkown commad (closing connection): %s", line);
                if (session.data_conn) {
                    mg_compat_drain_conn(session.data_conn);
                }
                mg_printf(c, "QUIT\r\n");
                mg_compat_drain_conn(c);
                break;
            }

            size_t consumed = line_next - line;

            if (consumed > c->MG_COMPAT_RECV.len) {
                MO_DBG_ERR("invalid state");
                break;
            }

            c->MG_COMPAT_RECV.len -= consumed;
        }
        c->MG_COMPAT_RECV.len = 0;
    }
}

void ftp_data_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev != MG_EV_POLL) {
        MO_DBG_DEBUG("Cb fn with event: %d\n", ev);
        (void)0;
    }

#if defined(MO_MG_VERSION_614)
    if (ev == MG_EV_CONNECT && *(int *) ev_data != 0) {
        MO_DBG_WARN("connection error %d", *(int *) ev_data);
        return;
    }
#else
    if (ev == MG_EV_ERROR) {
        MG_ERROR(("%p %s", c->fd, (char *) ev_data));
        MO_DBG_WARN("connection error");
        return;
    }
#endif

    if (!fn_data) {
        if (ev == MG_EV_CLOSE) {
            MO_DBG_INFO("connection closed");
            (void)0;
        } else {
            MO_DBG_ERR("invalid state %d", ev);
            mg_compat_drain_conn(c);
        }
        return;
    }

    //patch MG_COMPAT_EV_TLS_HS in MG v6.14
    #if defined(MO_MG_VERSION_614)
    if (ev == MG_EV_CONNECT && 
            MG_COMPAT_IS_TLS(c) &&
            ((c->flags & MG_F_SSL_HANDSHAKE_DONE) == MG_F_SSL_HANDSHAKE_DONE)) {
        ev = MG_COMPAT_EV_TLS_HS;
    }
    #endif

    MongooseFtpClient& session = *reinterpret_cast<MongooseFtpClient*>(fn_data);

    if (ev == MG_EV_CONNECT) {
        
        if (!session.proto.compare("ftps://") && !MG_COMPAT_IS_TLS(c)){ //tls not initialized yet
            MO_DBG_VERBOSE("upgrade to TLS");

            #if defined(MO_MG_VERSION_614)
            session.data_tls_want_upgrade = true; //triggers TLS upgrade in FtpClient::loop() function (this "indirection" is needed for backwards compatibility with MG v6.14)
            return; //FtpClient::loop() function will re-enter this cb with event MG_EV_CONNECT
            #else
            session.upgradeTlsDataConn();
            #endif
        }

        MO_DBG_DEBUG("connection %s -- connected!", session.data_url.c_str());
        if (session.method == MongooseFtpClient::Method::Retrieve) {
            MO_DBG_DEBUG("get file %s", session.fname.c_str());
            mg_printf(session.ctrl_conn, "RETR %s\r\n", session.fname.c_str());
        } else if (session.method == MongooseFtpClient::Method::Append) {
            MO_DBG_DEBUG("post file %s", session.fname.c_str());
            mg_printf(session.ctrl_conn, "APPE %s\r\n", session.fname.c_str());
        } else {
            MO_DBG_ERR("unsupported method");
            mg_printf(session.ctrl_conn, "QUIT\r\n");
        }
    } else if (ev == MG_EV_CLOSE) {
        MO_DBG_DEBUG("connection %s -- closed", session.data_url.c_str());
        session.data_conn_accepted = false;
        session.data_conn = nullptr;
    } else if (ev == MG_COMPAT_EV_READ) {
        MO_DBG_DEBUG("read");
        //receive payload
        if (session.method == MongooseFtpClient::Method::Retrieve) {

            if (!session.fileWriter) {
                MO_DBG_ERR("invalid state");
                c->MG_COMPAT_RECV.len = 0;
                mg_printf(session.ctrl_conn, "QUIT\r\n");
                mg_compat_drain_conn(c);
                return;
            }

            auto ret = session.fileWriter((unsigned char*)c->MG_COMPAT_RECV.buf, c->MG_COMPAT_RECV.len);

            if (ret <= c->MG_COMPAT_RECV.len) {
                c->MG_COMPAT_RECV.len -= ret;
            } else {
                MO_DBG_ERR("write error");
                c->MG_COMPAT_RECV.len = 0;
                mg_printf(session.ctrl_conn, "QUIT\r\n");
            }
        } //else: ignore incoming messages if Method is not Retrieve
    } else if (ev == MG_EV_POLL) {
        if (session.method == MongooseFtpClient::Method::Append && session.data_conn_accepted) {

            if (!session.fileReader) {
                MO_DBG_ERR("invalid state");
                mg_printf(session.ctrl_conn, "QUIT\r\n");
                mg_compat_drain_conn(c);
                return;
            }

            if (c->MG_COMPAT_SEND.len == 0) { //fill send buff
                if (c->MG_COMPAT_SEND.size < 512) {
                    mg_compat_iobuf_resize(&c->MG_COMPAT_SEND, 512);
                }

                c->MG_COMPAT_SEND.len = session.fileReader((unsigned char*)c->MG_COMPAT_SEND.buf, c->MG_COMPAT_SEND.size);

                if (c->MG_COMPAT_SEND.len == 0) {
                    MO_DBG_DEBUG("finished file reading");
                    session.data_conn_accepted = false;
                    mg_compat_drain_conn(c);

                    //on MG v7 and MbedTLS, call mbedtls_ssl_close_notify() when closing
                    #if !defined(MO_MG_VERSION_614) && MG_COMPAT_TLS == MG_COMPAT_MBEDTLS
                    if (auto tls = mg_compat_get_tls(c)) {
                        MO_DBG_DEBUG("TLS shutdown");
                        mbedtls_ssl_close_notify(tls);
                    }
                    #endif
                    return;
                }
            }
        }
    }
}

bool MongooseFtpClient::readUrl(const char *ftp_url_raw) {
    std::string ftp_url = ftp_url_raw; //copy input ftp_url

    //tolower protocol specifier
    for (auto c = ftp_url.begin(); *c != ':' && c != ftp_url.end(); c++) {
        *c = tolower(*c);
    }

    //parse FTP URL: protocol specifier
    if (!strncmp(ftp_url.c_str(), "ftps://", strlen("ftps://"))) {
        //FTP over TLS (RFC 4217)
        proto = "ftps://";
    } else if (!strncmp(ftp_url.c_str(), "ftp://", strlen("ftp://"))) {
        //FTP without security policies (RFC 959)
        proto = "ftp://";
    } else {
        MO_DBG_ERR("protocol not supported. Please use ftps:// or ftp://");
        return false;
    }

    //parse FTP URL: dir and fname
    auto dir_pos = ftp_url.find_first_of('/', proto.length());
    if (dir_pos != std::string::npos) {
        auto fname_pos = ftp_url.find_last_of('/');
        dir = ftp_url.substr(dir_pos, fname_pos - dir_pos);
        fname = ftp_url.substr(fname_pos + 1);
    }
    
    if (fname.empty()) {
        MO_DBG_ERR("missing filename");
        return false;
    }
    
    MO_DBG_VERBOSE("parsed dir: %s; fname: %s", dir.c_str(), fname.c_str());

    //parse FTP URL: user, pass, host, port

    std::string user_pass_host_port = ftp_url.substr(proto.length(), dir_pos - proto.length());
    std::string user_pass, host_port;
    auto user_pass_delim = user_pass_host_port.find_first_of('@');
    if (user_pass_delim != std::string::npos) {
        host_port = user_pass_host_port.substr(user_pass_delim + 1);
        user_pass = user_pass_host_port.substr(0, user_pass_delim);
    } else {
        host_port = user_pass_host_port;
    }

    if (!user_pass.empty()) {
        auto user_delim = user_pass.find_first_of(':');
        if (user_delim != std::string::npos) {
            user = user_pass.substr(0, user_delim);
            pass = user_pass.substr(user_delim + 1);
        } else {
            user = user_pass;
        }
    }

    MO_DBG_VERBOSE("parsed user: %s; pass: %.2s***", user.c_str(), pass.empty() ? "-" : pass.c_str());

    if (host_port.empty()) {
        MO_DBG_ERR("missing hostname");
        return false;
    }

    if (host_port.find(':') == std::string::npos) {
        //use default port number
        host_port.append(":21");
    }

    url = std::string("tcp://") + host_port;

    MO_DBG_VERBOSE("parsed ctrl_ch URL: %s", url.c_str());

    return true;
}
