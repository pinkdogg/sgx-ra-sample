#ifndef FROG_INCLUDE_SSLCONNECTION_H_
#define FROG_INCLUDE_SSLCONNECTION_H_

#include <string>
#include "define.h"
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <memory>

class SSLConnection {
 public:
  SSLConnection(const std::string& serverIp, int port, SSLConnectionType type);
  ~SSLConnection();
  bool ConnectSSL();
  bool ListenSSL();
  bool SendData(const uint8_t* data, uint32_t dataSize);
  bool ReceiveData(uint8_t** data, uint32_t & receivedSize);
  bool Finish();
 public:
  static int listenFd_;
 private:
  std::string serverIp_;
  int port_;
  int socketFd_;
  SSL* connection_ = nullptr;
  struct sockaddr_in socketAddr_;
  SSL_CTX *sslCtx_ = nullptr;

  std::string caFile_;
  std::string crtFile_;
  std::string keyFile_;
};

#endif//FROG_INCLUDE_SSLCONNECTION_H_
