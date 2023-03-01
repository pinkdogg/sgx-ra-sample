#include "SSLConnection.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/err.h>
#include <cstring>

int SSLConnection::listenFd_ = 0;

SSLConnection::SSLConnection(const std::string &serverIp, int port, SSLConnectionType type)
  :serverIp_(serverIp), port_(port) {

  SSL_load_error_strings();
  SSL_library_init();

  memset(&socketAddr_, 0, sizeof(socketAddr_));
  socketAddr_.sin_family = AF_INET;
  socketAddr_.sin_port = htons(port_);

  caFile_.assign(kCaCrt);
  int optValue = 1;
  switch(type) {
    case kCLIENTSIDE:
      crtFile_.assign(kClientCrt);
      keyFile_.assign(kClientKey);

      sslCtx_ = SSL_CTX_new(TLS_client_method());
      socketAddr_.sin_addr.s_addr = inet_addr(serverIp_.c_str());
      break;
    case kSERVERSIDE:
      crtFile_.assign(kServerCrt);
      keyFile_.assign(kServerKey);

      sslCtx_ = SSL_CTX_new(TLS_server_method());
      SSL_CTX_set_mode(sslCtx_, SSL_MODE_AUTO_RETRY);

      socketAddr_.sin_addr.s_addr = htons(INADDR_ANY);
      if(listenFd_ == 0) {
        listenFd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &optValue,
                       sizeof(int)) < 0) {
          fprintf(stderr, "SSLConnection:cannot set the port reuseable.\n");
          exit(EXIT_FAILURE);
        }
        if (bind(listenFd_, (struct sockaddr*)&socketAddr_,
                 sizeof(socketAddr_)) == -1) {
          fprintf(stderr, "SSLConnection:cannot bind to socketFd.\n");
          exit(EXIT_FAILURE);
        }
        if (listen(listenFd_, 10) == -1) {
          fprintf(stderr, "SSLConnection:cannot listen this socket.\n");
          exit(EXIT_FAILURE);
        }
      }
      break;
  }

  SSL_CTX_set_verify(sslCtx_, SSL_VERIFY_PEER, nullptr);
  if (!SSL_CTX_load_verify_locations(sslCtx_, caFile_.c_str(), nullptr)) {
    fprintf(stderr, "SSLConnection:load ca crt error.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (!SSL_CTX_use_certificate_file(sslCtx_, crtFile_.c_str(),
                                    SSL_FILETYPE_PEM)) {
    fprintf(stderr, "SSLConnection:load cert error.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (!SSL_CTX_use_PrivateKey_file(sslCtx_, keyFile_.c_str(),
                                   SSL_FILETYPE_PEM)) {
    fprintf(stderr, "SSLConnection:load private key error.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (!SSL_CTX_check_private_key(sslCtx_)) {
    fprintf(stderr, "SSLConnection:check private key error.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

SSLConnection::~SSLConnection() {
  SSL_CTX_free(sslCtx_);
}

bool SSLConnection::ConnectSSL() {
  socketFd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(connect(socketFd_, (struct sockaddr*)&socketAddr_, sizeof(socketAddr_)) == -1) {
    fprintf(stderr, "SSLConnection:cannot connect to the socket.\n");
    return false;
  }
  connection_ = SSL_new(sslCtx_);
  if(!SSL_set_fd(connection_, socketFd_)) {
    fprintf(stderr, "SSLConnection:cannot combine the fd and ssl.\n");
    return false;
  }
  if(SSL_connect(connection_) != 1) {
    fprintf(stderr, "SSLConnection:ssl connection failed.\n");
   return false;
  }
  printf("SSLConnection:client successfully connect to <%s:%d>\n", serverIp_.c_str(), port_);
  return true;
}

bool SSLConnection::ListenSSL() {
  struct sockaddr_in clientAddr;
  socklen_t clientAddrSize;

  socketFd_ = accept(listenFd_, (struct sockaddr*)&clientAddr, &clientAddrSize);
  if(socketFd_ < 0) {
    fprintf(stderr, "SSLConnection:socket listen fail.\n");
    return false;
  }
  connection_ = SSL_new(sslCtx_);
  if(!SSL_set_fd(connection_, socketFd_)) {
    fprintf(stderr, "SSLConnection:cannot combine the fd and ssl.\n");
    exit(EXIT_FAILURE);
  }
  if (SSL_accept(connection_) != 1) {
    connection_ = nullptr;
    fprintf(stderr, "SSLConnection:ssl accept fails.\n");
    exit(EXIT_FAILURE);
  }
  printf("SSLConnection:server successfully accept new connection\n");
  return true;
}

bool SSLConnection::SendData(const uint8_t* data, uint32_t dataSize) {
  int sentSize = 0, totalSentSize = 0;
  sentSize = SSL_write(connection_, &dataSize, sizeof(uint32_t));
  if(sentSize <= 0) {
    fprintf(stderr, "SSLConnection:write data fails.\n");
    return false;
  }
  while(totalSentSize < dataSize) {
    sentSize = SSL_write(connection_, data + totalSentSize, dataSize - totalSentSize);
    if(sentSize <= 0) {
      fprintf(stderr, "SSLConnection:write data fails.\n");
      return false;
    }
    totalSentSize += sentSize;
  }
  return true;
}

bool SSLConnection::ReceiveData(uint8_t** data, uint32_t& receivedSize) {
  uint32_t len;
  int readSize;
  readSize = SSL_read(connection_, &len, sizeof(uint32_t));
  if(readSize <= 0) {
    if (SSL_get_error(connection_, readSize) == SSL_ERROR_ZERO_RETURN) {
      fprintf(stderr, "SSLConnection:TLS/SSL peer has closed the connection.\n");
      SSL_shutdown(connection_);
    }
    return false;
  }
  *data = (uint8_t*)malloc(len);
  if(*data == nullptr) {
    fprintf(stderr, "SSLConnection:malloc fails.\n");
    return false;
  }
  receivedSize = 0;
  while(receivedSize < len) {
    readSize = SSL_read(connection_, *data + receivedSize, len - receivedSize);
    if(readSize <= 0) {
      if (SSL_get_error(connection_, readSize) == SSL_ERROR_ZERO_RETURN) {
        fprintf(stderr, "SSLConnection:TLS/SSL peer has closed the connection.\n");
        SSL_shutdown(connection_);
      }
      return false;
    }
    receivedSize += readSize;
  }
  return true;
}

bool SSLConnection::Finish() {
  int ret = SSL_shutdown(connection_);
  if (ret != 0) {
    fprintf(stderr, "SSLConnection:first shutdown the socket error.\n");
    exit(EXIT_FAILURE);
  }
  // check the ssl shutdown flag state
  if ((SSL_get_shutdown(connection_) & SSL_SENT_SHUTDOWN) != 1) {
    fprintf(stderr, "SSLConnection:set the sent shutdown flag error.\n");
    exit(EXIT_FAILURE);
  }
  // wait the close alert from another peer
  int tmp;
  ret = SSL_read(connection_, (uint8_t*)&tmp, sizeof(tmp));
  if (SSL_get_error(connection_, ret) != SSL_ERROR_ZERO_RETURN) {
    fprintf(stderr, "SSLConnection:receive shutdown flag error.\n");
  }

  printf("SSLConnection:shutdown the SSL connection successfully.\n");
  SSL_free(connection_);
  close(socketFd_);
}
