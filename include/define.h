#ifndef FROG_INCLUDE_DEFINE_H_
#define FROG_INCLUDE_DEFINE_H_
#include "sgx_quote.h"

enum HashSet {
  kSHA256 = 0,
  kMD5 = 1,
  kSHA1 = 2
};

enum EncryptSet {
  kAES_256_GCM = 0, 
  kAES_128_GCM = 1, 
  kAES_256_CFB = 2, 
  kAES_128_CFB = 3
};

const uint32_t kCRYPTO_BLOCK_SIZE = 16;
const uint8_t kAES_256_GCM_KEY[32] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

typedef struct {
    uint32_t rs_id_int;
    uint32_t counters[4];
    uint8_t data[273];
}SNP;

const uint32_t kREADSIZE = sizeof(SNP) * (16 << 10);
enum OrderType {
  kUPLOAD = 0,
  kPROCESS = 1,
  kQUIT =2,
};

enum OperationType {
  kGWASRequest = 0,
  kGWASResponse = 1,
};

enum DataMsgType {
  kFileNameHash = 0,
  kFileBody,
  kFileEnd,
  kClientError,
  kServerError
};

enum SSLConnectionType {
  kCLIENTSIDE = 0, kSERVERSIDE = 1
};

typedef struct {
  union {
    OrderType orderType;
    OperationType operationType;
  };
  uint8_t data[];
} OrderMsg_t;

typedef struct {
  DataMsgType dataMsgType;
}DataMsgHeader_t;

typedef struct {
  DataMsgHeader_t header;
  uint8_t data[];
}DataMsg_t;

const char kCaCrt[] = "key/ca/ca.crt";
const char kClientCrt[] = "key/client/client.crt";
const char kClientKey[] = "key/client/client.key";
const char kServerCrt[] = "key/server/server.crt";
const char kServerKey[] = "key/server/server.key";

/*
 * Define a structure to be used to transfer the Attestation Status 
 * from Server to client and include the Platform Info Blob in base16 
 * format as Message 4.
 *
 * The structure of Message 4 is not defined by SGX: it is up to the
 * service provider, and can include more than just the attestation
 * status and platform info blob.
 */

typedef enum {
	NotTrusted = 0,
	NotTrusted_ItsComplicated,
	Trusted_ItsComplicated,
	Trusted
} attestation_status_t;

typedef struct _ra_msg4_struct {
	attestation_status_t status;
	sgx_platform_info_t platformInfoBlob;
} ra_msg4_t;

#endif//FROG_INCLUDE_DEFINE_H_
