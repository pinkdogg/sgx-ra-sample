#include <iostream>
#include "SSLConnection.h"
#include <sgx_key_exchange.h>
#include "define.h"
#include <cstring>
#include "crypto.h"
#include "iasrequest.h"
#include "fileio.h"
#include <string>
#include "hexutil.h"
#include "agent.h"
#include "base64.h"
#include "json.hpp"
#include "enclave_verify.h"

static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01};

typedef struct ra_session_struct
{
	unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
} ra_session_t;

typedef struct config_struct
{
	sgx_spid_t spid;
	unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
	unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE + 1];
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	char *proxy_server;
	char *ca_bundle;
	char *user_agent;
	unsigned int proxy_port;
	unsigned char kdk[16];
	X509_STORE *store;
	X509 *signing_ca;
	unsigned int apiver;
	int strict_trust;
	sgx_measurement_t req_mrsigner;
	sgx_prod_id_t req_isv_product_id;
	sgx_isv_svn_t min_isvsvn;
	int allow_debug_enclave;
} config_t;

SSLConnection sslConnection("127.0.0.1", 7777, kSERVERSIDE);

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a);

int process_msg01(IAS_Connection *ias, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2,
				  char **sig_rl, config_t *config, ra_session_t *session);

int process_msg3(IAS_Connection *ias, sgx_ra_msg1_t *msg1,
				 ra_msg4_t *msg4, config_t *config, ra_session_t *session);

int get_sigrl(IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
			  char **sigrl, uint32_t *msg2);

int get_attestation_report(IAS_Connection *ias, int version,
						   const char *b64quote, sgx_ps_sec_prop_desc_t sec_prop, ra_msg4_t *msg4,
						   int strict_trust);

int get_proxy(char **server, unsigned int *port, const char *url);

void reverse_bytes(void *dest, void *src, size_t len);

char debug = 0;
char verbose = 0;

using namespace json;

int main()
{
	ra_session_t session;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t msg2;
	ra_msg4_t msg4;
	config_t config;
	char *sigrl = nullptr;
	IAS_Connection *ias = NULL;
	off_t offset = IAS_SUBSCRIPTION_KEY_SIZE;
	int ret = 0;
	char *eptr = NULL;
	unsigned long val;
	uint8_t *buffer = nullptr;
	uint32_t bufferSize = 0;

	memset(&session, 0, sizeof(ra_session_t));

	// to be filled
	char *ias_signing_cert = "Intel_SGX_Attestation_RootCA.cer"; // file path
	char *ca_bundle = "";		 // file path
	char *ias_pri_api_key = "primary_key";	 // file path
	char *ias_sec_api_key = "secondary_key";	 // file path
	char *mrsigner = "";		 // hexstring
	char *product_id = "0";
	char *spid_file = "SPID"; // file path
	char *min_isvsvn = "0";

	//=========test SSLConnection=========
    if(!sslConnection.ListenSSL()) {
        printf("SSLConnection: listen failed.\n");
        return -1;
    }
    std::string msg = "server hello";
    uint8_t* data;
    uint32_t receivedSize;
    if(!sslConnection.ReceiveData(&data, receivedSize)) {
        printf("SSLConnection: receive data failed.\n");
        return -1;
    }
	printf("read from client:");
	for(int i = 0; i < receivedSize; i++) {
		printf("%c", data[i]);
    }
	printf("\n");
    if(!sslConnection.SendData((uint8_t*)msg.c_str(), msg.size())) {
        printf("SSLConnection: send data failed.\n");
        return -1;
    }
    //===================================

	/* Config defaults */
	memset(&config, 0, sizeof(config));
	config.strict_trust = 0;
	config.apiver = IAS_API_DEF_VERSION; // api version
	config.allow_debug_enclave = 1;		 // allow debug-mode enclaves to attest.
	if (!cert_load_file(&config.signing_ca, ias_signing_cert))
	{ // IAS SGX Report Signing CA file
		crypto_perror("cert_load_file");
		printf("%s: could not load IAS Signing Cert CA\n", ias_signing_cert);
		return 1;
	}
	config.store = cert_init_ca(config.signing_ca);
	if (config.store == NULL)
	{
		printf("%s: could not initialize certificate store\n", ias_signing_cert);
		return 1;
	}

	// config.ca_bundle = strdup(ca_bundle); // CA bundle used to validate the IAS server certificate
	// if (config.ca_bundle == NULL)
	// {
	// 	perror("strdup");
	// 	return 1;
	// }

	// Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
	ret = from_file(NULL, ias_pri_api_key, &offset);

	if ((offset != IAS_SUBSCRIPTION_KEY_SIZE + 1) || (ret == 0))
	{
		printf("IAS Primary Subscription Key must be %d-byte hex string.\n",
			   IAS_SUBSCRIPTION_KEY_SIZE);
		return 1;
	}
	// Remove the EOF
	offset--;
	// Read the contents of the file
	if (!from_file((unsigned char *)&config.pri_subscription_key, ias_pri_api_key, &offset))
	{
		printf("IAS Primary Subscription Key must be %d-byte hex string.\n",
			   IAS_SUBSCRIPTION_KEY_SIZE);
		return 1;
	}
	printf("Primary_key:%s\n", config.pri_subscription_key);
	// Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
	ret = from_file(NULL, ias_sec_api_key, &offset);
	if ((offset != IAS_SUBSCRIPTION_KEY_SIZE + 1) || (ret == 0))
	{
		printf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
			   IAS_SUBSCRIPTION_KEY_SIZE);
		return 1;
	}
	// Remove the EOF
	offset--;
	// Read the contents of the file
	if (!from_file((unsigned char *)&config.sec_subscription_key, ias_sec_api_key, &offset))
	{
		printf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
			   IAS_SUBSCRIPTION_KEY_SIZE);
		return 1;
	}

	config.service_private_key = key_private_from_bytes(def_service_private_key);
	if (config.service_private_key == NULL)
	{
		crypto_perror("key_private_from_bytes");
		return 1;
	}

	if (!from_hexstring((unsigned char *)&config.req_mrsigner, mrsigner, 32))
	{
		printf("MRSIGNER must be 64-byte hex string\n");
		return 1;
	}

	eptr = NULL;
	val = strtoul(product_id, &eptr, 10);
	if (*eptr != '\0' || val > 0xFFFF)
	{
		printf("Product Id must be a positive integer <= 65535\n");
		return 1;
	}
	config.req_isv_product_id = val;

	if (!from_hexstring_file((unsigned char *)&config.spid, spid_file, 16))
	{
		printf("SPID must be 32-byte hex string\n");
		return 1;
	}

	eptr = nullptr;
	val = strtoul(min_isvsvn, &eptr, 10);
	if (*eptr != '\0' || val > (unsigned long)0xFFFF)
	{
		printf("Minimum ISV SVN must be a positive integer <= 65535\n");
		return 1;
	}
	config.min_isvsvn = val;
	config.user_agent = "wget";
	config.quote_type = SGX_LINKABLE_SIGNATURE;

	// config.ca_bundle= strdup(DEFAULT_CA_BUNDLE);
	// if ( config.ca_bundle == NULL ) {
	// 	perror("strdup");
	// 	return 1;
	// }

	char flag_noproxy = 1;

	/* Initialize out support libraries */
	crypto_init();
	/* Initialize our IAS request object */
	try
	{
		ias = new IAS_Connection(
			IAS_SERVER_DEVELOPMENT,
			0,
			(char *)(config.pri_subscription_key),
			(char *)(config.sec_subscription_key));
	}
	catch (...)
	{
		printf("exception while creating IAS request object\n");
		return 1;
	}

	if (flag_noproxy)
		ias->proxy_mode(IAS_PROXY_NONE);
	else if (config.proxy_server != NULL)
	{
		ias->proxy_mode(IAS_PROXY_FORCE);
		ias->proxy(config.proxy_server, config.proxy_port);
	}

	if (config.user_agent != NULL)
	{
		if (!ias->agent(config.user_agent))
		{
			printf("%s: unknown user agent\n", config.user_agent);
			return 0;
		}
	}
	/*
	 * Set the cert store for this connection. This is used for verifying
	 * the IAS signing certificate, not the TLS connection with IAS (the
	 * latter is handled using config.ca_bundle).
	 */
	ias->cert_store(config.store);

	/*
	 * Set the CA bundle for verifying the IAS server certificate used
	 * for the TLS session. If this isn't set, then the user agent
	 * will fall back to it's default.
	 */
	if (strlen(config.ca_bundle))
		ias->ca_bundle(config.ca_bundle);

	//====================start exchange messages====================
	// Read message 0 and 1, then generate message 2
	if (!process_msg01(ias, &msg1, &msg2, &sigrl, &config, &session))
	{
		printf("error processing msg1\n");
		return -1;
	}

	// send msg2 and sigrl
	bufferSize = sizeof(msg2) + msg2.sig_rl_size;
	buffer = (uint8_t *)malloc(bufferSize);
	memcpy(buffer, &msg2, sizeof(msg2));
	memcpy(buffer + sizeof(msg2), sigrl, msg2.sig_rl_size);
	sslConnection.SendData(buffer, bufferSize);
	free(buffer);
	free(sigrl);

	// read msg3 and generate msg4
	if (!process_msg3(ias, &msg1, &msg4, &config, &session))
	{
		printf("error processing msg3\n");
		return 1;
	}

	sslConnection.Finish();
	crypto_destroy();
	return 0;
}

int process_msg3(IAS_Connection *ias, sgx_ra_msg1_t *msg1,
				 ra_msg4_t *msg4, config_t *config, ra_session_t *session)
{
	sgx_ra_msg3_t *msg3 = nullptr;
	uint32_t msg3_sz;
	sgx_quote_t *q;
	uint32_t quote_sz;
	sgx_mac_t vrfymac;
	char *b64quote;

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */
	if (!sslConnection.ReceiveData((uint8_t **)&msg3, msg3_sz))
	{
		printf("read msg3 failed.\n");
		return 0;
	}
	quote_sz = msg3_sz - sizeof(sgx_ra_msg3_t);

	// make sure Ga matches msg1
	if (CRYPTO_memcmp(&msg3->g_a, &msg1->g_a, sizeof(sgx_ec256_public_t)))
	{
		printf("msg1.g_a and mgs3.g_a keys don't match\n");
		free(msg3);
		return 0;
	}

	// validate the mac of M
	cmac128(session->smk, (unsigned char *)&msg3->g_a,
			sizeof(sgx_ra_msg3_t) - sizeof(sgx_mac_t) + quote_sz,
			(unsigned char *)vrfymac);
	if (CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)))
	{
		printf("Failed to verify msg3 MAC\n");
		free(msg3);
		return 0;
	}

	/* encode the report body as base64 */
	b64quote = base64_encode((char *)&msg3->quote, quote_sz);
	if (b64quote == NULL)
	{
		printf("Could not base64 encode the quote\n");
		free(msg3);
		return 0;
	}
	q = (sgx_quote_t *)msg3->quote;

	/* verify that the EPID group ID in the quote matches the one from msg1 */
	if (memcmp(msg1->gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t)))
	{
		printf("EPID GID mismatch. Attestation failed.\n");
		free(b64quote);
		free(msg3);
		return 0;
	}

	if(get_attestation_report(ias, config->apiver, b64quote, msg3->ps_sec_prop, 
								msg4, config->strict_trust)) {

		unsigned char vfy_rdata[64];
		unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

		sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

		memset(vfy_rdata, 0, 64);

		/*
		 * Verify that the first 64 bytes of the report data (inside
		 * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
		 *
		 * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
		 *
		 * where || denotes concatenation.
		 */

		/* Derive VK */

		cmac128(session->kdk, (unsigned char *)("\x01VK\x00\x80\x00"),
				6, session->vk);

		/* Build our plaintext */

		memcpy(msg_rdata, session->g_a, 64);
		memcpy(&msg_rdata[64], session->g_b, 64);
		memcpy(&msg_rdata[128], session->vk, 16);

		/* SHA-256 hash */

		sha256_digest(msg_rdata, 144, vfy_rdata);

		if (CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data, 64) ) {
			printf("Report verification failed.\n");
			free(b64quote);
			free(msg3);
			return 0;
		}

		/*
		 * The service provider must validate that the enclave
		 * report is from an enclave that they recognize. Namely,
		 * that the MRSIGNER matches our signing key, and the MRENCLAVE
		 * hash matches an enclave that we compiled.
		 *
		 * Other policy decisions might include examining ISV_SVN to 
		 * prevent outdated/deprecated software from successfully
		 * attesting, and ensuring the TCB is not out of date.
		 *
		 * A real-world service provider might allow multiple ISV_SVN
		 * values, but for this sample we only allow the enclave that
		 * is compiled.
		 */

		if (!verify_enclave_identity(config->req_mrsigner, 
			config->req_isv_product_id, config->min_isvsvn, 
			config->allow_debug_enclave, r) ) {
			printf("Invalid enclave.\n");
			msg4->status= NotTrusted;
		}

		// send msg4
		if(!sslConnection.SendData((uint8_t*)msg4, sizeof(ra_msg4_t))) {
			printf("send msg4 failed.\n");
			return 0;
		}

		/*
		 * If the enclave is trusted, derive the MK and SK. Also get
		 * SHA256 hashes of these so we can verify there's a shared
		 * secret between us and the client.
		 */

		if ( msg4->status == Trusted ) {
			unsigned char hashmk[32], hashsk[32];

			printf("+++ Deriving the MK and SK\n");
			cmac128(session->kdk, (unsigned char *)("\x01MK\x00\x80\x00"),
				6, session->mk);
			cmac128(session->kdk, (unsigned char *)("\x01SK\x00\x80\x00"),
				6, session->sk);

			sha256_digest(session->mk, 16, hashmk);
			sha256_digest(session->sk, 16, hashsk);

			printf("MK         = %s\n", hexstring(session->mk, 16));
			printf("SK         = %s\n", hexstring(session->sk, 16));
			printf("SHA256(MK) = %s\n", hexstring(hashmk, 32));
			printf("SHA256(SK) = %s\n", hexstring(hashsk, 32));
		}

	} else {
		printf("Attestation failed\n");
		free(msg3);
		free(b64quote);
		return 0;
	}
	free(msg3);
	free(b64quote);
	return 1;
}

int process_msg01(IAS_Connection *ias, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2,
				  char **sig_rl, config_t *config, ra_session_t *session)
{
	struct msg01_struct
	{
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} *msg01;
	EVP_PKEY *Gb;
	unsigned char digest[32], r[32], s[32], gb_ga[128];

	uint32_t receivedSize = 0;
	// read incoming message
	sslConnection.ReceiveData((uint8_t **)&msg01, receivedSize);
	if (receivedSize != sizeof(msg01_struct))
	{
		printf("read msg0||msg1 failed.\n");
		return 0;
	}

	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID
	 * is not zero, the server aborts remote attestation"
	 */

	if (msg01->msg0_extended_epid_group_id != 0)
	{
		printf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		free(msg01);
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	memcpy(msg1, &msg01->msg1, sizeof(sgx_ra_msg1_t));

	// generate our session key
	Gb = key_generate();
	if (Gb == NULL)
	{
		printf("could not create a session key\n");
		free(msg01);
		return 0;
	}

	// derive KDK
	if (!derive_kdk(Gb, session->kdk, msg1->g_a))
	{
		printf("could not derive the KDK\n");
		free(msg01);
		return 0;
	}

	/*
	 * Derive the SMK from the KDK
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00)
	 */

	cmac128(session->kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, session->smk);

	/*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga)
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 *
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contents
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */

	key_to_sgx_ec256(&msg2->g_b, Gb);
	memcpy(&msg2->spid, &config->spid, sizeof(sgx_spid_t));
	msg2->quote_type = config->quote_type;
	msg2->kdf_id = 1;

	/* Get the sigrl */

	if (!get_sigrl(ias, config->apiver, msg1->gid, sig_rl, &msg2->sig_rl_size))
	{
		printf("could not retrieve the sigrl\n");
		free(msg01);
		return 0;
	}

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(session->g_b, &msg2->g_b, 64);

	memcpy(&gb_ga[64], &msg1->g_a, 64);
	memcpy(session->g_a, &msg1->g_a, 64);

	ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(session->smk, (unsigned char *)msg2, 148,
			(unsigned char *)&msg2->mac);

	free(msg01);

	return 1;
}

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga = key_from_sgx_ec256(&g_a);
	if (Ga == NULL)
	{
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x = key_shared_secret(Gb, Ga, &slen);
	if (Gab_x == NULL)
	{
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	reverse_bytes(Gab_x, Gab_x, slen);

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

int get_sigrl(IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
			  char **sig_rl, uint32_t *sig_rl_size)
{
	IAS_Request *req = NULL;
	int oops = 1;
	string sigrlstr;

	try
	{
		oops = 0;
		req = new IAS_Request(ias, (uint16_t)version);
	}
	catch (...)
	{
		oops = 1;
	}

	if (oops)
	{
		printf("Exception while creating IAS request object\n");
		delete req;
		return 0;
	}

	ias_error_t ret = IAS_OK;

	while (1)
	{
		ret = req->sigrl(*(uint32_t *)gid, sigrlstr);

		if (ret == IAS_UNAUTHORIZED && (ias->getSubscriptionKeyID() == IAS_Connection::SubscriptionKeyID::Primary))
		{
			// Retry with Secondary Subscription Key
			ias->SetSubscriptionKeyID(IAS_Connection::SubscriptionKeyID::Secondary);
			continue;
		}
		else if (ret != IAS_OK)
		{
			delete req;
			return 0;
		}
		break;
	}
	size_t size;

	*sig_rl = (char *)base64_decode(sigrlstr.c_str(), &size);
	if (*sig_rl == NULL)
	{
		printf("Could not decode SigRL\n");
		delete req;
		return 0;
	}

	*sig_rl_size = (uint32_t)size;
	delete req;

	return 1;
}

int get_attestation_report(IAS_Connection *ias, int version,
						   const char *b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t *msg4,
						   int strict_trust)
{
	IAS_Request *req = NULL;
	map<string, string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;

	try
	{
		req = new IAS_Request(ias, (uint16_t)version);
	}
	catch (...)
	{
		printf("Exception while creating IAS request object\n");
		if (req != NULL)
			delete req;
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));

	status = req->report(payload, content, messages);
	if (status == IAS_OK)
	{
		JSON reportObj = JSON::Load(content);
		/*
		 * If the report returned a version number (API v3 and above), make
		 * sure it matches the API version we used to fetch the report.
		 *
		 * For API v3 and up, this field MUST be in the report.
		 */

		if (reportObj.hasKey("version"))
		{
			unsigned int rversion = (unsigned int)reportObj["version"].ToInt();
			if (version != rversion)
			{
				printf("Report version %u does not match API version %u\n",
						rversion, version);
				delete req;
				return 0;
			}
		} else if (version >= 3)
		{
			printf("attestation report version required for API version >= 3\n");
			delete req;
			return 0;
		}

		/*
		 * This sample's attestion policy is based on isvEnclaveQuoteStatus:
		 *
		 *   1) if "OK" then return "Trusted"
		 *
		 *   2) if "CONFIGURATION_NEEDED", "SW_HARDENING_NEEDED", or
		 *      "CONFIGURATION_AND_SW_HARDENING_NEEDED", then return
				"NotTrusted_ItsComplicated" when in --strict-trust-mode
				 and "Trusted_ItsComplicated" otherwise
		 *
		 *   3) return "NotTrusted" for all other responses
		 *
		 * In case #2, this is ultimatly a policy decision. Do you want to
		 * trust a client that is running with a configuration that weakens
		 * its security posture? Even if you ultimately choose to trust the
		 * client, the "Trusted_ItsComplicated" response is intended to
		 * tell the client "I'll trust you (for now), but inform the user
		 * that I may not trust them in the future unless they take some
		 * action". A real service would provide some guidance to the
		 * end user based on the advisory URLs and advisory IDs.
		 */

		/*
		 * Simply check to see if status is OK, else enclave considered
		 * not trusted
		 */

		memset(msg4, 0, sizeof(ra_msg4_t));

		if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK")))
		{
			msg4->status = Trusted;
			if (verbose)
				printf("Enclave TRUSTED\n");
		}
		else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED")))
		{
			if (strict_trust)
			{
				msg4->status = NotTrusted_ItsComplicated;
				if (verbose)
					printf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
							reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			}
			else
			{
				if (verbose)
					printf("Enclave TRUSTED and COMPLICATED - Reason: %s\n",
							reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
				msg4->status = Trusted_ItsComplicated;
			}
		}
		else if (!(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE")))
		{
			msg4->status = NotTrusted_ItsComplicated;
			if (verbose)
				printf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
						reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
		}
		else
		{
			msg4->status = NotTrusted;
			if (verbose)
				printf("Enclave NOT TRUSTED - Reason: %s\n",
						reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
		}

		/* Check to see if a platformInfoBlob was sent back as part of the
		 * response */

		if (!reportObj["platformInfoBlob"].IsNull())
		{
			if (verbose)
				printf("A Platform Info Blob (PIB) was provided by the IAS\n");

			/* The platformInfoBlob has two parts, a TVL Header (4 bytes),
			 * and TLV Payload (variable) */

			string pibBuff = reportObj["platformInfoBlob"].ToString();

			/* remove the TLV Header (8 base16 chars, ie. 4 bytes) from
			 * the PIB Buff. */

			pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4 * 2));

			int ret = from_hexstring((unsigned char *)&msg4->platformInfoBlob,
									 pibBuff.c_str(), pibBuff.length() / 2);
		}
		else
		{
			if (verbose)
				printf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
		}

		delete req;
		return 1;
	}

	printf("attestation query returned %lu: \n", status);

	switch (status)
	{
	case IAS_QUERY_FAILED:
		printf("Could not query IAS\n");
		break;
	case IAS_BADREQUEST:
		printf("Invalid payload\n");
		break;
	case IAS_UNAUTHORIZED:
		printf("Failed to authenticate or authorize request\n");
		break;
	case IAS_SERVER_ERR:
		printf("An internal error occurred on the IAS server\n");
		break;
	case IAS_UNAVAILABLE:
		printf("Service is currently not able to process the request. Try again later.\n");
		break;
	case IAS_INTERNAL_ERROR:
		printf("An internal error occurred while processing the IAS response\n");
		break;
	case IAS_BAD_CERTIFICATE:
		printf("The signing certificate could not be validated\n");
		break;
	case IAS_BAD_SIGNATURE:
		printf("The report signature could not be validated\n");
		break;
	default:
		if (status >= 100 && status < 600)
		{
			printf("Unexpected HTTP response code\n");
		}
		else
		{
			printf("An unknown error occurred.\n");
		}
	}

	delete req;

	return 0;
}

/*
 * Reverse the bytes in an array. Can do this in-place (src == dest)
 * but any other overlapping gives undefined behavior so don't do it.
 */

void reverse_bytes(void *dest, void *src, size_t len)
{
	size_t i;
	char *sp = (char *)src;

	if (len < 2)
		return;

	if (src == dest)
	{
		size_t j;

		for (i = 0, j = len - 1; i < j; ++i, --j)
		{
			char t = sp[j];
			sp[j] = sp[i];
			sp[i] = t;
		}
	}
	else
	{
		char *dp = (char *)dest + len - 1;
		for (i = 0; i < len; ++i, ++sp, --dp)
			*dp = *sp;
	}
}