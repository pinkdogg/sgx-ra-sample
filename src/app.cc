#include <sgx_urts.h>
#include <iostream>
#include "Enclave_u.h"
#include <sgx_uae_epid.h>
#include <sgx_ukey_exchange.h>
#include "SSLConnection.h"
#include "hexutil.h"

#define ENCLAVE_FILEPATH "Enclave/enclave.signed.so"

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

sgx_enclave_id_t global_eid = 0;

int do_attestation(sgx_enclave_id_t eid);

SSLConnection sslConnection("127.0.0.1", 7777, kCLIENTSIDE);
int main()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILEPATH, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("create enclave failed.\n");
        return -1;
    }

    ret = ecall_print_hello(global_eid);
    if (ret != SGX_SUCCESS)
    {
        printf("ecall failed.\n");
        return -1;
    }

    //=========test SSLConnection=========
    if(!sslConnection.ConnectSSL()) {
        printf("SSLConnection: connect failed.\n");
        return -1;
    }
    std::string msg = "client hello";
    uint8_t* data;
    uint32_t receivedSize;
    if(!sslConnection.SendData((uint8_t*)msg.c_str(), msg.size())) {
        printf("SSLConnection: send data failed.\n");
        return -1;
    }
    if(!sslConnection.ReceiveData(&data, receivedSize)) {
        printf("SSLConnection: receive data failed.\n");
        return -1;
    }
    printf("read from server:");
    for(int i = 0; i < receivedSize; i++) {
        printf("%c", data[i]);
    }
    printf("\n");
    //===================================

    do_attestation(global_eid);

    sgx_destroy_enclave(global_eid);
    sslConnection.Finish();
    return 0;
}

int do_attestation(sgx_enclave_id_t eid)
{
    sgx_status_t ret, status;
    uint8_t *buffer;
    uint32_t bufferSize;

    bool b_pse = false;
    sgx_ra_context_t context = 0xdeadbeef;

    // message
    uint32_t msg0_extended_epid_group_id = 0;
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t *msg2 = nullptr;
    sgx_ra_msg3_t *msg3 = nullptr;
    ra_msg4_t *msg4 = nullptr;
    uint32_t msg2_sz, msg3_sz, msg4_sz;

    int enclaveTrusted = NotTrusted; // Not Trusted

    /* Executes an ECALL that runs sgx_ra_init() */
    status = ecall_enclave_ra_init(global_eid, &ret, b_pse, &context);
    if (status != SGX_SUCCESS)
    {
        fprintf(stderr, "enclave_ra_init: %08x\n", status);
        return 1;
    }
    if (ret != SGX_SUCCESS)
    {
        fprintf(stderr, "sgx_ra_init: %08x\n", ret);
        return 1;
    }

    // generate msg0
    status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
    if (status != SGX_SUCCESS)
    {
        ecall_enclave_ra_close(eid, &ret, context);
        fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
        return 1;
    }

    // generate msg1
    status = sgx_ra_get_msg1(context, global_eid, sgx_ra_get_ga, &msg1);
    if (status != SGX_SUCCESS)
    {
        ecall_enclave_ra_close(eid, &ret, context);
        fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
        return 1;
    }

    // send msg0 || msg1 to service provider
    bufferSize = sizeof(uint32_t) + sizeof(sgx_ra_msg1_t);
    buffer = (uint8_t *)malloc(bufferSize);
    memcpy(buffer, &msg0_extended_epid_group_id, sizeof(uint32_t));
    memcpy(buffer + sizeof(uint32_t), &msg1, sizeof(msg1));
    if (!sslConnection.SendData(buffer, bufferSize))
    {
        fprintf(stderr, "send msg0||msg1 failed.\n");
        return 1;
    }
    free(buffer);

    // read msg2
    if (!sslConnection.ReceiveData((uint8_t **)&msg2, msg2_sz))
    {
        fprintf(stderr, "read msg2 failed.\n");
        ecall_enclave_ra_close(eid, &ret, context);
        return 1;
    }

    // process msg2, get msg3
    msg3 = nullptr;

    status = sgx_ra_proc_msg2(context, eid,
                              sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2,
                              sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
                              &msg3, &msg3_sz);

    free(msg2);

    if (status != SGX_SUCCESS)
    {
        ecall_enclave_ra_close(eid, &ret, context);
        fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);
        return 1;
    }

    // send msg3, remember to free msg3
    if (!sslConnection.SendData((uint8_t *)msg3, msg3_sz))
    {
        fprintf(stderr, "send msg3 failed.\n");
        ecall_enclave_ra_close(eid, &ret, context);
        return 1;
    }
    free(msg3);

    // read msg4 provided by the Service Provider and process
    if (!sslConnection.ReceiveData((uint8_t **)&msg4, msg4_sz))
    {
        fprintf(stderr, "read msg4 failed.\n");
        ecall_enclave_ra_close(eid, &ret, context);
        return 1;
    }
    enclaveTrusted = msg4->status;
    if (enclaveTrusted == Trusted)
    {
        printf("Enclave TRUSTED\n");
    }
    else if (enclaveTrusted == NotTrusted)
    {
        printf("Enclave NOT TRUSTED\n");
    }
    else if (enclaveTrusted == Trusted_ItsComplicated)
    {
        // Trusted, but client may be untrusted in the future unless it
        // takes action.

        printf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
    }
    else
    {
        // Not Trusted, but client may be able to take action to become
        // trusted.

        printf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
    }

    /* check to see if we have a PIB by comparing to empty PIB */
    sgx_platform_info_t emptyPIB;
    memset(&emptyPIB, 0, sizeof(sgx_platform_info_t));

    int retPibCmp = memcmp(&emptyPIB, (void *)(&msg4->platformInfoBlob), sizeof(sgx_platform_info_t));

    if (retPibCmp == 0)
    {
        printf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
    }
    else
    {
        printf("A Platform Info Blob (PIB) was provided by the IAS\n");

        /* We have a PIB, so check to see if there are actions to take */
        sgx_update_info_bit_t update_info;
        sgx_status_t ret = sgx_report_attestation_status(&msg4->platformInfoBlob,
                                                         enclaveTrusted, &update_info);

        /* Check to see if there is an update needed */
        if (ret == SGX_ERROR_UPDATE_NEEDED)
        {

            printf("Platform Update Required");
            printf("The following Platform Update(s) are required to bring this\n");
            printf("platform's Trusted Computing Base (TCB) back into compliance:\n\n");
            if (update_info.pswUpdate)
            {
                printf("  * Intel SGX Platform Software needs to be updated to the latest version.\n");
            }

            if (update_info.csmeFwUpdate)
            {
                printf("  * The Intel Management Engine Firmware Needs to be Updated.  Contact your\n");
                printf("    OEM for a BIOS Update.\n");
            }

            if (update_info.ucodeUpdate)
            {
                printf("  * The CPU Microcode needs to be updated.  Contact your OEM for a platform\n");
                printf("    BIOS Update.\n");
            }
            printf("\n");
        }
    }

    /*
	 * If the enclave is trusted, fetch a hash of the the MK and SK from
	 * the enclave to show proof of a shared secret with the service 
	 * provider.
	 */

	if ( enclaveTrusted == Trusted ) {
		sgx_status_t key_status, sha_status;
		sgx_sha256_hash_t mkhash, skhash;

		// First the MK
		printf("+++ fetching SHA256(MK)\n");
		status= ecall_enclave_ra_get_key_hash(eid, &sha_status, &key_status, context,
			SGX_RA_KEY_MK, &mkhash);
		// printf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n", status);
		// printf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);

		// Then the SK
		printf("+++ fetching SHA256(SK)\n");
		status= ecall_enclave_ra_get_key_hash(eid, &sha_status, &key_status, context,
            SGX_RA_KEY_SK, &skhash);
		// printf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n", status);
		// printf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);

        printf("SHA256(MK) = ");
        print_hexstring(stderr, mkhash, sizeof(mkhash));
        printf("\n");
        printf("SHA256(SK) = ");
        print_hexstring(stderr, skhash, sizeof(skhash));
	}

	free (msg4);

	ecall_enclave_ra_close(eid, &ret, context);

    return 0;
}