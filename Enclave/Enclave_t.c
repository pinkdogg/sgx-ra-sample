#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_enclave_ra_init_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
} ms_ecall_enclave_ra_init_t;

typedef struct ms_ecall_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ctx;
} ms_ecall_enclave_ra_close_t;

typedef struct ms_ecall_enclave_ra_get_key_hash_t {
	sgx_status_t ms_retval;
	sgx_status_t* ms_get_keys_status;
	sgx_ra_context_t ms_ctx;
	sgx_ra_key_type_t ms_type;
	sgx_sha256_hash_t* ms_hash;
} ms_ecall_enclave_ra_get_key_hash_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_ecall_print_hello(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_print_hello();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_ra_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_ra_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_ra_init_t* ms = SGX_CAST(ms_ecall_enclave_ra_init_t*, pms);
	ms_ecall_enclave_ra_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_enclave_ra_init_t), ms, sizeof(ms_ecall_enclave_ra_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_ctx = __in_ms.ms_ctx;
	size_t _len_ctx = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_ctx = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ctx, _len_ctx);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ctx != NULL && _len_ctx != 0) {
		if ((_in_ctx = (sgx_ra_context_t*)malloc(_len_ctx)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ctx, 0, _len_ctx);
	}
	_in_retval = ecall_enclave_ra_init(__in_ms.ms_b_pse, _in_ctx);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ctx) {
		if (memcpy_verw_s(_tmp_ctx, _len_ctx, _in_ctx, _len_ctx)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ctx) free(_in_ctx);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_ra_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_ra_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_ra_close_t* ms = SGX_CAST(ms_ecall_enclave_ra_close_t*, pms);
	ms_ecall_enclave_ra_close_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_enclave_ra_close_t), ms, sizeof(ms_ecall_enclave_ra_close_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_enclave_ra_close(__in_ms.ms_ctx);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_enclave_ra_get_key_hash(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_enclave_ra_get_key_hash_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_enclave_ra_get_key_hash_t* ms = SGX_CAST(ms_ecall_enclave_ra_get_key_hash_t*, pms);
	ms_ecall_enclave_ra_get_key_hash_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_enclave_ra_get_key_hash_t), ms, sizeof(ms_ecall_enclave_ra_get_key_hash_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t* _tmp_get_keys_status = __in_ms.ms_get_keys_status;
	size_t _len_get_keys_status = sizeof(sgx_status_t);
	sgx_status_t* _in_get_keys_status = NULL;
	sgx_sha256_hash_t* _tmp_hash = __in_ms.ms_hash;
	size_t _len_hash = sizeof(sgx_sha256_hash_t);
	sgx_sha256_hash_t* _in_hash = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_get_keys_status, _len_get_keys_status);
	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_get_keys_status != NULL && _len_get_keys_status != 0) {
		if ((_in_get_keys_status = (sgx_status_t*)malloc(_len_get_keys_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_get_keys_status, 0, _len_get_keys_status);
	}
	if (_tmp_hash != NULL && _len_hash != 0) {
		if ((_in_hash = (sgx_sha256_hash_t*)malloc(_len_hash)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hash, 0, _len_hash);
	}
	_in_retval = ecall_enclave_ra_get_key_hash(_in_get_keys_status, __in_ms.ms_ctx, __in_ms.ms_type, _in_hash);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_get_keys_status) {
		if (memcpy_verw_s(_tmp_get_keys_status, _len_get_keys_status, _in_get_keys_status, _len_get_keys_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_hash) {
		if (memcpy_verw_s(_tmp_hash, _len_hash, _in_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_get_keys_status) free(_in_get_keys_status);
	if (_in_hash) free(_in_hash);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	ms_sgx_ra_get_ga_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_get_ga_t), ms, sizeof(ms_sgx_ra_get_ga_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = __in_ms.ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	_in_retval = sgx_ra_get_ga(__in_ms.ms_context, _in_g_a);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_g_a) {
		if (memcpy_verw_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	ms_sgx_ra_proc_msg2_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_proc_msg2_trusted_t), ms, sizeof(ms_sgx_ra_proc_msg2_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = __in_ms.ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = __in_ms.ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = __in_ms.ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = __in_ms.ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	_in_retval = sgx_ra_proc_msg2_trusted(__in_ms.ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_report) {
		if (memcpy_verw_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_verw_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	ms_sgx_ra_get_msg3_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_get_msg3_trusted_t), ms, sizeof(ms_sgx_ra_get_msg3_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = __in_ms.ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = __in_ms.ms_p_msg3;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = sgx_ra_get_msg3_trusted(__in_ms.ms_context, __in_ms.ms_quote_size, _in_qe_report, _tmp_p_msg3, __in_ms.ms_msg3_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_ecall_print_hello, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_ra_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_ra_close, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_enclave_ra_get_key_hash, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][7];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

