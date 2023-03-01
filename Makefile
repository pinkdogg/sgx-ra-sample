######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
OPENSSL_INCLUDE_PATH = /usr/include/openssl
OPENSSL_LIBRARY_PATH = /lib/x86_64-linux-gnu

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Include_Paths := -Ihttpparser -Iinclude -IIAS -I$(SGX_SDK)/include -I$(OPENSSL_INCLUDE_PATH) 

C_Flags := -fPIC -Wno-attributes $(Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Cpp_Flags := $(C_Flags)
Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lsgx_uae_service_sim -lsgx_ukey_exchange -lpthread 
Link_Flags += -L$(OPENSSL_LIBRARY_PATH) -lssl -lcrypto 

######## Objects ########

.PHONY: all

all: app sp

src/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd src && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

src/Enclave_u.c: src/Enclave_u.h

%.o: %.cc
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

%.o: %.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


app: src/Enclave_u.o src/app.o  src/SSLConnection.o IAS/hexutil.o
	@$(CXX) $^ -o $@ $(Link_Flags) 
	@echo "LINK =>  $@"

sp: src/sp.o src/SSLConnection.o IAS/crypto.o IAS/fileio.o IAS/iasrequest.o IAS/hexutil.o IAS/base64.o IAS/enclave_verify.o IAS/agent_wget.o IAS/common.o IAS/logfile.o
	@$(CXX) $^ -o $@ $(Link_Flags)
	@echo "LINK => $@"

.PHONY: clean
clean:
	@rm -f app sp src/*.o src/Enclave_u.* IAS/*.o
