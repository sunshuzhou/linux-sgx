#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include ../../../../buildenv.mk

SIM_DIR := $(LINUX_SDK_DIR)/simulation
VTUNE_DIR = $(LINUX_EXTERNAL_DIR)/vtune/linux

ifndef DEBUG
CXXFLAGS += -DDISABLE_TRACE
CFLAGS += -DDISABLE_TRACE
endif

CXXFLAGS += -fPIC -DSE_SIM -Werror
CFLAGS   += -fPIC -DSE_SIM -Werror

CPPFLAGS += $(ADDED_INC) #for ubuntu 11 and later version
CPPFLAGS += -I$(COMMON_DIR)/inc                \
            -I$(COMMON_DIR)/inc/internal/linux \
            -I$(LINUX_PSW_DIR)/urts            \
            -I$(LINUX_PSW_DIR)/urts/parser     \
            -I$(VTUNE_DIR)/include \
            -I$(VTUNE_DIR)/sdk/src/ittnotify

CPPFLAGS += -I$(COMMON_DIR)/inc/internal      \
            -I$(LINUX_PSW_DIR)/urts/linux     \
            -I$(SIM_DIR)/tinst                \
            -I$(SIM_DIR)/uinst

DIR1 := $(LINUX_PSW_DIR)/urts/
DIR2 := $(LINUX_PSW_DIR)/urts/linux/
DIR3 := $(LINUX_PSW_DIR)/urts/parser/
DIR4 := ../

LDFLAGS += -L$(COMMON_DIR)/se_wrapper \
           -L$(SIM_DIR)/uae_service_sim/linux

LDFLAGS += -L$(VTUNE_DIR)/sdk/src/ittnotify/ -littnotify -ldl

OBJ1 := enclave.o         \
        tcs.o             \
        loader.o          \
        se_detect.o       \
        enclave_mutex.o   \
        routine.o         \
        urts_xsave.o      \
        se_ocalls.o       \
        cpu_features.o    \
        node.o            \
        launch_checker.o 

OBJ2 := urts.o             \
        misc.o             \
        sig_handler.o      \
        debugger_support.o \
        get_thread_id.o

OBJ3 := section.o \
        elfparser.o

OBJ4 := enter_enclave.o

OBJ5 := enclave_creator_sim.o \
        cpusvn_util.o

OBJ6 := $(SIM_DIR)/driver_api/driver_api.o \
        $(SIM_DIR)/assembly/linux/lowlib.o \
        $(SIM_DIR)/assembly/linux/sgxsim.o \
        $(SIM_DIR)/uinst/u_instructions.o  \
        $(SIM_DIR)/uinst/enclave_mngr.o    \
        $(SIM_DIR)/uinst/linux/set_tls.o   \
        $(SIM_DIR)/uinst/linux/restore_tls.o

CPP_OBJ := $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ5)
OBJ     := $(CPP_OBJ) $(OBJ4)

vpath %.cpp .:$(DIR1):$(DIR2):$(DIR3):$(DIR4)

LDFLAGS +=  -L$(LINUX_EXTERNAL_DIR)/crypto_px

LIBURTSSIM_SHARED := libsgx_urts_sim.so
LIBURTS_DEPLOY := libsgx_urts_deploy.so

LDLIBS  += -lwrapper -lcrypto_px -Wl,-Bdynamic -Wl,-Bsymbolic -lsgx_uae_service_sim
SONAME = $(LIBURTSSIM_SHARED)

.PHONY: all
all: $(LIBURTSSIM_SHARED) $(LIBURTS_DEPLOY)| $(BUILD_DIR)
	$(CP) $^ $|


$(LIBURTSSIM_SHARED): simasm uinst driver_api wrapper uae_service_sim $(OBJ) $(OBJ6) -lcrypto_px ittnotify
	$(CXX) $(CXXFLAGS) -shared -Wl,-soname=$(SONAME) $(OBJ) $(OBJ6) $(LDFLAGS) $(LDLIBS) -o $@


$(BUILD_DIR):
	@$(MKDIR) $@

$(OBJ4): %.o: $(DIR2)/%.S
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(CPP_OBJ): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $< -o $@

-lcrypto_px:
	$(MAKE) -C $(LINUX_EXTERNAL_DIR)/crypto_px

.PHONY: wrapper
wrapper:
	$(MAKE) -C $(COMMON_DIR)/se_wrapper/

.PHONY: driver_api
driver_api:
	$(MAKE) -C $(SIM_DIR)/driver_api/

.PHONY: simasm
simasm:
	$(MAKE) -C $(SIM_DIR)/assembly/

.PHONY: uinst
uinst:
	$(MAKE) -C $(SIM_DIR)/uinst/

.PHONY: uae_service_sim
uae_service_sim:
	$(MAKE) -C $(SIM_DIR)/uae_service_sim/linux

.PHONY: ittnotify
ittnotify:
	$(MAKE) -C $(VTUNE_DIR)/sdk/src/ittnotify/

$(LIBURTS_DEPLOY):../urts_deploy.c
	 $(CC) -I$(COMMON_DIR)/inc -shared -fPIC -Wl,-soname=libsgx_urts.so $< -o $@

.PHONY: clean
clean::
	@$(RM) *.o $(LIBURTSSIM_SHARED) $(LIBURTS_DEPLOY) 
	@$(RM) $(BUILD_DIR)/$(LIBURTSSIM_SHARED) $(BUILD_DIR)/$(LIBURTS_DEPLOY)
	$(MAKE) -C $(COMMON_DIR)/se_wrapper                                    clean
	$(MAKE) -C $(SIM_DIR)/driver_api/                                      clean
	$(MAKE) -C $(SIM_DIR)/assembly/                                        clean
	$(MAKE) -C $(SIM_DIR)/uinst/                                           clean
	$(MAKE) -C $(SIM_DIR)/uae_service_sim/linux                            clean
	$(MAKE) -C $(LINUX_EXTERNAL_DIR)/crypto_px                             clean
	$(MAKE) -C $(VTUNE_DIR)/sdk/src/ittnotify/                             clean
