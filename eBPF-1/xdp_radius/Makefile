# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern xdp_eap
USER_TARGETS := xdp_loader xdp_user

COMMON_DIR := ../common
COMMON_OBJS := $(COMMON_DIR)/common_user_bpf_xdp.o

LDLIBS += -lbpf

include $(COMMON_DIR)/common.mk
