# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

BUILD_DIR ?= build
RUNNER := $(BUILD_DIR)/bin/bpf_conformance_runner
LIBBPF_PLUGIN := $(BUILD_DIR)/bin/libbpf_plugin
ALIVIO_PLUGIN := $(BUILD_DIR)/bin/alivio_plugin
PREVAIL_PLUGIN := $(BUILD_DIR)/bin/prevail_plugin

ALIVIO_DIR := $(CURDIR)/external/alivio
PREVAIL_DIR := $(CURDIR)/external/prevail
PREVAIL_BUILD_DIR ?= $(PREVAIL_DIR)/build
ALIVIO ?= $(ALIVIO_DIR)/target/release/alivio
PREVAIL ?= $(PREVAIL_DIR)/bin/prevail
PREVAIL_CMAKE_OPTIONS ?= -DCMAKE_BUILD_TYPE=Release
SUDO ?= sudo

ifeq ($(shell uname -s),Darwin)
HOMEBREW_PREFIX ?= $(shell brew --prefix)
PREVAIL_BUILD_ENV ?= CPATH=$(HOMEBREW_PREFIX)/include LIBRARY_PATH=$(HOMEBREW_PREFIX)/lib CMAKE_PREFIX_PATH=$(HOMEBREW_PREFIX)
PREVAIL_CMAKE_OPTIONS += -DCMAKE_C_COMPILER=$(HOMEBREW_PREFIX)/opt/llvm/bin/clang -DCMAKE_CXX_COMPILER=$(HOMEBREW_PREFIX)/opt/llvm/bin/clang++
else
PREVAIL_BUILD_ENV ?=
endif

ifneq ($(strip $(TEST)),)
TEST_INPUT := --test_file_path "$(abspath $(TEST))"
else
TEST_INPUT := --test_file_directory "$(CURDIR)/verifier_tests"
endif

VERIFIER_OPTIONS := \
	$(TEST_INPUT) \
	--cpu_version v4 \
	--verifier true \
	--xdp_prolog true

.DEFAULT_GOAL := all

.PHONY: all clean cleanall test linux alivio prevail ensure-alivio ensure-prevail

all:
	cmake -S . -B $(BUILD_DIR)
	cmake --build $(BUILD_DIR)

clean:
	cmake --build $(BUILD_DIR) --target clean

cleanall:
	cmake -E remove_directory "$(BUILD_DIR)"

test:
	cmake --build $(BUILD_DIR) --target test --

linux: all
	$(SUDO) "$(RUNNER)" \
		$(VERIFIER_OPTIONS) \
		--exclude_regex "imm-" \
		--plugin_path "$(LIBBPF_PLUGIN)" \
		--plugin_options="--verify-only"

ensure-alivio:
	@if [ ! -x "$(ALIVIO)" ]; then \
		echo "Building Alivio from $(ALIVIO_DIR)"; \
		cargo build --release --manifest-path "$(ALIVIO_DIR)/Cargo.toml"; \
	fi
	@test -x "$(ALIVIO)" || { echo "Alivio executable not found at $(ALIVIO)" >&2; exit 1; }

ensure-prevail:
	@if [ ! -x "$(PREVAIL)" ]; then \
		echo "Building Prevail from $(PREVAIL_DIR)"; \
		$(PREVAIL_BUILD_ENV) cmake -S "$(PREVAIL_DIR)" -B "$(PREVAIL_BUILD_DIR)" $(PREVAIL_CMAKE_OPTIONS); \
		$(PREVAIL_BUILD_ENV) cmake --build "$(PREVAIL_BUILD_DIR)" --target prevail-cli; \
	fi
	@test -x "$(PREVAIL)" || { echo "Prevail executable not found at $(PREVAIL)" >&2; exit 1; }

alivio: all ensure-alivio
	"$(RUNNER)" \
		$(VERIFIER_OPTIONS) \
		--elf true \
		--plugin_path "$(ALIVIO_PLUGIN)" \
		--plugin_options="--alivio $(ALIVIO)"

prevail: all ensure-prevail
	"$(RUNNER)" \
		$(VERIFIER_OPTIONS) \
		--elf true \
		--plugin_path "$(PREVAIL_PLUGIN)" \
		--plugin_options="--prevail $(PREVAIL)"
