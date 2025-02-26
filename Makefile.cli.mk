#!make

SHELL = bash

CC = gcc
CLANG = clang

BASE_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
INC_DIR = $(abspath ${BASE_DIR})/kern/include
SRC_DIR = $(abspath ${BASE_DIR})/kern/src
BIN_DIR = $(abspath ${BASE_DIR})/bin
BPF_DIR = $(abspath ${BASE_DIR})/kern

XNET_KERN_OUT = xnet.kern.o
XNET_KERN_SRC = $(patsubst %.o,%.c,${XNET_KERN_OUT})

BPF_CFLAGS = \
	-O2 \
	-D__KERNEL__ \
	-Wno-unused-value     \
	-Wno-pointer-sign     \
	-Wno-compare-distinct-pointer-types

BPF_EXTRA_CFLAGS ?=

CGO_CFLAGS_DYN = "-I. -I./kern/include -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

BPF_LOAD_FLAGS ?= $(shell if bpftool --version | grep libbpf_strict > /dev/null 2>&1; then echo --legacy; fi)

BPF_FS  = /sys/fs/bpf

.PHONY: c-fmt
c-fmt:
	@find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \; > /dev/null 2>&1 || true

.PHONY: bpf-fs
bpf-fs:
	@mountpoint -q ${BPF_FS} || mount -t bpf bpf ${BPF_FS}

.PHONY: debug-fs
debug-fs:
	@mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug

.PHONY: go-fmt
go-fmt:
	go fmt ./...

.PHONY: go-mod-tidy
go-mod-tidy:
	./scripts/go-mod-tidy.sh

.PHONY: go-generate
go-generate: export BPF_CFLAGS := $(BPF_CFLAGS)
go-generate: export BPF_INC_DIR := $(INC_DIR)
go-generate: export BPF_SRC_DIR := $(SRC_DIR)
go-generate:
	@go generate .gen/xnet.go

.PHONY: go-test-coverage
go-test-coverage:
	./scripts/test-w-coverage.sh

.PHONY: build-cli
build-cli:
	@go build -o ${BIN_DIR}/xnat cmd/xnat/*
	@go build -o ${BIN_DIR}/xcni cmd/xcni/*
	@go build -o ${BIN_DIR}/xctr cmd/xctr/*

.PHONY: build-bpf
build-bpf: bpf-clean bpf-fmt bpf-build

.PHONY: bpf-fmt
bpf-fmt: c-fmt

.PHONY: bpf-build
bpf-build: ${BIN_DIR}/${XNET_KERN_OUT}

${BIN_DIR}/${XNET_KERN_OUT}: ${SRC_DIR}/${XNET_KERN_SRC}
	@clang -I${INC_DIR} ${BPF_CFLAGS} ${BPF_EXTRA_CFLAGS} -emit-llvm -c -g $< -o - | llc -march=bpf -filetype=obj -o $@

.PHONY: bpf-clean
bpf-clean:
	@rm -f ${BIN_DIR}/${XNET_KERN_OUT}

.PHONY: load
load: debug-fs bpf-fs c-fmt bpf-build
	@bpftool prog loadall ${BIN_DIR}/${XNET_KERN_OUT} /sys/fs/bpf/fsm pinmaps /sys/fs/bpf/fsm ${BPF_LOAD_FLAGS} > /dev/null 2>&1

.PHONY: clean
clean: bpf-clean
	@rm -rf /sys/fs/bpf/fsm

.PHONY: kern-trace
kern-trace:
	@clear
	@sudo cat /sys/kernel/debug/tracing/trace_pipe|grep bpf_trace_printk