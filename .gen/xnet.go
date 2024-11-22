package gen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS Fsm $BPF_SRC_DIR/xnet.kern.c -- -I $BPF_INC_DIR
