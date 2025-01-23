package maps

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
)

func AddTraceIPEntry(sysId SysID, traceIPKey *TraceIPKey, traceIPVal *TraceIPVal) error {
	traceIPKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_TRACE_IP)
	if traceIPMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer traceIPMap.Close()
		return traceIPMap.Update(unsafe.Pointer(traceIPKey), unsafe.Pointer(traceIPVal), ebpf.UpdateAny)
	} else {
		return err
	}
}

func DelTraceIPEntry(sysId SysID, traceIPKey *TraceIPKey) error {
	traceIPKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_TRACE_IP)
	if traceIPMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer traceIPMap.Close()
		err = traceIPMap.Delete(unsafe.Pointer(traceIPKey))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	} else {
		return err
	}
}

func ShowTraceIPEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_TRACE_IP)
	traceIPMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer traceIPMap.Close()

	traceIPKey := new(TraceIPKey)
	traceIPVal := new(TraceIPVal)
	it := traceIPMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(unsafe.Pointer(traceIPKey), unsafe.Pointer(traceIPVal)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%s,"value":%s}`, traceIPKey.String(), traceIPVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}

func (t *TraceIPKey) String() string {
	return fmt.Sprintf(`{"sys": "%s","addr": "%s"}`,
		_sys_(t.Sys), _ip_(t.Addr[0]))
}

func (t *TraceIPVal) String() string {
	return fmt.Sprintf(`{"trace_tc_ingress_on": "%t","trace_tc_egress_on": "%t"}`,
		_bool_(t.TcDir[TC_DIR_IGR]), _bool_(t.TcDir[TC_DIR_EGR]))
}
