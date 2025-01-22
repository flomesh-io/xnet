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

func AddTracePortEntry(sysId SysID, tracePortKey *TracePortKey, tracePortVal *TracePortVal) error {
	tracePortKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_TRACE_PORT)
	if tracePortMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer tracePortMap.Close()
		return tracePortMap.Update(unsafe.Pointer(tracePortKey), unsafe.Pointer(tracePortVal), ebpf.UpdateAny)
	} else {
		return err
	}
}

func DelTracePortEntry(sysId SysID, tracePortKey *TracePortKey) error {
	tracePortKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_TRACE_PORT)
	if tracePortMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer tracePortMap.Close()
		err = tracePortMap.Delete(unsafe.Pointer(tracePortKey))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	} else {
		return err
	}
}

func ShowTracePortEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_TRACE_PORT)
	tracePortMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer tracePortMap.Close()

	tracePortKey := new(TracePortKey)
	tracePortVal := new(TracePortVal)
	it := tracePortMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(unsafe.Pointer(tracePortKey), unsafe.Pointer(tracePortVal)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%s,"value":%s}`, tracePortKey.String(), tracePortVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}

func (t *TracePortKey) String() string {
	return fmt.Sprintf(`{"sys": "%s","port": %d}`,
		_sys_(t.Sys), _port_(t.Port))
}

func (t *TracePortVal) String() string {
	return fmt.Sprintf(`{"trace_tc_ingress_on": "%t","trace_tc_egress_on": "%t"}`,
		_bool_(t.TcDir[TC_DIR_IGR]), _bool_(t.TcDir[TC_DIR_EGR]))
}
