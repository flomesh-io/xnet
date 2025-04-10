package maps

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

func InitProgEntries() error {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_PROG)
	progMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		return mapErr
	}
	defer progMap.Close()

	type ebpfProg struct {
		progKey  ProgKey
		progName string
	}

	progs := []ebpfProg{
		{
			progKey:  ProgKey(bpf.FSM_PASS_PROG_KEY),
			progName: bpf.FSM_PASS_PROG_NAME,
		},
		{
			progKey:  ProgKey(bpf.FSM_DROP_PROG_KEY),
			progName: bpf.FSM_DROP_PROG_NAME,
		},
		{
			progKey:  ProgKey(bpf.FSM_FLOW_PROG_KEY),
			progName: bpf.FSM_FLOW_PROG_NAME,
		},
	}

	for _, prog := range progs {
		pinnedFile = fs.GetPinningFile(prog.progName)
		if exists := util.Exists(pinnedFile); !exists {
			pinnedFile = fs.GetPinningFile(strings.TrimPrefix(prog.progName, bpf.FSM_PROG_NAME_PREFIX))
		}
		pinnedProg, progErr := ebpf.LoadPinnedProgram(pinnedFile, &ebpf.LoadPinOptions{})
		if progErr != nil {
			return progErr
		}
		defer pinnedProg.Close()

		progFD := pinnedProg.FD()
		if err := progMap.Update(prog.progKey, int32(progFD), ebpf.UpdateAny); err != nil {
			return err
		}
	}

	return nil
}

func ShowProgEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_PROG)
	progMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer progMap.Close()

	var progKey ProgKey
	var progFD ProgVal
	it := progMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(unsafe.Pointer(&progKey), unsafe.Pointer(&progFD)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%d,"value":%d}`, progKey, progFD)
	}
	fmt.Println()
	fmt.Println(`]`)
}
