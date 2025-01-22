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

func AddTCPOptEntry(sysId SysID, optKey *OptKey, optVal *OptVal) error {
	optKey.Sys = uint32(sysId)
	return addOptEntry(bpf.FSM_MAP_NAME_TCP_OPT, optKey, optVal)
}

func DelTCPOptEntry(sysId SysID, optKey *OptKey) error {
	optKey.Sys = uint32(sysId)
	return delOptEntry(bpf.FSM_MAP_NAME_TCP_OPT, optKey)
}

func ShowTCPOptEntries() {
	showOptEntries(bpf.FSM_MAP_NAME_TCP_OPT)
}

func AddUDPOptEntry(sysId SysID, optKey *OptKey, optVal *OptVal) error {
	optKey.Sys = uint32(sysId)
	return addOptEntry(bpf.FSM_MAP_NAME_UDP_OPT, optKey, optVal)
}

func DelUDPOptEntry(sysId SysID, optKey *OptKey) error {
	optKey.Sys = uint32(sysId)
	return delOptEntry(bpf.FSM_MAP_NAME_UDP_OPT, optKey)
}

func addOptEntry(emap string, optKey *OptKey, optVal *OptVal) error {
	pinnedFile := fs.GetPinningFile(emap)
	if optMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer optMap.Close()
		return optMap.Update(unsafe.Pointer(optKey), unsafe.Pointer(optVal), ebpf.UpdateAny)
	} else {
		return err
	}
}

func ShowUDPOptEntries() {
	showOptEntries(bpf.FSM_MAP_NAME_UDP_OPT)
}

func delOptEntry(emap string, optKey *OptKey) error {
	pinnedFile := fs.GetPinningFile(emap)
	if optMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer optMap.Close()
		err = optMap.Delete(unsafe.Pointer(optKey))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	} else {
		return err
	}
}

func showOptEntries(emap string) {
	pinnedFile := fs.GetPinningFile(emap)
	optMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer optMap.Close()

	optKey := new(OptKey)
	optVal := new(OptVal)
	it := optMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(unsafe.Pointer(optKey), unsafe.Pointer(optVal)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%s,"value":%s}`, optKey.String(), optVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}

func (t *OptKey) String() string {
	return fmt.Sprintf(`{"sys": "%s","local_addr": "%s","remote_addr": "%s","local_port": %d,"remote_port": %d,"proto": "%s","v6": %t}`,
		_sys_(t.Sys), _ip_(t.Laddr[0]), _ip_(t.Raddr[0]), _port_(t.Lport), _port_(t.Rport), _proto_(t.Proto), _bool_(t.V6))
}

func (t *OptVal) String() string {
	return fmt.Sprintf(`{"daddr": "%s","saddr": "%s","dport": %d,"sport": %d,"proto": "%s","v6": %t}`,
		_ip_(t.Daddr[0]), _ip_(t.Saddr[0]), _port_(t.Dport), _port_(t.Sport), _proto_(t.Proto), _bool_(t.V6))
}
