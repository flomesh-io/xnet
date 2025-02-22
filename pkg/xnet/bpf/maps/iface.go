package maps

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
)

func AddIFaceEntry(ifaceKey *IFaceKey, ifaceVal *IFaceVal) error {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_IFS)
	if ifaceMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer ifaceMap.Close()
		return ifaceMap.Update(ifaceKey, ifaceVal, ebpf.UpdateAny)
	} else {
		return err
	}
}

func DelIFaceEntry(ifaceKey *IFaceKey) error {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_IFS)
	if ifaceMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer ifaceMap.Close()
		err = ifaceMap.Delete(ifaceKey)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	} else {
		return err
	}
}

func GetIFaceEntry(ifaceKey *IFaceKey) (*IFaceVal, error) {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_IFS)
	if natMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer natMap.Close()
		ifaceVal := new(IFaceVal)
		err = natMap.Lookup(ifaceKey, ifaceVal)
		return ifaceVal, err
	} else {
		return nil, err
	}
}

func GetIFaceEntries() map[IFaceKey]IFaceVal {
	items := make(map[IFaceKey]IFaceVal)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_IFS)
	ifaceMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer ifaceMap.Close()
	ifaceKey := new(IFaceKey)
	ifaceVal := new(IFaceVal)
	it := ifaceMap.Iterate()
	for it.Next(ifaceKey, ifaceVal) {
		items[*ifaceKey] = *ifaceVal
	}
	return items
}

func ShowIFaceEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_IFS)
	ifaceMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer ifaceMap.Close()

	ifaceKey := new(IFaceKey)
	ifaceVal := new(IFaceVal)
	it := ifaceMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(ifaceKey, ifaceVal) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%s,"value":%s}`, ifaceKey.String(), ifaceVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}

func (t *IFaceKey) String() string {
	return fmt.Sprintf(`{"name": "%s"}`, string(t.Name[0:t.Len]))
}

func (t *IFaceVal) String() string {
	return fmt.Sprintf(`{"ifi": "%d","addr": "%s","mac": "%s","xmac": "%s"}`,
		t.Ifi, _ip_(t.Addr), _mac_(t.Mac[:]), _mac_(t.Xmac[:]))
}
