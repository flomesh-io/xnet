package maps

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
)

func GetXNetCfg(sysId SysID) (*CfgVal, error) {
	cfgVal := new(CfgVal)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_CFG)
	if cfgMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer cfgMap.Close()
		cfgKey := CfgKey(sysId)
		err = cfgMap.Lookup(unsafe.Pointer(&cfgKey), unsafe.Pointer(cfgVal))
		return cfgVal, err
	} else {
		return nil, err
	}
}

func SetXNetCfg(sysId SysID, cfgVal *CfgVal) error {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_CFG)
	if cfgMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer cfgMap.Close()
		cfgKey := CfgKey(sysId)
		return cfgMap.Update(unsafe.Pointer(&cfgKey), unsafe.Pointer(cfgVal), ebpf.UpdateAny)
	} else {
		return err
	}
}

func ShowCfgEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_CFG)
	cfgMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer cfgMap.Close()

	cfgKey := new(CfgKey)
	cfgVal := new(CfgVal)
	it := cfgMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(unsafe.Pointer(cfgKey), unsafe.Pointer(cfgVal)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`%s`, cfgVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}

func (t *CfgVal) String() string {
	var sb strings.Builder
	sb.WriteString(`{"flags":{`)
	sb.WriteString(fmt.Sprintf(`"IPv4":{"mask":"%064s",`, strconv.FormatUint(t.Ipv4.Flags, 2)))
	for flag, name := range flagNames {
		if flag > 0 {
			sb.WriteString(`,`)
		}
		sb.WriteString(fmt.Sprintf(`"%s": %t`, name, _bool_(t.IPv4().Get(uint8(flag)))))
	}
	sb.WriteString(`},`)
	sb.WriteString(fmt.Sprintf(`"IPv6":{"mask":"%064s",`, strconv.FormatUint(t.Ipv6.Flags, 2)))
	for flag, name := range flagNames {
		if flag > 0 {
			sb.WriteString(`,`)
		}
		sb.WriteString(fmt.Sprintf(`"%s": %t`, name, _bool_(t.IPv6().Get(uint8(flag)))))
	}
	sb.WriteString(`}`)
	sb.WriteString(`}}`)
	return sb.String()
}

func (t *CfgVal) IPv4() *FlagT {
	return &t.Ipv4
}

func (t *CfgVal) IPv6() *FlagT {
	return &t.Ipv6
}

func (t *FlagT) Get(bit uint8) uint8 {
	bitMask := t.Flags >> bit
	return uint8(bitMask & 0x1)
}

func (t *FlagT) Set(bit uint8) {
	bitMask := uint64(1 << bit)
	t.Flags |= bitMask
}

func (t *FlagT) IsSet(bit uint8) bool {
	bitMask := t.Flags >> bit
	return uint8(bitMask&0x1) == 1
}

func (t *FlagT) Clear(bit uint8) {
	bitMask := uint64(1 << bit)
	t.Flags &= ^bitMask
}
