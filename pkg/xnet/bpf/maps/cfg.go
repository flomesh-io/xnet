package maps

import (
	"fmt"
	"strconv"
	"strings"

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
		err = cfgMap.Lookup(&cfgKey, cfgVal)
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
		return cfgMap.Update(&cfgKey, cfgVal, ebpf.UpdateAny)
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
	for it.Next(cfgKey, cfgVal) {
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
	_write_(&sb, `{"flags":{`)
	_write_(&sb, fmt.Sprintf(`"IPv4":{"magic":"%X", "mask":"%064s",`, t.Ipv4.Flags, strconv.FormatUint(t.Ipv4.Flags, 2)))
	for flag, name := range flagNames {
		if flag > 0 {
			_write_(&sb, `,`)
		}
		_write_(&sb, fmt.Sprintf(`"%s": %t`, name, _bool_(t.IPv4().Get(uint8(flag)))))
	}
	_write_(&sb, `},`)
	_write_(&sb, fmt.Sprintf(`"IPv6":{"magic":"%X", "mask":"%064s",`, t.Ipv6.Flags, strconv.FormatUint(t.Ipv6.Flags, 2)))
	for flag, name := range flagNames {
		if flag > 0 {
			_write_(&sb, `,`)
		}
		_write_(&sb, fmt.Sprintf(`"%s": %t`, name, _bool_(t.IPv6().Get(uint8(flag)))))
	}
	_write_(&sb, `}`)
	_write_(&sb, `}}`)
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
