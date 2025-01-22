package maps

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

func AddNatEntry(sysId SysID, natKey *NatKey, natVal *NatVal) error {
	natKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_NAT)
	if natMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer natMap.Close()
		if natVal.EpCnt > 0 {
			return natMap.Update(unsafe.Pointer(natKey), unsafe.Pointer(natVal), ebpf.UpdateAny)
		}
		err = natMap.Delete(unsafe.Pointer(natKey))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	} else {
		return err
	}
}

func DelNatEntry(sysId SysID, natKey *NatKey) error {
	natKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_NAT)
	if natMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer natMap.Close()
		err = natMap.Delete(unsafe.Pointer(natKey))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	} else {
		return err
	}
}

func GetNatEntry(sysId SysID, natKey *NatKey) (*NatVal, error) {
	natKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_NAT)
	if natMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer natMap.Close()
		natVal := new(NatVal)
		err = natMap.Lookup(unsafe.Pointer(natKey), unsafe.Pointer(natVal))
		return natVal, err
	} else {
		return nil, err
	}
}

func (t *NatKey) String() string {
	return fmt.Sprintf(`{"sys": "%s","daddr": "%s","dport": %d,"proto": "%s","v6": %t,"tc_dir": "%s"}`,
		_sys_(t.Sys), _ip_(t.Daddr[0]), _port_(t.Dport), _proto_(t.Proto), _bool_(t.V6), _tc_dir_(t.TcDir))
}

func (t *NatVal) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`{"ep_sel": %d,"ep_cnt": %d,"eps": [`, t.EpSel, t.EpCnt))
	for idx, ep := range t.Eps {
		if idx >= int(t.EpCnt) {
			break
		}
		if idx > 0 {
			sb.WriteString(`,`)
		}
		sb.WriteString(fmt.Sprintf(`{"rmac": "%s","raddr": "%s","rport": %d,"ofi": %d,"oflags": %d,"omac_set": %t,"omac": "%s","active": %t}`,
			_mac_(ep.Rmac[:]), _ip_(ep.Raddr[0]), _port_(ep.Rport), ep.Ofi, ep.Oflags, _bool_(ep.OmacSet), _mac_(ep.Omac[:]), _bool_(ep.Active)))
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func (t *NatVal) AddEp(raddr net.IP, rport uint16, rmac []uint8, ofi, oflags uint32, omac []uint8, active bool) (bool, error) {
	ipNb, err := util.IPv4ToInt(raddr)
	if err != nil {
		return false, err
	}
	portBe := util.HostToNetShort(rport)
	if t.EpCnt > 0 {
		for idx := range t.Eps {
			if t.Eps[idx].Raddr[0] == ipNb && t.Eps[idx].Rport == portBe {
				for n := range t.Eps[idx].Rmac {
					t.Eps[idx].Rmac[n] = rmac[n]
				}
				t.Eps[idx].Ofi = ofi
				t.Eps[idx].Oflags = oflags
				if len(omac) > 0 {
					t.Eps[idx].OmacSet = 0
					for n := range t.Eps[idx].Omac {
						t.Eps[idx].Omac[n] = omac[n]
						if omac[n] > 0 {
							t.Eps[idx].OmacSet = 1
						}
					}
				} else {
					t.Eps[idx].OmacSet = 0
				}
				if active {
					t.Eps[idx].Active = 1
				} else {
					t.Eps[idx].Active = 0
				}
				return true, nil
			}
		}
	}

	if t.EpCnt >= uint16(len(t.Eps)) {
		return false, nil
	}

	t.Eps[t.EpCnt].Raddr[0] = ipNb
	t.Eps[t.EpCnt].Rport = portBe
	for n := range t.Eps[t.EpCnt].Rmac {
		t.Eps[t.EpCnt].Rmac[n] = rmac[n]
	}
	t.Eps[t.EpCnt].Ofi = ofi
	t.Eps[t.EpCnt].Oflags = oflags
	if len(omac) > 0 {
		t.Eps[t.EpCnt].OmacSet = 0
		for n := range t.Eps[t.EpCnt].Omac {
			t.Eps[t.EpCnt].Omac[n] = omac[n]
			if omac[n] > 0 {
				t.Eps[t.EpCnt].OmacSet = 1
			}
		}
	} else {
		t.Eps[t.EpCnt].OmacSet = 0
	}
	if active {
		t.Eps[t.EpCnt].Active = 1
	} else {
		t.Eps[t.EpCnt].Active = 0
	}
	t.EpCnt++
	return true, nil
}

func (t *NatVal) DelEp(raddr net.IP, rport uint16) error {
	ipNb, err := util.IPv4ToInt(raddr)
	if err != nil {
		return err
	}

	if t.EpCnt == 0 {
		return nil
	}

	portBe := util.HostToNetShort(rport)
	hitIdx := -1
	lastIdx := int(t.EpCnt - 1)

	for idx := range t.Eps {
		if t.Eps[idx].Raddr[0] == ipNb && t.Eps[idx].Rport == portBe {
			hitIdx = idx
			break
		}
	}

	if hitIdx == -1 {
		return nil
	}

	if hitIdx == lastIdx {
		t.Eps[hitIdx].Raddr[0] = 0
		t.Eps[hitIdx].Rport = 0
		t.Eps[hitIdx].Active = 0
	} else {
		t.Eps[hitIdx].Raddr[0] = t.Eps[lastIdx].Raddr[0]
		t.Eps[hitIdx].Rport = t.Eps[lastIdx].Rport
		t.Eps[hitIdx].Active = t.Eps[lastIdx].Active

		t.Eps[lastIdx].Raddr[0] = 0
		t.Eps[lastIdx].Rport = 0
		t.Eps[lastIdx].Active = 0
	}

	t.EpCnt--

	return nil
}

func ShowNatEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_NAT)
	natMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer natMap.Close()

	natKey := new(NatKey)
	natVal := new(NatVal)
	it := natMap.Iterate()
	first := true
	fmt.Println("[")
	for it.Next(unsafe.Pointer(natKey), unsafe.Pointer(natVal)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%s,"value":%s}`, natKey.String(), natVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}
