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

func AddNatEntry(natKey *NatKey, natVal *NatVal) error {
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

func DelNatEntry(natKey *NatKey) error {
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

func GetNatEntry(natKey *NatKey) (*NatVal, error) {
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
	return fmt.Sprintf(`{"daddr": "%s","dport": %d,"proto": "%s","v6": %t,"tc_dir": "%s"}`,
		_ip_(t.Daddr[0]), _port_(t.Dport), _proto_(t.Proto), _bool_(t.V6), _tc_dir_(t.TcDir))
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
		sb.WriteString(fmt.Sprintf(`{"rmac": "%s","raddr": "%s","rport": %d,"inactive": %t}`,
			_mac_(ep.Rmac[:]), _ip_(ep.Raddr[0]), _port_(ep.Rport), _bool_(ep.Inactive)))
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func (t *NatVal) AddEp(raddr net.IP, rport uint16, rmac []uint8, inactive bool) (bool, error) {
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
				if inactive {
					t.Eps[idx].Inactive = 1
				} else {
					t.Eps[idx].Inactive = 0
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
	if inactive {
		t.Eps[t.EpCnt].Inactive = 1
	} else {
		t.Eps[t.EpCnt].Inactive = 0
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
		t.Eps[hitIdx].Inactive = 0
	} else {
		t.Eps[hitIdx].Raddr[0] = t.Eps[lastIdx].Raddr[0]
		t.Eps[hitIdx].Rport = t.Eps[lastIdx].Rport
		t.Eps[hitIdx].Inactive = t.Eps[lastIdx].Inactive

		t.Eps[lastIdx].Raddr[0] = 0
		t.Eps[lastIdx].Rport = 0
		t.Eps[lastIdx].Inactive = 0
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
