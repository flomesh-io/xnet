package maps

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

func AddUDPFlowEntry(sysId SysID, flowKey *FlowKey, flowVal *FlowUDPVal) error {
	flowKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_UDP_FLOW)
	if flowMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer flowMap.Close()
		return flowMap.Update(unsafe.Pointer(flowKey), unsafe.Pointer(flowVal), ebpf.UpdateAny)
	} else {
		return err
	}
}

func DelUDPFlowEntry(sysId SysID, flowKey *FlowKey) error {
	flowKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_UDP_FLOW)
	if flowMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer flowMap.Close()
		return flowMap.Delete(unsafe.Pointer(flowKey))
	} else {
		return err
	}
}

func FlushIdleUDPFlowEntries(sysId SysID, idleSeconds, batchSize int) (int, error) {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_UDP_FLOW)
	flowMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer flowMap.Close()

	natOptOn := false
	optWithLocalAddrOn := false
	optWithLocalPortOn := false
	var optMap *ebpf.Map
	var idleOptKeys []OptKey
	if cfg, err := GetXNetCfg(sysId); err != nil {
		return 0, nil
	} else if natOptOn = cfg.IsSet(CfgFlagOffsetIPv4UDPNatOptOn); natOptOn {
		pinnedFile = fs.GetPinningFile(bpf.FSM_MAP_NAME_UDP_OPT)
		optMap, mapErr = ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
		if mapErr != nil {
			log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
		}
		defer optMap.Close()

		if cfg.IsSet(CfgFlagOffsetIPv4UDPNatOptWithLocalAddrOn) {
			optWithLocalAddrOn = true
		}
		if cfg.IsSet(CfgFlagOffsetIPv4UDPNatOptWithLocalPortOn) {
			optWithLocalPortOn = true
		}
	}

	uptimeDuration := time.Duration(util.Uptime()) * time.Second
	idleDuration := time.Duration(idleSeconds) * time.Second

	idleFlowKeys := make([]FlowKey, batchSize)
	idleFlowIdx := 0

	flowKey := new(FlowKey)
	flowVal := new(FlowUDPVal)
	it := flowMap.Iterate()
	for it.Next(unsafe.Pointer(flowKey), unsafe.Pointer(flowVal)) {
		escapeDuration := uptimeDuration - time.Duration(flowVal.Atime)*time.Nanosecond
		if escapeDuration > idleDuration {
			idleFlowKeys[idleFlowIdx] = *flowKey
			if natOptOn && (flowVal.Nfs[TC_DIR_EGR]&NF_XNAT == NF_XNAT) {
				optKey := OptKey{}
				copy(optKey.Raddr[:], flowVal.Xnat.Xaddr[:])
				if optWithLocalAddrOn {
					copy(optKey.Laddr[:], flowVal.Xnat.Raddr[:])
				}
				optKey.Rport = flowVal.Xnat.Xport
				if optWithLocalPortOn {
					optKey.Lport = flowVal.Xnat.Rport
				}

				optKey.Proto = flowKey.Proto
				optKey.V6 = flowKey.V6
				idleOptKeys = append(idleOptKeys, optKey)
			}

			idleFlowIdx++
			if idleFlowIdx >= batchSize {
				break
			}
		}
	}

	if idleFlowIdx > 0 {
		if natOptOn && len(idleOptKeys) > 0 {
			_, _ = optMap.BatchDelete(idleOptKeys[0:], &ebpf.BatchOptions{})
		}
		return flowMap.BatchDelete(idleFlowKeys[0:idleFlowIdx], &ebpf.BatchOptions{})
	}

	return 0, nil
}

func ShowUDPFlowEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_UDP_FLOW)
	flowMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer flowMap.Close()

	flowKey := new(FlowKey)
	flowVal := new(FlowUDPVal)
	it := flowMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(unsafe.Pointer(flowKey), unsafe.Pointer(flowVal)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%s,"value":%s}`, flowKey.String(), flowVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}

func (t *FlowUDPVal) String() string {
	return fmt.Sprintf(`{"flow_dir": "%s","do_trans": %t,"fin": %t,`+
		`"idle_duration": "%s",`+
		`"nfs": {"TC_DIR_IGR":"%s","TC_DIR_EGR":"%s"},`+
		`"xnat": {"xmac": "%s","rmac": "%s","xaddr": "%s","raddr": "%s","xport": %d,"rport": %d},`+
		`"trans": {`+
		`"udp": {`+
		`"conns": {`+
		`"pkts": %d`+
		`}`+
		`}`+
		`}`+
		`}`,
		_flow_dir_(t.FlowDir), _bool_(t.DoTrans), _bool_(t.Fin),
		_duration_(t.Atime),
		_nf_(t.Nfs[0]), _nf_(t.Nfs[1]),
		_mac_(t.Xnat.Xmac[:]), _mac_(t.Xnat.Rmac[:]),
		_ip_(t.Xnat.Xaddr[0]), _ip_(t.Xnat.Raddr[0]),
		_port_(t.Xnat.Xport), _port_(t.Xnat.Rport),
		t.Trans.Udp.Conns.Pkts,
	)
}
