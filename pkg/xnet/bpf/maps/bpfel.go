package maps

type FsmAclKeyT struct {
	Sys   uint32
	Addr  [4]uint32
	Port  uint16
	Proto uint8
}

type FsmAclOpT struct {
	Acl  uint8
	Flag uint8
	Id   uint16
}

type FsmCfgT struct{ Flags uint64 }

type FsmFlowTOpT struct {
	Lock    struct{ Val uint32 }
	FlowDir uint8
	Fin     uint8
	Nfs     [2]uint8
	Atime   uint64
	Xnat    struct {
		Xmac  [6]uint8
		Rmac  [6]uint8
		Xaddr [4]uint32
		Raddr [4]uint32
		Xport uint16
		Rport uint16
	}
	Trans struct {
		Tcp struct {
			Conns [2]struct {
				Seq        uint32
				PrevSeq    uint32
				PrevAckSeq uint32
				InitAcks   uint32
			}
			State  uint8
			FinDir uint8
			_      [2]byte
		}
	}
	DoTrans uint8
	_       [3]byte
}

type FsmFlowUOpT struct {
	Lock    struct{ Val uint32 }
	FlowDir uint8
	Fin     uint8
	Nfs     [2]uint8
	Atime   uint64
	Xnat    struct {
		Xmac  [6]uint8
		Rmac  [6]uint8
		Xaddr [4]uint32
		Raddr [4]uint32
		Xport uint16
		Rport uint16
	}
	Trans struct {
		Udp struct{ Conns struct{ Pkts uint32 } }
		_   [32]byte
	}
	DoTrans uint8
	_       [3]byte
}

type FsmFlowT struct {
	Sys   uint32
	Daddr [4]uint32
	Saddr [4]uint32
	Dport uint16
	Sport uint16
	Proto uint8
	V6    uint8
}

type FsmIfInfoT struct {
	Ifi  uint32
	Addr [4]uint32
	Mac  [6]uint8
}

type FsmIfNameT struct {
	Len  uint8
	Name [16]uint8
}

type FsmNatKeyT struct {
	Sys   uint32
	Daddr [4]uint32
	Dport uint16
	Proto uint8
	V6    uint8
	TcDir uint8
}

type FsmNatOpT struct {
	Lock  struct{ Val uint32 }
	EpSel uint16
	EpCnt uint16
	Eps   [128]struct {
		Raddr   [4]uint32
		Rport   uint16
		Rmac    [6]uint8
		Ofi     uint32
		Oflags  uint32
		Omac    [6]uint8
		OmacSet uint8
		Active  uint8
	}
}

type FsmOptKeyT struct {
	Sys   uint32
	Laddr [4]uint32
	Raddr [4]uint32
	Lport uint16
	Rport uint16
	Proto uint8
	V6    uint8
}

type FsmTrIpT struct {
	Sys  uint32
	Addr [4]uint32
}

type FsmTrOpT struct{ TcDir [2]uint8 }

type FsmTrPortT struct {
	Sys  uint32
	Port uint16
}
