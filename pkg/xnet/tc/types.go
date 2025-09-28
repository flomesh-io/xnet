package tc

// Constants to define the direction
const (
	TC_KIND_BPF    = "bpf"
	TC_KIND_CLSACT = "clsact"

	TC_BPF_FILTER_PREFIX = "xnet"

	HandleIngress uint32 = 0xFFFFFFF2
	HandleEgress  uint32 = 0xFFFFFFF3

	// TC filter constants
	TCFilterPriority uint32 = 66
	TCProtocol       uint32 = 0x0300
	TCBPFFlags       uint32 = 0x1
)
