package maps

import "fmt"

func (t *FlowKey) String() string {
	return fmt.Sprintf(`{"sys": "%s","daddr": "%s","saddr": "%s","dport": %d,"sport": %d,"proto": "%s","v6": %t}`,
		_sys_(t.Sys), _ip_(t.Daddr), _ip_(t.Saddr), _port_(t.Dport), _port_(t.Sport), _proto_(t.Proto), _bool_(t.V6))
}
