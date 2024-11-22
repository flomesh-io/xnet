package maps

import "fmt"

func (t *FlowKey) String() string {
	return fmt.Sprintf(`{"daddr": "%s","saddr": "%s","dport": %d,"sport": %d,"proto": "%s","v6": %t}`,
		_ip_(t.Daddr[0]), _ip_(t.Saddr[0]), _port_(t.Dport), _port_(t.Sport), _proto_(t.Proto), _bool_(t.V6))
}
