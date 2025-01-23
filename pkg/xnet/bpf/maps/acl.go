package maps

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/fs"
)

func AddAclEntry(sysId SysID, aclKey *AclKey, aclVal *AclVal) error {
	aclKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_ACL)
	if aclMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer aclMap.Close()
		return aclMap.Update(unsafe.Pointer(aclKey), unsafe.Pointer(aclVal), ebpf.UpdateAny)
	} else {
		return err
	}
}

func DelAclEntry(sysId SysID, aclKey *AclKey) error {
	aclKey.Sys = uint32(sysId)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_ACL)
	if aclMap, err := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{}); err == nil {
		defer aclMap.Close()
		err = aclMap.Delete(unsafe.Pointer(aclKey))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	} else {
		return err
	}
}

func GetAclEntries() map[AclKey]AclVal {
	items := make(map[AclKey]AclVal)
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_ACL)
	aclMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer aclMap.Close()
	aclKey := new(AclKey)
	aclVal := new(AclVal)
	it := aclMap.Iterate()
	for it.Next(unsafe.Pointer(aclKey), unsafe.Pointer(aclVal)) {
		items[*aclKey] = *aclVal
	}
	return items
}

func ShowAclEntries() {
	pinnedFile := fs.GetPinningFile(bpf.FSM_MAP_NAME_ACL)
	aclMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer aclMap.Close()
	aclKey := new(AclKey)
	aclVal := new(AclVal)
	it := aclMap.Iterate()
	first := true
	fmt.Println(`[`)
	for it.Next(unsafe.Pointer(aclKey), unsafe.Pointer(aclVal)) {
		if first {
			first = false
		} else {
			fmt.Println(`,`)
		}
		fmt.Printf(`{"key":%s,"value":%s}`, aclKey.String(), aclVal.String())
	}
	fmt.Println()
	fmt.Println(`]`)
}

func (t *AclKey) String() string {
	return fmt.Sprintf(`{"sys": "%s","addr": "%s","port": %d,"proto": "%s"}`,
		_sys_(t.Sys), _ip_(t.Addr[0]), _port_(t.Port), _proto_(t.Proto))
}

func (t *AclVal) String() string {
	return fmt.Sprintf(`{"acl": "%s", "id": %d, "flag": %d}`,
		_acl_(t.Acl), t.Flag, t.Id)
}
