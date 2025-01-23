package route

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// See http://man7.org/linux/man-pages/man8/route.8.html
	file = "/proc/net/route"
)

func readRoutes() ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("can't access %s", file)
	}
	defer f.Close()

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("can't read %s", file)
	}

	return bytes, nil
}

func discoverGatewayOSSpecific() (iface string, ip net.IP, err error) {
	bytes, err := readRoutes()
	if err != nil {
		return "", nil, err
	}
	return parseLinuxGateway(bytes)
}

type linuxRouteStruct struct {
	// Name of interface
	Iface string

	// big-endian hex string
	Gateway string
}

func parseToLinuxRouteStruct(output []byte) (linuxRouteStruct, error) {
	// parseLinuxProcNetRoute parses the route file located at /proc/net/route
	// and returns the IP address of the default gateway. The default gateway
	// is the one with Destination value of 0.0.0.0.
	//
	// The Linux route file has the following format:
	//
	// $ cat /proc/net/route
	//
	// Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask
	// eno1    00000000    C900A8C0    0003    0   0   100 00000000    0   00
	// eno1    0000A8C0    00000000    0001    0   0   100 00FFFFFF    0   00
	const (
		sep              = "\t" // field separator
		destinationField = 1    // field containing hex destination address
		gatewayField     = 2    // field containing hex gateway address
		maskField        = 7    // field containing hex mask
	)
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header line
	if !scanner.Scan() {
		err := scanner.Err()
		if err == nil {
			return linuxRouteStruct{}, &ErrNoGateway{}
		}

		return linuxRouteStruct{}, err
	}

	for scanner.Scan() {
		row := scanner.Text()
		tokens := strings.Split(row, sep)
		if len(tokens) < 11 {
			return linuxRouteStruct{}, &ErrInvalidRouteFileFormat{row: row}
		}

		// The default interface is the one that's 0 for both destination and mask.
		if !(tokens[destinationField] == "00000000" && tokens[maskField] == "00000000") {
			continue
		}

		return linuxRouteStruct{
			Iface:   tokens[0],
			Gateway: tokens[2],
		}, nil
	}
	return linuxRouteStruct{}, &ErrNoGateway{}
}

func parseLinuxGateway(output []byte) (string, net.IP, error) {
	parsedStruct, err := parseToLinuxRouteStruct(output)
	if err != nil {
		return "", nil, err
	}

	// cast hex address to uint32
	d, err := strconv.ParseUint(parsedStruct.Gateway, 16, 32)
	if err != nil {
		return "", nil, fmt.Errorf(
			"parsing default interface address field hex %q: %w",
			parsedStruct.Gateway,
			err,
		)
	}
	// make net.IP address from uint32
	ipd32 := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ipd32, uint32(d))
	return parsedStruct.Iface, ipd32, nil
}

func GetDefaultGatewayAddr(iface net.Interface) (net.IP, error) {
	nlLink, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return nil, err
	}
	nlHandle, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}

	retries := 3
	for retries > 0 {
		routes, err := nlHandle.RouteList(nlLink, syscall.AF_INET)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				log.Debug().Msgf("listing routes for interface %s, family %d hit EINTR. Retrying", nlLink.Attrs().Name, syscall.AF_INET)
				retries--
				continue
			}
		}

		for _, route := range routes {
			if route.Gw != nil && route.Dst != nil && route.Dst.IP.IsUnspecified() {
				return route.Gw, nil
			}
		}
	}
	return nil, nil
}
