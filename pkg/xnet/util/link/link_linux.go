package link

/*
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <linux/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

static int set_dev_up(const char *ifname, bool up)
{
  struct ifreq ifr;
  int fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ifr.ifr_ifindex = if_nametoindex(ifname);

  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }
  if (up && !(ifr.ifr_flags & IFF_UP)) {
    ifr.ifr_flags |= IFF_UP;
  } else if (!up && ifr.ifr_flags & IFF_UP) {
    ifr.ifr_flags &= ~IFF_UP;
  } else {
    close(fd);
    return 0;
  }

  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

static int set_up_tap_dev(const char *ifname) {
  int fd;
  int ret;
  struct ifreq ifr;
  char *dev = "/dev/net/tun";

  if ((fd = open(dev, O_RDWR)) < 0 ) {
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

  if ((ret = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    close(fd);
    return ret;
  }

  if ((ret = ioctl(fd, TUNSETPERSIST, 1)) < 0) {
    close(fd);
    return ret;
  }

  set_dev_up(ifname, 1);

  return 0;
}

*/
import "C"
import (
	"unsafe"
)

func linkTapAdd(ifName string) int {
	ifStr := C.CString(ifName)
	ret := C.set_up_tap_dev(ifStr)
	C.free(unsafe.Pointer(ifStr))
	return int(ret)
}
