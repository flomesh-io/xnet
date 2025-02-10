#!make
SHELL = bash

CTR_ETH  ?= ens33
CTR_ETH_IP4 ?= $(shell ip -j -4 a show dev $(CTR_ETH) | jq -r .[0].addr_info[0].local)
CTR_CNI1_MAC ?= $(shell ip -j a show dev cni1 | jq -r .[0].address)
CTR_CNI2_MAC ?= $(shell ip -j a show dev cni2 | jq -r .[0].address)
CTR_CNI1_IFI ?= $(shell ip -j a show dev cni1 | jq -r .[0].ifindex)
CTR_CNI2_IFI ?= $(shell ip -j a show dev cni2 | jq -r .[0].ifindex)

WORK_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ROOT_DIR :=  $(abspath $(WORK_DIR)/../..)
BIN_DIR :=  $(abspath $(WORK_DIR)/../../bin)

.PHONY: mesh-up
mesh-up: mesh-reset
	@echo 1 > /proc/sys/net/ipv4/ip_forward
	@echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	@sudo iptables -t nat -A POSTROUTING -o ${CTR_ETH} -j MASQUERADE
	@# Configure load-balancer end-point v1
	@sudo ip netns add v1
	@sudo ip link add cni1 type veth peer name eth0 netns v1
	@sudo ip link set cni1 up
	@sudo ip addr add 10.0.0.1/24 dev cni1
	@sudo ip addr add 10::1/124 dev cni1
	@sudo ip -n v1 link set eth0 up
	@sudo ip netns exec v1 ifconfig eth0 10.0.0.2/24 up
	@sudo ip netns exec v1 ip addr add 10::2/124 dev eth0
	@sudo ip netns exec v1 ip route add default via 10.0.0.1
	@sudo ip netns exec v1 ip -6 route add default via 10::1
	@sudo ip netns exec v1 ifconfig lo up
	@# Configure load-balancer end-point v1 Done
	@# Configure load-balancer end-point v2
	@sudo ip netns add v2
	@sudo ip link add cni2 type veth peer name eth0 netns v2
	@sudo ip link set cni2 up
	@sudo ip addr add 20.0.0.1/24 dev cni2
	@sudo ip addr add 20::1/124 dev cni2
	@sudo ip -n v2 link set eth0 up
	@sudo ip netns exec v2 ifconfig eth0 20.0.0.2/24 up
	@sudo ip netns exec v2 ip addr add 20::2/124 dev eth0
	@sudo ip netns exec v2 ip route add default via 20.0.0.1
	@sudo ip netns exec v2 ip -6 route add default via 20::1
	@sudo ip netns exec v2 ifconfig lo up
	@# Configure load-balancer end-point v2 Done

.PHONY: mesh-reset
mesh-reset:
	@sudo ip link del cni1 > /dev/null 2>&1 || true
	@sudo ip netns del v1 > /dev/null 2>&1 || true
	@sudo ip link del cni2 > /dev/null 2>&1 || true
	@sudo ip netns del v2 > /dev/null 2>&1 || true
	@sudo iptables -t nat -F || true
	@sudo killall pipy > /dev/null 2>&1 || true

.PHONY: e4lb-up
e4lb-up: mesh-up
	@#sudo ip netns exec v1 ip addr add 18.18.18.18/32 dev lo
	@#sudo ip r add 18.18.18.18/32 dev cni1
	@#sudo iptables -t nat -F || true

.PHONY: e4lb-reset
e4lb-reset: mesh-reset

.PHONY: noop-up
noop-up: mesh-up

.PHONY: noop-reset
e4lb-noop: mesh-reset

.PHONY: fgw-inbound
fgw-inbound:
	@pipy -e "pipy().listen(15003).serveHTTP(new Message('hi, it works as fgw inbound listener.\n'))"

.PHONY: fgw-outbound
fgw-outbound:
	@pipy -e "pipy().listen(15001).serveHTTP(new Message('hi, it works as fgw outbound listener.\n'))"

.PHONY: fgw-demo
fgw-demo:
	@sudo nohup pipy -e "pipy().listen(15001).serveHTTP(new Message('hi, it works as fgw outbound listener in sys.\n'))" > /dev/null 2>&1 &
	@sudo nohup pipy -e "pipy().listen(15003).serveHTTP(new Message('hi, it works as fgw inbound listener in sys.\n'))" > /dev/null 2>&1 &

.PHONY: v1-curl-demo
v1-curl-demo:
	@sudo ip netns exec v1 curl 10.0.0.1:8080

.PHONY: v2-curl-demo
v2-curl-demo:
	@sudo ip netns exec v2 curl 20.0.0.1:8080

.PHONY: v1-pipy-demo
v1-pipy-demo:
	@sudo nohup ip netns exec v1 pipy -e "pipy().listen('[::]:8080').serveHTTP(new Message('hi, it works as demo in v1.\n'))" > /dev/null 2>&1 &

.PHONY: curl-v1-demo
curl-v1-demo:
	@curl 10.0.0.2:8080

.PHONY: v2-curl-v1-demo
v2-curl-v1-demo:
	@sudo ip netns exec v2 curl 10.0.0.2:8080

.PHONY: v2-pipy-demo
v2-pipy-demo:
	@sudo nohup ip netns exec v2 pipy -e "pipy().listen('[::]:8080').serveHTTP(new Message('hi, it works as demo in v2.\n'))" > /dev/null 2>&1 &

.PHONY: curl-v2-demo
curl-v2-demo:
	@curl 20.0.0.2:8080

.PHONY: v1-curl-v2-demo
v1-curl-v2-demo:
	@sudo ip netns exec v1 curl 20.0.0.2:8080

.PHONY: test-mesh-tcp-outbound
test-mesh-tcp-outbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --debug-on
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --opt-on
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=0 --proto-tcp --tc-ingress --ep-addr=${CTR_ETH_IP4} --ep-port=15003 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=0 --proto-tcp --tc-egress --ep-addr=${CTR_ETH_IP4} --ep-port=15001 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true
	sudo ip netns exec v1 curl 20.0.0.2:8080

.PHONY: test-mesh-tcp-inbound
test-mesh-tcp-inbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --debug-on
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=0 --proto-tcp --tc-ingress --ep-addr=${CTR_ETH_IP4} --ep-port=15003 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=0 --proto-tcp --tc-egress --ep-addr=${CTR_ETH_IP4} --ep-port=15001 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true
	curl 10.0.0.2:8080

.PHONY: test-mesh-acl-outbound
test-mesh-acl-outbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --debug-on --acl_check_on=1
	@${BIN_DIR}/xnat acl add --sys=mesh --proto-tcp --port=0 --addr=10.0.0.1 --acl=trusted
	@${BIN_DIR}/xnat acl add --sys=mesh --proto-tcp --port=0 --addr=20.0.0.2 --acl=trusted
	@${BIN_DIR}/xnat bpf attach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true
	sudo ip netns exec v1 curl 20.0.0.2:8080

.PHONY: test-mesh-acl-inbound
test-mesh-acl-inbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --debug-on --acl_check_on=1
	@${BIN_DIR}/xnat acl add --sys=mesh --proto-tcp --port=0 --addr=10.0.0.1 --acl=trusted
	@${BIN_DIR}/xnat acl add --sys=mesh --proto-tcp --port=0 --addr=20.0.0.2 --acl=trusted
	@${BIN_DIR}/xnat bpf attach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true
	curl 10.0.0.2:8080

.PHONY: test-mesh-dns-outbound
test-mesh-dns-outbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --debug-on
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --opt-on
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --udp_nat_by_port_on=1
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=53 --proto-udp --tc-ingress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=53 --proto-udp --tc-egress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true
	nslookup www.baidu.com 10.0.0.2

.PHONY: test-mesh-dns-inbound
test-mesh-dns-inbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --debug-on
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --opt-on
	@${BIN_DIR}/xnat cfg set --sys=mesh --ipv4 --udp_nat_by_port_on=1
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=53 --proto-udp --tc-ingress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --sys=mesh --addr=0.0.0.0 --port=53 --proto-udp --tc-egress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --sys=mesh --namespace=v1 --dev=eth0 --tc-ingress=true --tc-egress=true
	@ip netns exec v1 nslookup www.baidu.com 20.0.0.2

.PHONY: test-e4lb-tcp
test-e4lb-tcp:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=e4lb --dev=cni2 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --sys=e4lb --ipv4 --debug-on --tcp_nat_all_off=1 --tcp_nat_by_ip_port_on=1 --tcp_proto_allow_nat_escape=1 --udp_proto_allow_all=1 --oth_proto_deny_all=0
	@${BIN_DIR}/xnat cfg set --sys=e4lb --ipv6 --debug-on --tcp_nat_all_off=1 --tcp_nat_by_ip_port_on=1 --tcp_proto_allow_nat_escape=1 --udp_proto_allow_all=1 --oth_proto_deny_all=0
	@${BIN_DIR}/xnat nat add --sys=e4lb --proto-tcp --addr=17.17.17.17 --port=8080 --tc-ingress --ep-addr=10.0.0.2 --ep-port=8080 --ep-mac=$(CTR_CNI1_MAC) --ep-ofi=$(CTR_CNI1_IFI) --ep-oflags=1
	${BIN_DIR}/xnat nat add --sys=e4lb --proto-tcp --addr=17::17 --port=8080 --tc-ingress --ep-addr=10::2 --ep-port=8080 --ep-mac=$(CTR_CNI1_MAC) --ep-ofi=$(CTR_CNI1_IFI) --ep-oflags=1
	@${BIN_DIR}/xnat bpf attach --sys=e4lb --dev=cni2 --tc-ingress=true --tc-egress=true
	sudo ip netns exec v2 curl 17.17.17.17:8080
	sudo ip netns exec v2 curl [17::17]:8080

.PHONY: test-noop-tcp
test-noop-tcp:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --sys=noop --dev=cni2 --tc-ingress=true --tc-egress=true > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat bpf attach --sys=noop --dev=cni2 --tc-ingress=true --tc-egress=true
	sudo ip netns exec v2 curl 10.0.0.2:8080

.PHONY: init-prog-map
init-prog-map:
	@${BIN_DIR}/xnat prog init

.PHONY: init-noop-nat-map
init-noop-nat-map:
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-ingress --ep-addr=${CTR_ETH_IP4} --ep-port=15003 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-egress --ep-addr=${CTR_ETH_IP4} --ep-port=15001 --ep-mac=${CTR_CNI1_MAC}

.PHONY: init-noop-acl-map
init-noop-acl-map:
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=10.0.0.1 --acl=trusted
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=20.0.0.2 --acl=trusted

.PHONY: init-noop-trace-ip-map
init-noop-trace-ip-map:
	@${BIN_DIR}/xnat tr ip add --addr=10.0.0.2 --tc-ingress --tc-egress

.PHONY: init-noop-trace-port-map
init-noop-trace-port-map:
	@${BIN_DIR}/xnat trace port add --port=8080 --tc-ingress --tc-egress

.PHONY: show-tcp-flow-map
show-tcp-flow-map:
	@${BIN_DIR}/xnat flow tcp list | jq

.PHONY: show-udp-flow-map
show-udp-flow-map:
	@${BIN_DIR}/xnat flow udp list | jq

.PHONY: show-tcp-opt-map
show-tcp-opt-map:
	@${BIN_DIR}/xnat opt tcp list | jq

.PHONY: show-udp-opt-map
show-udp-opt-map:
	@${BIN_DIR}/xnat opt udp list | jq

.PHONY: show-acl-map
show-acl-map:
	@${BIN_DIR}/xnat acl list | jq

.PHONY: show-nat-map
show-nat-map:
	@${BIN_DIR}/xnat nat list | jq

.PHONY: show-cfg-map
show-cfg-map:
	@${BIN_DIR}/xnat cfg list | jq

.PHONY: show-noop-cfg
show-noop-cfg:
	@${BIN_DIR}/xnat cfg get --sys=noop | jq

.PHONY: show-mesh-cfg
show-mesh-cfg:
	@${BIN_DIR}/xnat cfg get --sys=mesh | jq

.PHONY: show-e4lb-cfg
show-e4lb-cfg:
	@${BIN_DIR}/xnat cfg get --sys=e4lb | jq

.PHONY: show-prog-map
show-prog-map:
	@${BIN_DIR}/xnat prog list | jq

.PHONY: show-trace-ip-map
show-trace-ip-map:
	@${BIN_DIR}/xnat tr ip list | jq

.PHONY: show-trace-port-map
show-trace-port-map:
	@${BIN_DIR}/xnat tr port list | jq