#!make
SHELL = bash

CTR_ETH  ?= ens33
CTR_ETH_IP4 ?= $(shell ip -j -4 a show dev $(CTR_ETH) | jq -r .[0].addr_info[0].local)
CTR_CNI1_MAC ?= $(shell ip -j a show dev cni1 | jq -r .[0].address)
CTR_CNI2_MAC ?= $(shell ip -j a show dev cni2 | jq -r .[0].address)

WORK_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ROOT_DIR :=  $(abspath $(WORK_DIR)/../..)
BIN_DIR :=  $(abspath $(WORK_DIR)/../../bin)

.PHONY: test-up
test-up: test-reset
	@echo 1 > /proc/sys/net/ipv4/ip_forward
	@sudo iptables -t nat -A POSTROUTING -o ${CTR_ETH} -j MASQUERADE
	@# Configure load-balancer end-point v1
	@sudo ip netns add v1
	@sudo ip link add cni1 type veth peer name eth0 netns v1
	@sudo ip link set cni1 up
	@sudo ip addr add 10.0.0.1/24 dev cni1
	@sudo ip -n v1 link set eth0 up
	@sudo ip netns exec v1 ifconfig eth0 10.0.0.2/24 up
	@sudo ip netns exec v1 ip route add default via 10.0.0.1
	@sudo ip netns exec v1 ifconfig lo up
	@# Configure load-balancer end-point v1 Done
	@# Configure load-balancer end-point v2
	@sudo ip netns add v2
	@sudo ip link add cni2 type veth peer name eth0 netns v2
	@sudo ip link set cni2 up
	@sudo ip addr add 20.0.0.1/24 dev cni2
	@sudo ip -n v2 link set eth0 up
	@sudo ip netns exec v2 ifconfig eth0 20.0.0.2/24 up
	@sudo ip netns exec v2 ip route add default via 20.0.0.1
	@sudo ip netns exec v2 ifconfig lo up
	@# Configure load-balancer end-point v2 Done

.PHONY: test-reset
test-reset:
	@sudo ip link del cni1 > /dev/null 2>&1 || true
	@sudo ip netns del v1 > /dev/null 2>&1 || true
	@sudo ip link del cni2 > /dev/null 2>&1 || true
	@sudo ip netns del v2 > /dev/null 2>&1 || true
	@sudo iptables -t nat -F || true

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
	@sudo nohup ip netns exec v1 pipy -e "pipy().listen(8080).serveHTTP(new Message('hi, it works as demo in v1.\n'))" > /dev/null 2>&1 &

.PHONY: curl-v1-demo
curl-v1-demo:
	@curl 10.0.0.2:8080

.PHONY: v2-curl-v1-demo
v2-curl-v1-demo:
	@sudo ip netns exec v2 curl 10.0.0.2:8080

.PHONY: v2-pipy-demo
v2-pipy-demo:
	@sudo nohup ip netns exec v2 pipy -e "pipy().listen(8080).serveHTTP(new Message('hi, it works as demo in v2.\n'))" > /dev/null 2>&1 &

.PHONY: curl-v2-demo
curl-v2-demo:
	@curl 20.0.0.2:8080

.PHONY: v1-curl-v2-demo
v1-curl-v2-demo:
	@sudo ip netns exec v1 curl 20.0.0.2:8080

.PHONY: test-tcp-outbound
test-tcp-outbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --namespace=v1 --dev=eth0 > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --debug-on
	@${BIN_DIR}/xnat cfg set --opt-on
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-ingress --ep-addr=${CTR_ETH_IP4} --ep-port=15003 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-egress --ep-addr=${CTR_ETH_IP4} --ep-port=15001 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --namespace=v1 --dev=eth0
	@sudo ip netns exec v1 curl 20.0.0.2:8080

.PHONY: test-tcp-inbound
test-tcp-inbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --namespace=v1 --dev=eth0 > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --debug-on
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-ingress --ep-addr=${CTR_ETH_IP4} --ep-port=15003 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-egress --ep-addr=${CTR_ETH_IP4} --ep-port=15001 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --namespace=v1 --dev=eth0
	@curl 10.0.0.2:8080

.PHONY: test-acl-outbound
test-acl-outbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --namespace=v1 --dev=eth0 > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --ipv4_acl_check_on=1
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=10.0.0.1 --acl=trusted
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=20.0.0.2 --acl=trusted
	@${BIN_DIR}/xnat bpf attach --namespace=v1 --dev=eth0
	@sudo ip netns exec v1 curl 20.0.0.2:8080

.PHONY: test-acl-inbound
test-acl-inbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --namespace=v1 --dev=eth0 > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --ipv4_acl_check_on=1
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=10.0.0.1 --acl=trusted
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=20.0.0.2 --acl=trusted
	@${BIN_DIR}/xnat bpf attach --namespace=v1 --dev=eth0
	@curl 10.0.0.2:8080

.PHONY: test-dns-outbound
test-dns-outbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --namespace=v1 --dev=eth0 > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --debug-on
	@${BIN_DIR}/xnat cfg set --opt-on
	@${BIN_DIR}/xnat cfg set --ipv4_udp_nat_by_port_on=1
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=53 --proto-udp --tc-ingress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=53 --proto-udp --tc-egress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --namespace=v1 --dev=eth0
	@nslookup www.baidu.com 10.0.0.2

.PHONY: test-dns-inbound
test-dns-inbound:
	@make -f ${ROOT_DIR}/Makefile.cli.mk clean load
	@${BIN_DIR}/xnat bpf detach --namespace=v1 --dev=eth0 > /dev/null 2>&1 || true
	@${BIN_DIR}/xnat prog init
	@${BIN_DIR}/xnat cfg set --debug-on
	@${BIN_DIR}/xnat cfg set --opt-on
	@${BIN_DIR}/xnat cfg set --ipv4_udp_nat_by_port_on=1
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=53 --proto-udp --tc-ingress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=53 --proto-udp --tc-egress --ep-addr=8.8.8.8 --ep-port=53 --ep-mac=${CTR_CNI1_MAC}
	@${BIN_DIR}/xnat bpf attach --namespace=v1 --dev=eth0
	@ip netns exec v1 nslookup www.baidu.com 20.0.0.2

.PHONY: init-prog-map
init-prog-map:
	@${BIN_DIR}/xnat prog init

.PHONY: init-nat-map
init-nat-map:
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-ingress --ep-addr=${CTR_ETH_ADDR} --ep-port=15003
	@${BIN_DIR}/xnat nat add --addr=0.0.0.0 --port=0 --proto-tcp --tc-egress --ep-addr=${CTR_ETH_ADDR} --ep-port=15001

.PHONY: init-acl-map
init-acl-map:
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=10.0.0.1 --acl=trusted
	@${BIN_DIR}/xnat acl add --proto-tcp --port=0 --addr=20.0.0.2 --acl=trusted

.PHONY: init-trace-ip-map
init-trace-ip-map:
	@${BIN_DIR}/xnat tr ip add --addr=10.0.0.2 --tc-ingress --tc-egress

.PHONY: init-trace-port-map
init-trace-port-map:
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

.PHONY: show-prog-map
show-prog-map:
	@${BIN_DIR}/xnat prog list | jq

.PHONY: show-trace-ip-map
show-trace-ip-map:
	@${BIN_DIR}/xnat tr ip list | jq

.PHONY: show-trace-port-map
show-trace-port-map:
	@${BIN_DIR}/xnat tr port list | jq

.PHONY: show-tc
show-tc:
	@${BIN_DIR}/xnat bpf list --namespace=v1 --dev=eth0 | jq