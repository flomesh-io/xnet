## 编译环境

```
apt install -y clang llvm libelf-dev libbpf-dev clang-format
```

## 测试指令

```
mkdir bin
make -f Makefile.cli.mk kern-trace

make -f docs/tests/Makefile test-up
make -f docs/tests/Makefile fgw-demo
make -f docs/tests/Makefile v1-pipy-demo
make -f docs/tests/Makefile v2-pipy-demo

make -f Makefile.cli.mk build-bpf build-cli

make -f docs/tests/Makefile test-tcp-outbound
make -f docs/tests/Makefile test-tcp-inbound

make -f docs/tests/Makefile test-acl-outbound
make -f docs/tests/Makefile test-acl-inbound

make -f docs/tests/Makefile test-dns-outbound
make -f docs/tests/Makefile test-dns-inbound

make -f docs/tests/Makefile init-prog-map
make -f docs/tests/Makefile init-cfg-map
make -f docs/tests/Makefile init-nat-map
make -f docs/tests/Makefile init-acl-map
make -f docs/tests/Makefile init-trace-ip-map
make -f docs/tests/Makefile init-trace-port-map

make -f docs/tests/Makefile show-prog-map
make -f docs/tests/Makefile show-mesh-cfg
make -f docs/tests/Makefile show-e4lb-cfg
make -f docs/tests/Makefile show-nat-map
make -f docs/tests/Makefile show-acl-map
make -f docs/tests/Makefile show-tcp-flow-map
make -f docs/tests/Makefile show-udp-flow-map
make -f docs/tests/Makefile show-tcp-opt-map
make -f docs/tests/Makefile show-udp-opt-map
make -f docs/tests/Makefile show-trace-ip-map
make -f docs/tests/Makefile show-trace-port-map
```
