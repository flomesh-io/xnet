## 编译环境

```
apt install -y clang llvm libelf-dev libbpf-dev clang-format
```

## Mesh测试指令

```
mkdir bin
make -f Makefile.cli.mk kern-trace

make -f docs/tests/Makefile mesh-up
make -f docs/tests/Makefile fgw-demo
make -f docs/tests/Makefile v1-pipy-demo
make -f docs/tests/Makefile v2-pipy-demo

make -f Makefile.cli.mk build-bpf build-cli

make -f docs/tests/Makefile test-mesh-tcp-outbound
make -f docs/tests/Makefile test-mesh-tcp-inbound

make -f docs/tests/Makefile test-mesh-acl-outbound
make -f docs/tests/Makefile test-mesh-acl-inbound

make -f docs/tests/Makefile test-mesh-dns-outbound
make -f docs/tests/Makefile test-mesh-dns-inbound
```

## E4lb测试指令

```
mkdir bin
make -f Makefile.cli.mk kern-trace

make -f docs/tests/Makefile e4lb-up
make -f docs/tests/Makefile v1-pipy-demo

make -f Makefile.cli.mk build-bpf build-cli
make -f docs/tests/Makefile test-e4lb-tcp
```

## Noop测试指令

```bash
mkdir bin
make -f Makefile.cli.mk kern-trace

make -f docs/tests/Makefile noop-up
make -f docs/tests/Makefile v1-pipy-demo

make -f Makefile.cli.mk build-bpf build-cli
make -f docs/tests/Makefile test-noop-tcp
```

## 辅助指令

```bash
make -f docs/tests/Makefile init-prog-map
make -f docs/tests/Makefile init-noop-nat-map
make -f docs/tests/Makefile init-noop-acl-map
make -f docs/tests/Makefile init-noop-trace-ip-map
make -f docs/tests/Makefile init-noop-trace-port-map

make -f docs/tests/Makefile show-prog-map
make -f docs/tests/Makefile show-noop-cfg
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

