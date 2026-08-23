# ustc-iwan-mac-linklab (archived scratch)

## macotest 结论（2026-08-23, macOS 14 arm64 runner, 项目 @5c0c877）

- utun 双向帧路径：项目真实 pool reader + tun_write 下 ping v4/v6 全通（FULL-PASS）。
- **family 头是网络字节序**（{00 00 00 02}）：同轮对照中原生序 {02 00 00 00} 被
  内核静默丢弃。上游 tun.c 已按网络序修复；常见"native order"说法不适用于 utun 控制套接字。
- 审计再评估：①重复 route add 在 macOS 14 静默成功（EEXIST 前提不成立，delete-first 无害保留）；
  ②未掩码 CIDR 目标被 route(8) 归一化、路由可命中（审计的"永不命中"不成立）；
  ③root 可直读用户 login keychain 条目（uid=0 unwrap 成功），sudo --connect 链路可行。
- 上游落地：Jerrid-Huang/ustc-iwan-c @ 66babaa + 917f308 + 5c0c877。
