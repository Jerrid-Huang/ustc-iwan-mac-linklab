# ustc-iwan-mac-linklab (archived scratch)

结论（2026-08-22）：macOS Security.framework 链接修复已合入上游

- 根因：此前每次链接尝试只给 Security，漏了 CoreFoundation，CF* 符号必然未定义。
- 方案：`target_link_options(iwan-client-oidc PRIVATE "SHELL:-framework Security" "SHELL:-framework CoreFoundation")`。
- 验证：macos-14 arm64/x86_64 全量构建通过，二进制正确携带两个系统框架。
- 上游落地：Jerrid-Huang/ustc-iwan-c @ 79b5059。
