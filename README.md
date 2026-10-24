# fastls-lab

独立的 Fastls 请求指纹靶场。当前为首批诊断实现，**不表示全部规划能力已完成**。

已实现：TCP/TLS1.2/1.3、独立H2端口的首个请求SETTINGS/窗口/优先级/HPACK头序、按连接编号的 ClientHello 套件/扩展原始序列及实际协商、每连接首个 HTTP1 请求头的顺序/大小写/重复项、WS/WSS 的 HTTP1 Upgrade、未压缩消息回显、分片/控制帧/关闭与部分负向检查。采集器不导入 Fastls、ftransport 或 uTLS；HTTP2 HPACK 解码使用固定版本 x/net，独立于 Fastls 编译器。

尚未实现：通用多流HTTP2服务/HTTP3、逐套件完整矩阵、WS 压缩及子协议场景配置、H2/H3 WebSocket、Profile 自动比较、跨程序/设备驱动、完整 run 管理与统一报告适配。`/capabilities` 如实声明这些边界；echo/101 不是指纹一致性结论。

```sh
go test ./...
go run . -output ../reports/lab-run-001
```

默认 HTTP、HTTPS、管理接口绑定回环随机端口。启动输出与 `lab-manifest.json` 提供 HTTP、HTTPS、独立 `https2` 地址和 `ca.pem`；客户端只信任该测试 CA，无需修改系统证书或忽略校验。重复运行使用新输出目录，防止覆盖证据。

数据面 `/inspect`、`/ws`，管理面 `/health`、`/capabilities`、`/events`。`events.jsonl` 保存握手、头序列与 WS 帧元信息，不保存帧正文、Cookie/Authorization 或 key_share/PSK 的原始密钥材料。原始 TLS 扩展载荷仍可能包含主机名，分享前检查。CLI 退出保留证据。

当前限制：首个头捕获最多64KiB、ClientHello捕获128KiB、WS每帧/消息1MiB、会话15秒/256帧，每次运行最多10000条事件/64MiB证据，达到上限写入 capture.incomplete 并使健康检查失败。仅用于受控测试；不能将缺失/截断观测计为匹配。规划和后续验收见外层 FASTLS_FINGERPRINT_LAB.md。


H2 接收端仅处理每连接首个请求，限制为256帧/64KiB帧或头块/10秒，不作为生产HTTP2服务器。记录 SETTINGS 原始顺序、WINDOW_UPDATE、PRIORITY、HEADERS 优先级和解码后的有序重复头，敏感头脱敏，不保存HPACK块原文。标准库HTTP2客户端校准测试与固定字节帧测试分别验证采集器与后端，不能用Fastls自身生成结果替代参考。

跨仓完整验收位于核心 `scripts/verify-imitate.py`，能驱动此靶场实际观测 Spec 编辑、H2 空/零配置和 WS/WSS；报告仍区分诊断执行成功与目标浏览器样本一致。
