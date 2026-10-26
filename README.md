# fastls-lab

[English documentation](https://fasttls.github.io/en/ecosystem/fastls-lab)

独立的 Fastls 请求指纹靶场。当前为首批诊断实现，**不表示全部规划能力已完成**。

已实现：TCP/TLS1.2/1.3、独立H2端口的首个请求SETTINGS/窗口/优先级/HPACK头序、按连接编号的 ClientHello 套件/扩展原始序列及实际协商、每连接首个 HTTP1 请求头的顺序/大小写/重复项、WS/WSS 的 HTTP1 Upgrade、未压缩消息回显、分片/控制帧/关闭与部分负向检查。采集器不导入 Fastls、ftransport 或 uTLS；HTTP2 HPACK 解码使用固定版本 x/net，独立于 Fastls 编译器。

尚未实现：通用多流HTTP2服务/HTTP3、逐套件完整矩阵、WS 压缩及子协议场景配置、H2/H3 WebSocket、Profile 自动比较、跨程序/设备驱动、完整 run 管理与统一报告适配。`/capabilities` 如实声明这些边界；echo/101 不是指纹一致性结论。

## 启动与使用

需要 Go 1.26+。从本仓库目录启动后读取输出目录的 lab-manifest.json，使用其中地址和 ca.pem 配置受测客户端，再从管理接口或 events.jsonl 读取证据。示例输出路径须选择新目录。

```sh
go test ./...
go run . -output ../reports/lab-run-001
```

默认 HTTP、HTTPS、管理接口绑定回环随机端口。启动输出与 `lab-manifest.json` 提供 HTTP、HTTPS、独立 `https2` 地址和 `ca.pem`；客户端只信任该测试 CA，无需修改系统证书或忽略校验。重复运行使用新输出目录，防止覆盖证据。

数据面 `/inspect`、`/ws`，管理面 `/health`、`/capabilities`、`/events`。`events.jsonl` 保存握手、头序列与 WS 帧元信息，不保存帧正文、Cookie/Authorization 或 key_share/PSK 的原始密钥材料。原始 TLS 扩展载荷仍可能包含主机名，分享前检查。CLI 退出保留证据。

当前限制：首个头捕获最多64KiB、ClientHello捕获128KiB、WS每帧/消息1MiB、会话15秒/256帧，每次运行最多10000条事件/64MiB证据，达到上限写入 capture.incomplete 并使健康检查失败。仅用于受控测试；不能将缺失/截断观测计为匹配。本仓库的功能边界以 `/capabilities` 和本文为准；后续变更应附对应测试与脱敏证据，不依赖本地工作区外的规划文件。


H2 接收端仅处理每连接首个请求，限制为256帧/64KiB帧或头块/10秒，不作为生产HTTP2服务器。记录 SETTINGS 原始顺序、WINDOW_UPDATE、PRIORITY、HEADERS 优先级和解码后的有序重复头，敏感头脱敏，不保存HPACK块原文。标准库HTTP2客户端校准测试与固定字节帧测试分别验证采集器与后端，不能用Fastls自身生成结果替代参考。

跨仓完整验收位于核心 `scripts/verify-imitate.py`，能驱动此靶场实际观测 Spec 编辑、H2 空/零配置和 WS/WSS；报告仍区分诊断执行成功与目标浏览器样本一致。

## 详细文档与问题反馈

- [使用文档](https://fasttls.github.io/ecosystem/)：安装、功能、参数与排错。
- [版本与发布说明](https://github.com/FastTLS/fastls-lab/releases)：正式版本、开发版本和产物边界。
- [问题反馈](https://github.com/FastTLS/fastls-lab/issues)：请提供版本、系统架构、脱敏后的最小示例与错误；不要提交凭据、Cookie、私钥或个人数据。

## 开源协议与第三方声明

自有代码采用 [Apache-2.0](LICENSE)。Go/x/net 等第三方材料保留原版权与授权；采集内容的权利和隐私责任由采集者确认。

## 使用边界与免责声明

仅在拥有权限的系统、数据和网络上使用，并遵守适用法律、服务条款及隐私要求。软件按许可证约定以“现状”提供，不承诺可用性、特定用途适用性、第三方服务放行、匿名性或与真实浏览器完全一致。浏览器名称和版本用于描述配置，不表示获得相应厂商认证或背书。部署方负责访问控制、密钥和个人信息保护、请求限额及数据备份；担保排除与责任限制以随附许可证及适用法律为准。本说明不改变许可证授予的权利或新增许可限制。
