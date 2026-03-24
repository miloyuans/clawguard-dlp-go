# ClawGuard DLP Gateway (Go)

## 功能
- 私聊消息敏感数据检测
- 自动脱敏（占位符替换）
- 策略决策：ALLOW_REDACTED / BLOCK / LOCAL_ONLY（当前实现 ALLOW_REDACTED/BLOCK）
- 审计日志（不记录明文敏感值）
- 强制模型代理：无 `X-Guard-Token` 拒绝下游推理

## 启动
```bash
cd /root/.openclaw/.openclaw/workspace/clawguard-dlp-go
CLAWGUARD_LISTEN=:18080 \
CLAWGUARD_AUDIT_PATH=/tmp/clawguard_audit.log \
CLAWGUARD_TOKEN='replace-with-strong-token' \
CLAWGUARD_MODEL_TARGET='http://127.0.0.1:8080/model' \
go run ./cmd/server
```

## 接口

### 1) 仅脱敏测试
```bash
curl -s http://127.0.0.1:18080/v1/sanitize \
  -H 'content-type: application/json' \
  -d '{"userId":"7997315413","text":"AKIA1234567890ABCDE password=abc123 bearer eyJabc.def.ghi 10.1.2.3"}'
```

### 2) 强制模型代理（生产接入关键）
```bash
curl -s http://127.0.0.1:18080/v1/model-proxy \
  -H 'content-type: application/json' \
  -H 'X-Guard-Token: replace-with-strong-token' \
  -d '{"userId":"7997315413","prompt":"my token is bearer abc... and ip 10.1.2.3"}'
```

## 生产接入（OpenClaw）
1. 把所有大模型调用改走 `POST /v1/model-proxy`
2. OpenClaw 侧固定注入 `X-Guard-Token`
3. 下游模型服务只接受来自 ClawGuard 的来源（网络ACL + token校验）
4. 无 guard token 请求一律拒绝（当前已实现）

## systemd 示例
`/etc/systemd/system/clawguard.service`
```ini
[Unit]
Description=ClawGuard DLP Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/.openclaw/.openclaw/workspace/clawguard-dlp-go
Environment=CLAWGUARD_LISTEN=:18080
Environment=CLAWGUARD_AUDIT_PATH=/var/log/clawguard_audit.log
Environment=CLAWGUARD_TOKEN=replace-with-strong-token
Environment=CLAWGUARD_MODEL_TARGET=http://127.0.0.1:8080/model
ExecStart=/usr/bin/env go run ./cmd/server
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

## 后续待完善
- YAML 配置加载
- 附件 OCR/文档提取后再脱敏
- 更细粒度策略（按用户/频道/敏感级别）
- 密文映射缓存与会话级占位符稳定性
# clawguard-dlp-go
