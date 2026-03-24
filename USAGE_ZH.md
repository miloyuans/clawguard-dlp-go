# ClawGuard 脱敏网关（Go版）使用说明

## 1. 适用场景
在消息进入大模型前，先做敏感信息检测与脱敏，避免明文 secrets 透传。

## 2. 已包含内容
- `build/clawguard`：可执行文件
- 源码：`cmd/`、`internal/`
- 配置模板：`production.env.example`
- 脚本：
  - `scripts_build_release.sh`
  - `scripts_install_systemd.sh`
  - `scripts_smoke_test.sh`

## 3. 快速启动（前台）
```bash
cd clawguard-dlp-go
CLAWGUARD_LISTEN=:18080 \
CLAWGUARD_AUDIT_PATH=/tmp/clawguard_audit.log \
CLAWGUARD_TOKEN='replace-with-strong-token' \
CLAWGUARD_MODEL_TARGET='http://127.0.0.1:8080/model' \
./build/clawguard
```

## 4. 生产安装（systemd）
```bash
cd clawguard-dlp-go
./scripts_install_systemd.sh
```
> 非 systemd 环境请用 supervisor/nohup 启动。

## 5. 接口说明
### 健康检查
`GET /healthz`

### 脱敏测试
`POST /v1/sanitize`

示例：
```bash
curl -s http://127.0.0.1:18080/v1/sanitize \
  -H 'content-type: application/json' \
  -d '{"userId":"u1","text":"AKIA... password=abc 10.0.0.1"}'
```

### 模型代理（强制token）
`POST /v1/model-proxy`
- 必须带 `X-Guard-Token`

## 6. 关键环境变量
- `CLAWGUARD_LISTEN` 监听地址
- `CLAWGUARD_AUDIT_PATH` 审计日志路径
- `CLAWGUARD_TOKEN` 代理鉴权 token
- `CLAWGUARD_MODEL_TARGET` 下游模型地址
- `CLAWGUARD_DEFAULT_ACTION` 默认策略（ALLOW_REDACTED）
- `CLAWGUARD_HIGH_ACTION` 高敏策略（BLOCK）
- `CLAWGUARD_UPSTREAM_BASE` 透明代理上游（默认 chatgpt.com）

## 7. 推荐上线顺序
1) 先旁路运行 + 只审计
2) 开启 ALLOW_REDACTED
3) 高敏改 BLOCK
4) 全量切换模型流量

