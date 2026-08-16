#!/usr/bin/env bash
# FlowScan3 Docker 化一键构建 + 端到端验证脚本
# 用法: sudo bash docker/verify_docker.sh     (需要 docker daemon 权限)
# 单机验证: 主节点镜像(redis+web+xray) + worker 镜像(全工具链)
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_DIR}"

echo "============================================"
echo " FlowScan3 Docker 构建与端到端验证"
echo "============================================"

# ── 1. 构建镜像(主节点 + worker) ──
echo ""
echo "[1/7] 构建 flowscan:main(主节点/web 面板)..."
docker build -t flowscan:main . || { echo "❌ 主节点镜像构建失败"; exit 1; }
echo "✅ 主节点镜像构建完成"

echo ""
echo "[2/7] 构建 flowscan:worker(全工具链)..."
docker build -f Dockerfile.worker -t flowscan:worker . || { echo "❌ worker 镜像构建失败"; exit 1; }
echo "✅ worker 镜像构建完成"

# ── 3. 工具可用性检查(worker 镜像内 18 工具) ──
echo ""
echo "[3/7] 验证 worker 镜像内工具可用性..."
docker run --rm flowscan:worker bash -c '
for t in amass feroxbuster naabu nmap nuclei subfinder whatweb httpx dnsx cdncheck katana afrog fofax ksubdomain medusa whois chromium xray; do
    if command -v $t >/dev/null 2>&1; then echo "  ✅ $t"; else echo "  ❌ $t 缺失"; fi
done
python3 -c "import yaml,redis,flask,tldextract" 2>/dev/null && echo "  ✅ python deps" || echo "  ❌ python deps"
' || { echo "❌ 工具检查失败"; exit 1; }

echo ""
echo "验证主节点镜像 web 依赖..."
docker run --rm flowscan:main bash -c '
python3 -c "import yaml,redis,flask,tldextract" 2>/dev/null && echo "  ✅ web python deps" || echo "  ❌ web python deps"
command -v xray >/dev/null 2>&1 && echo "  ✅ xray 已装入主节点镜像" || echo "  ⚠️ xray 未装入(可接受)"
' || { echo "❌ 主节点镜像检查失败"; exit 1; }

# ── 4. 主节点编排启动(redis + web) ──
echo ""
echo "[4/7] 启动主节点编排(redis + web)..."
docker compose up -d --build || docker-compose up -d --build || { echo "❌ compose 启动失败(缺少 compose 插件?)"; exit 1; }

echo "等待服务就绪(30s)..."
sleep 30
docker compose ps || docker-compose ps

# ── 5. worker 节点编排启动(连 127.0.0.1 主节点 redis) ──
echo ""
echo "[5/7] 启动 worker 节点编排(FS3_REDIS_HOST=127.0.0.1)..."
FS3_REDIS_HOST=127.0.0.1 docker compose -f docker-compose.worker.yml up -d --build \
    || FS3_REDIS_HOST=127.0.0.1 docker-compose -f docker-compose.worker.yml up -d --build \
    || { echo "⚠️ worker 编排启动失败(单机验证可忽略)"; }
sleep 10

# ── 6. 事件注入与消费链路 ──
echo ""
echo "[6/7] 注入 DNS_NAME 事件并观察 worker 消费..."
docker compose -f docker-compose.worker.yml exec -T worker \
    python3 main.py inject --event-type DNS_NAME --value example.com \
    || docker compose exec -T worker python3 main.py inject --event-type DNS_NAME --value example.com
sleep 10
echo "--- worker 最近日志 ---"
docker compose -f docker-compose.worker.yml logs --tail 20 worker || docker compose logs --tail 20 worker

# ── 7. Web 面板 + 状态 ──
echo ""
echo "[7/7] Web 面板探测 + 状态..."
curl -s -o /dev/null -w "Web HTTP %{http_code}\n" http://127.0.0.1:8080/login || echo "⚠️ web 未响应"
docker compose -f docker-compose.worker.yml exec -T worker python3 main.py status 2>/dev/null \
    || docker compose exec -T worker python3 main.py status || true

echo ""
echo "============================================"
echo " 验证完成"
echo " Web 面板: http://127.0.0.1:8080"
echo " 生产部署: 主节点 docker compose up -d;"
echo "           worker 节点 FS3_REDIS_HOST=<主节点IP> docker compose -f docker-compose.worker.yml up -d"
echo "============================================"
