#!/usr/bin/env bash
# FlowScan 安装脚本共享下载/校验助手(source 使用,不直接执行)。
#
# 用法:
#   . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_fetch.sh"
#   fs3_fetch <输出文件> <下载URL> [期望sha256]
#
# 行为:
#   1. 离线优先:$FS3_OFFLINE_DIR(未设置时回退 <本脚本目录>/offline,存在即用)
#      下有同名文件(URL 的 basename 或 <输出文件> 名)时直接复制,不联网。
#   2. 否则下载:gh-proxy.com → ghproxy.net → 直连。
#   3. sha256 校验:期望值取 [第3参] > $FS3_SHA256 > 内置 _FS3_SHA256 表。
#      - 有期望值且不匹配  → 明确报错 + 删除下载物 + 返回 1(脚本随 set -e 中止)
#      - 无任何期望值      → 明确报错并拒绝安装未校验产物(不再静默继续)
#
# 环境变量(全部可选):
#   FS3_OFFLINE_DIR  本地离线包目录(优先使用;支持断网/内网批量部署)
#   FS3_SHA256       本次产物的期望 sha256(覆盖内置表,用于临时换版本)
#   FS3_INSECURE=1   跳过校验(仅调试;打印醒目警告)
set -euo pipefail

_FS3_CURL="curl -fsSL --connect-timeout 5 --max-time 600 --retry 3 --retry-delay 5"

# 内置 sha256 基线:与各 install/*.sh 里写死的下载 URL 版本号一一对应。
# 取值为 2026-09-28 实测该 pinned 发布产物的 sha256(dnsx/cdncheck 已与上游
# *_checksums.txt 官方值比对一致;上游未发布校验和的用实测值,配合 URL 版本锁)。
declare -A _FS3_SHA256=(
    ["afrog_3.5.6_linux_amd64.zip"]="aff990270977e8ae8b0d60fad986ecc4ad43c35833ed99748046d3f5d9e5c8ad"
    ["katana_1.7.0_linux_amd64.zip"]="fe1142d92f418549338ea46d67a472124878482e225d279e9a42700c75d76a4d"
    ["ksubdomain_linux.zip"]="4ddf69350c169a19efb5178b8baaf552255b2f8498e1513b7cd1b1f3303bf205"
    ["fofax_v0.1.48_linux_amd64.tar.gz"]="25d30520f92441ca3285a7e61324af294ffb93e87a679932412e617fcac70e5f"
    ["dnsx_1.2.2_linux_amd64.zip"]="dabd54146d63b53fdd08186156ca117fcb79656c66153e3d3c61367aa87a9943"
    ["cdncheck_1.2.48_linux_amd64.zip"]="903c3ad5d50bfd560e2606ca65ee638083ca90e44d0b2ca5a8631c70334d9252"
)

_fs3_offline_dir() {
    if [ -n "${FS3_OFFLINE_DIR:-}" ]; then
        printf '%s' "$FS3_OFFLINE_DIR"
        return 0
    fi
    local d
    d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/offline"
    [ -d "$d" ] && printf '%s' "$d"
}

fs3_fetch() {
    local out="$1" url="$2" want="${3:-}"
    local base="${url##*/}"
    local od
    od="$(_fs3_offline_dir || true)"

    # 1) 离线包优先
    if [ -n "$od" ]; then
        if [ -f "$od/$base" ]; then
            cp -f "$od/$base" "$out"
            echo "[fetch] 使用离线包 $od/$base"
        elif [ -f "$od/$out" ]; then
            cp -f "$od/$out" "$out"
            echo "[fetch] 使用离线包 $od/$out"
        fi
    fi

    # 2) 联网下载(镜像 → 直连);失败给明确原因,不让 set -e 静默中断
    if [ ! -s "$out" ]; then
        if ! { $_FS3_CURL "https://gh-proxy.com/$url" -o "$out" \
               || $_FS3_CURL "https://ghproxy.net/$url" -o "$out" \
               || $_FS3_CURL "$url" -o "$out"; }; then
            echo "[fetch] 错误:$base 下载失败(gh-proxy.com / ghproxy.net / 直连均不可用)。" >&2
            echo "        可把离线包放到 \$FS3_OFFLINE_DIR 后重试。" >&2
            rm -f "$out"
            return 1
        fi
    fi

    # 3) sha256 校验
    [ -n "$want" ] || want="${FS3_SHA256:-}"
    [ -n "$want" ] || want="${_FS3_SHA256[$base]:-}"

    if [ "${FS3_INSECURE:-0}" = "1" ]; then
        echo "[fetch] 警告:FS3_INSECURE=1,跳过 $base 的 sha256 校验" >&2
        return 0
    fi
    if [ -z "$want" ]; then
        echo "[fetch] 错误:没有 $base 的 sha256 基线,拒绝安装未校验产物。" >&2
        echo "        请 export FS3_SHA256=<sha256> 后重试,或把离线包放入 \$FS3_OFFLINE_DIR。" >&2
        rm -f "$out"
        return 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo "[fetch] 错误:系统缺少 sha256sum,无法校验 $base" >&2
        rm -f "$out"
        return 1
    fi
    local got
    got="$(sha256sum "$out" | awk '{print $1}')"
    if [ "$got" != "$want" ]; then
        echo "[fetch] 错误:$base sha256 校验失败" >&2
        echo "        期望 $want" >&2
        echo "        实际 $got" >&2
        rm -f "$out"
        return 1
    fi
    echo "[fetch] $base sha256 校验通过(${got:0:12}...)"
    return 0
}
