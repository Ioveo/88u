#!/bin/bash
# ============================================================
#  S5 Proxy Scanner - SERV00 一键安装管理脚本
#  用法: bash <(curl -Ls https://raw.githubusercontent.com/Ioveo/88u/main/serv00.sh)
# ============================================================

# set -e 会导致 confirm 返回 1 时整个脚本退出，不使用

# ======================== 配置 ========================
INSTALL_DIR="$HOME/socks5"
BIN_NAME="socks5"
SRC_NAME="socks5.c"
IP_FILE="$INSTALL_DIR/check.txt"
CRED_FILE="$INSTALL_DIR/credentials.txt"
OUTPUT_FILE="$INSTALL_DIR/socks.txt"
LOG_FILE="$INSTALL_DIR/scan.log"
PID_FILE="$INSTALL_DIR/.scan.pid"

# GitHub 源码地址
GITHUB_RAW="https://raw.githubusercontent.com/Ioveo/88u/main"
SRC_URL="$GITHUB_RAW/socks5.c"
PARSE_URL="$GITHUB_RAW/src/parse.c"
PROTO_URL="$GITHUB_RAW/src/socks5_proto.c"
PARSE_H_URL="$GITHUB_RAW/include/parse.h"
PROTO_H_URL="$GITHUB_RAW/include/socks5_proto.h"

# ======================== 颜色 ========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ======================== 工具函数 ========================

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
title() { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}\n"; }

press_enter() {
    echo ""
    read -rp "$(echo -e "${WHITE}按回车键继续...${NC}")" _
}

confirm() {
    read -rp "$(echo -e "${YELLOW}$1 [y/N]: ${NC}")" yn
    case "$yn" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

# 确保安装目录存在
ensure_dir() {
    [ -d "$INSTALL_DIR" ] || mkdir -p "$INSTALL_DIR"
}

download_file() {
    local url="$1"
    local out="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$out"
    elif command -v wget &>/dev/null; then
        wget -qO "$out" "$url"
    elif command -v fetch &>/dev/null; then
        fetch -qo "$out" "$url"
    else
        error "找不到 curl/wget/fetch, 无法下载"; return 1
    fi
}

# ======================== 安装/更新 ========================

install_or_update() {
    title "安装 / 更新 S5 Scanner"
    ensure_dir

    info "下载源码..."
    mkdir -p "$INSTALL_DIR/src" "$INSTALL_DIR/include"

    download_file "$SRC_URL" "$INSTALL_DIR/$SRC_NAME" || return 1
    download_file "$PARSE_URL" "$INSTALL_DIR/src/parse.c" || return 1
    download_file "$PROTO_URL" "$INSTALL_DIR/src/socks5_proto.c" || return 1
    download_file "$PARSE_H_URL" "$INSTALL_DIR/include/parse.h" || return 1
    download_file "$PROTO_H_URL" "$INSTALL_DIR/include/socks5_proto.h" || return 1

    info "源码已保存至 $INSTALL_DIR"

    info "编译中..."
    cd "$INSTALL_DIR" || return 1
    if cc -o "$BIN_NAME" "$SRC_NAME" src/parse.c src/socks5_proto.c 2>/dev/null; then
        info "编译成功: $INSTALL_DIR/$BIN_NAME"
    elif gcc -o "$BIN_NAME" "$SRC_NAME" src/parse.c src/socks5_proto.c 2>/dev/null; then
        info "编译成功 (gcc): $INSTALL_DIR/$BIN_NAME"
    elif clang -o "$BIN_NAME" "$SRC_NAME" src/parse.c src/socks5_proto.c 2>/dev/null; then
        info "编译成功 (clang): $INSTALL_DIR/$BIN_NAME"
    else
        error "编译失败! 请检查编译器是否安装"
        return 1
    fi
    chmod +x "$INSTALL_DIR/$BIN_NAME"

    # 创建默认文件
    [ -f "$IP_FILE" ]   || touch "$IP_FILE"
    [ -f "$CRED_FILE" ] || touch "$CRED_FILE"

    info "安装完成!"
}

check_installed() {
    if [ ! -f "$INSTALL_DIR/$BIN_NAME" ]; then
        warn "S5 Scanner 尚未安装"
        if confirm "是否立即安装?"; then
            install_or_update
        else
            return 1
        fi
    fi
    return 0
}

# ======================== IP 管理 ========================

show_ip_list() {
    title "当前 IP 列表"
    if [ -f "$IP_FILE" ] && [ -s "$IP_FILE" ]; then
        local count
        count=$(grep -cv '^\s*$\|^\s*#' "$IP_FILE" 2>/dev/null || echo 0)
        echo -e "${WHITE}共 ${GREEN}${count}${WHITE} 条记录:${NC}"
        echo "────────────────────────────────"
        cat -n "$IP_FILE"
        echo "────────────────────────────────"
    else
        warn "IP 列表为空"
    fi
}

add_ip() {
    title "添加 IP 地址"
    echo -e "${WHITE}支持格式:${NC}"
    echo "  单个IP:    192.168.1.1"
    echo "  CIDR:      192.168.1.0/24"
    echo "  范围:      192.168.1.1-192.168.1.100"
    echo "  简写范围:  192.168.1.1-100"
    echo "  多个(逗号): 1.2.3.4,5.6.7.8"
    echo ""
    echo -e "${YELLOW}输入 IP 地址/范围 (输入 q 返回):${NC}"

    while true; do
        read -rp "> " input
        [ "$input" = "q" ] || [ "$input" = "Q" ] && break
        [ -z "$input" ] && continue
        ensure_dir
        echo "$input" >> "$IP_FILE"
        info "已添加: $input"
    done
}

import_ip_file() {
    title "从文件导入 IP"
    read -rp "$(echo -e "${WHITE}输入文件路径: ${NC}")" filepath
    if [ -f "$filepath" ]; then
        ensure_dir
        cat "$filepath" >> "$IP_FILE"
        local count
        count=$(wc -l < "$filepath")
        info "已从 $filepath 导入 ${count} 行"
    else
        error "文件不存在: $filepath"
    fi
}

clear_ip() {
    if confirm "确定清空所有 IP 记录?"; then
        ensure_dir
        : > "$IP_FILE"
        info "IP 列表已清空"
    fi
}

ip_menu() {
    while true; do
        title "IP 地址管理"
        echo -e "  ${GREEN}1.${NC} 查看 IP 列表"
        echo -e "  ${GREEN}2.${NC} 添加 IP 地址"
        echo -e "  ${GREEN}3.${NC} 从文件导入 IP"
        echo -e "  ${GREEN}4.${NC} 清空 IP 列表"
        echo -e "  ${GREEN}5.${NC} 编辑 IP 文件"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        read -rp "$(echo -e "${CYAN}请选择 [0-5]: ${NC}")" choice
        case "$choice" in
            1) show_ip_list; press_enter ;;
            2) add_ip ;;
            3) import_ip_file; press_enter ;;
            4) clear_ip; press_enter ;;
            5)
                ensure_dir
                [ -f "$IP_FILE" ] || touch "$IP_FILE"
                if command -v nano &>/dev/null; then
                    nano "$IP_FILE"
                elif command -v vi &>/dev/null; then
                    vi "$IP_FILE"
                elif command -v ee &>/dev/null; then
                    ee "$IP_FILE"
                else
                    error "找不到编辑器 (nano/vi/ee)"
                    press_enter
                fi
                ;;
            0) return ;;
            *) error "无效选择" ;;
        esac
    done
}

# ======================== 凭证管理 ========================

show_cred_list() {
    title "当前凭证列表"
    if [ -f "$CRED_FILE" ] && [ -s "$CRED_FILE" ]; then
        local count
        count=$(grep -cv '^\s*$\|^\s*#' "$CRED_FILE" 2>/dev/null || echo 0)
        echo -e "${WHITE}共 ${GREEN}${count}${WHITE} 组凭证:${NC}"
        echo "────────────────────────────────"
        cat -n "$CRED_FILE"
        echo "────────────────────────────────"
    else
        warn "凭证列表为空 (将使用内置默认凭证: admin:123, admin:pass, user:pass)"
    fi
}

add_cred() {
    title "添加凭证"
    echo -e "${WHITE}格式: 用户名:密码  (每行一组)${NC}"
    echo -e "${WHITE}示例: admin:123456${NC}"
    echo ""
    echo -e "${YELLOW}输入凭证 (输入 q 返回):${NC}"

    while true; do
        read -rp "> " input
        [ "$input" = "q" ] || [ "$input" = "Q" ] && break
        [ -z "$input" ] && continue
        ensure_dir
        echo "$input" >> "$CRED_FILE"
        info "已添加: $input"
    done
}

add_common_creds() {
    title "添加常用凭证"
    ensure_dir
    local creds=(
        "admin:admin"
        "admin:123456"
        "admin:password"
        "admin:123"
        "admin:pass"
        "root:root"
        "root:123456"
        "root:password"
        "user:user"
        "user:pass"
        "user:123456"
        "test:test"
        "test:123456"
        "proxy:proxy"
        "socks:socks"
    )
    for c in "${creds[@]}"; do
        if ! grep -qF "$c" "$CRED_FILE" 2>/dev/null; then
            echo "$c" >> "$CRED_FILE"
        fi
    done
    info "已添加 ${#creds[@]} 组常用凭证 (自动去重)"
}

clear_cred() {
    if confirm "确定清空所有凭证?"; then
        ensure_dir
        : > "$CRED_FILE"
        info "凭证列表已清空"
    fi
}

cred_menu() {
    while true; do
        title "凭证(用户名/密码)管理"
        echo -e "  ${GREEN}1.${NC} 查看凭证列表"
        echo -e "  ${GREEN}2.${NC} 手动添加凭证"
        echo -e "  ${GREEN}3.${NC} 一键添加常用凭证"
        echo -e "  ${GREEN}4.${NC} 清空凭证列表"
        echo -e "  ${GREEN}5.${NC} 编辑凭证文件"
        echo -e "  ${RED}0.${NC} 返回主菜单"
        echo ""
        read -rp "$(echo -e "${CYAN}请选择 [0-5]: ${NC}")" choice
        case "$choice" in
            1) show_cred_list; press_enter ;;
            2) add_cred ;;
            3) add_common_creds; press_enter ;;
            4) clear_cred; press_enter ;;
            5)
                ensure_dir
                [ -f "$CRED_FILE" ] || touch "$CRED_FILE"
                if command -v nano &>/dev/null; then
                    nano "$CRED_FILE"
                elif command -v vi &>/dev/null; then
                    vi "$CRED_FILE"
                elif command -v ee &>/dev/null; then
                    ee "$CRED_FILE"
                else
                    error "找不到编辑器 (nano/vi/ee)"
                    press_enter
                fi
                ;;
            0) return ;;
            *) error "无效选择" ;;
        esac
    done
}

# ======================== 扫描参数设置 ========================

get_scan_params() {
    local default_port="1080"
    local default_concurrency="1000"
    local default_timeout="5"

    echo ""
    read -rp "$(echo -e "${WHITE}端口范围 [默认: ${GREEN}${default_port}${WHITE}]: ${NC}")" scan_port
    [ -z "$scan_port" ] && scan_port="$default_port"

    read -rp "$(echo -e "${WHITE}并发连接数 [默认: ${GREEN}${default_concurrency}${WHITE}]: ${NC}")" scan_concurrency
    [ -z "$scan_concurrency" ] && scan_concurrency="$default_concurrency"

    read -rp "$(echo -e "${WHITE}超时时间/秒 [默认: ${GREEN}${default_timeout}${WHITE}]: ${NC}")" scan_timeout
    [ -z "$scan_timeout" ] && scan_timeout="$default_timeout"

    echo ""
    echo -e "${WHITE}参数确认:${NC}"
    echo -e "  IP 来源:  ${GREEN}${IP_FILE}${NC}"
    echo -e "  端口:     ${GREEN}${scan_port}${NC}"
    echo -e "  并发:     ${GREEN}${scan_concurrency}${NC}"
    echo -e "  超时:     ${GREEN}${scan_timeout}秒${NC}"
    echo -e "  输出:     ${GREEN}${OUTPUT_FILE}${NC}"

    # 导出参数供调用方使用
    SCAN_PORT="$scan_port"
    SCAN_CONCURRENCY="$scan_concurrency"
    SCAN_TIMEOUT="$scan_timeout"
}

# ======================== 扫描执行 ========================

check_ip_ready() {
    if [ ! -f "$IP_FILE" ] || [ ! -s "$IP_FILE" ]; then
        error "IP 列表为空! 请先添加 IP 地址"
        return 1
    fi
    return 0
}

check_running() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            warn "扫描进程正在运行中 (PID: $pid)"
            echo -e "  ${WHITE}查看日志: ${GREEN}tail -f $LOG_FILE${NC}"
            echo -e "  ${WHITE}停止扫描: ${RED}kill $pid${NC}"
            return 1
        else
            rm -f "$PID_FILE"
        fi
    fi
    return 0
}

# 模式1: 纯扫描 (只探测 SOCKS5 握手，不验证连通性)
run_scan_only() {
    title "模式1: 纯扫描"
    echo -e "${WHITE}只进行 SOCKS5 握手探测，发现开放的代理端口${NC}"
    echo -e "${YELLOW}提示: 此模式速度最快，但可能包含蜜罐${NC}"

    check_installed || return
    check_ip_ready  || { press_enter; return; }
    check_running   && { press_enter; return; }

    get_scan_params
    echo ""
    if ! confirm "确认开始扫描?"; then return; fi

    echo ""
    info "开始纯扫描..."

    cd "$INSTALL_DIR" || return
    ./$BIN_NAME \
        -i "$IP_FILE" \
        -p "$SCAN_PORT" \
        -C "$SCAN_CONCURRENCY" \
        -T "$SCAN_TIMEOUT" \
        -o "$OUTPUT_FILE" 2>&1 | tee "$LOG_FILE"

    echo ""
    if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
        local count
        count=$(wc -l < "$OUTPUT_FILE")
        info "扫描完成! 发现 ${count} 个结果"
        info "结果文件: $OUTPUT_FILE"
    else
        warn "扫描完成, 未发现代理"
    fi
    press_enter
}

# 模式2: 扫描 + 验证 (完整模式)
run_scan_verify() {
    title "模式2: 扫描 + 验证"
    echo -e "${WHITE}探测 SOCKS5 代理并验证连通性 + 尝试凭证认证${NC}"
    echo -e "${YELLOW}提示: 此模式较慢但结果更准确${NC}"

    check_installed || return
    check_ip_ready  || { press_enter; return; }
    check_running   && { press_enter; return; }

    get_scan_params
    echo ""
    if ! confirm "确认开始扫描+验证?"; then return; fi

    echo ""
    info "开始扫描+验证..."

    cd "$INSTALL_DIR" || return
    ./$BIN_NAME \
        -i "$IP_FILE" \
        -p "$SCAN_PORT" \
        -c "$CRED_FILE" \
        -C "$SCAN_CONCURRENCY" \
        -T "$SCAN_TIMEOUT" \
        -o "$OUTPUT_FILE" 2>&1 | tee "$LOG_FILE"

    echo ""
    if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
        local count
        count=$(wc -l < "$OUTPUT_FILE")
        info "扫描+验证完成! 发现 ${count} 个结果"
        info "结果文件: $OUTPUT_FILE"
    else
        warn "扫描完成, 未发现有效代理"
    fi
    press_enter
}

# 模式3: 只验证 (验证已有结果)
run_verify_only() {
    title "模式3: 验证已有结果"
    echo -e "${WHITE}对已发现的代理重新验证连通性${NC}"

    check_installed || return

    # 检查是否有之前的扫描结果
    if [ ! -f "$OUTPUT_FILE" ] || [ ! -s "$OUTPUT_FILE" ]; then
        error "没有找到扫描结果文件 ($OUTPUT_FILE)"
        warn "请先执行模式1或模式2进行扫描"
        press_enter
        return
    fi

    local total
    total=$(wc -l < "$OUTPUT_FILE")
    info "发现 ${total} 条待验证记录"

    # FreeBSD grep 不支持 -oP, 使用 sed 提取 IP:Port
    local verify_list="$INSTALL_DIR/.verify_tmp.txt"
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' "$OUTPUT_FILE" 2>/dev/null | sort -u > "$verify_list" || \
    sed -n 's/^\([0-9.]*:[0-9]*\).*/\1/p' "$OUTPUT_FILE" | sort -u > "$verify_list"

    if [ ! -s "$verify_list" ]; then
        error "无法从结果文件中提取 IP:Port"
        rm -f "$verify_list"
        press_enter
        return
    fi

    local verify_count
    verify_count=$(wc -l < "$verify_list")
    info "提取到 ${verify_count} 个唯一 IP:Port"

    # 将IP提取到临时check文件
    local verify_ip="$INSTALL_DIR/.verify_ip.txt"
    awk -F: '{print $1}' "$verify_list" | sort -u > "$verify_ip"

    # 提取端口
    local verify_ports
    verify_ports=$(awk -F: '{print $2}' "$verify_list" | sort -un | tr '\n' ',' | sed 's/,$//')

    echo ""
    echo -e "  ${WHITE}验证IP数:  ${GREEN}$(wc -l < "$verify_ip")${NC}"
    echo -e "  ${WHITE}验证端口:  ${GREEN}${verify_ports}${NC}"
    echo ""

    local default_concurrency="200"
    local default_timeout="8"
    read -rp "$(echo -e "${WHITE}并发连接数 [默认: ${GREEN}${default_concurrency}${WHITE}]: ${NC}")" vc
    [ -z "$vc" ] && vc="$default_concurrency"
    read -rp "$(echo -e "${WHITE}超时时间/秒 [默认: ${GREEN}${default_timeout}${WHITE}]: ${NC}")" vto
    [ -z "$vto" ] && vto="$default_timeout"

    local verified_output="$INSTALL_DIR/verified.txt"
    echo ""
    if ! confirm "确认开始验证?"; then
        rm -f "$verify_list" "$verify_ip"
        return
    fi

    info "开始验证..."
    cd "$INSTALL_DIR" || return
    ./$BIN_NAME \
        -i "$verify_ip" \
        -p "$verify_ports" \
        -c "$CRED_FILE" \
        -C "$vc" \
        -T "$vto" \
        -o "$verified_output" 2>&1 | tee "$LOG_FILE"

    rm -f "$verify_list" "$verify_ip"

    echo ""
    if [ -f "$verified_output" ] && [ -s "$verified_output" ]; then
        local vcount
        vcount=$(wc -l < "$verified_output")
        info "验证完成! ${vcount} 个代理通过验证"
        info "验证结果: $verified_output"
    else
        warn "验证完成, 无代理通过验证"
    fi
    press_enter
}

# 后台运行
run_background() {
    title "后台扫描"
    echo -e "${WHITE}扫描将在后台运行，可通过日志查看进度${NC}"

    check_installed || return
    check_ip_ready  || { press_enter; return; }
    check_running   && { press_enter; return; }

    get_scan_params
    echo ""
    if ! confirm "确认后台启动?"; then return; fi

    cd "$INSTALL_DIR" || return
    nohup ./$BIN_NAME \
        -i "$IP_FILE" \
        -p "$SCAN_PORT" \
        -c "$CRED_FILE" \
        -C "$SCAN_CONCURRENCY" \
        -T "$SCAN_TIMEOUT" \
        -o "$OUTPUT_FILE" > "$LOG_FILE" 2>&1 &

    local pid=$!
    echo "$pid" > "$PID_FILE"
    info "后台扫描已启动 (PID: $pid)"
    echo ""
    echo -e "  ${WHITE}查看日志:  ${GREEN}tail -f $LOG_FILE${NC}"
    echo -e "  ${WHITE}查看进度:  ${GREEN}cat $LOG_FILE | tail -5${NC}"
    echo -e "  ${WHITE}停止扫描:  ${RED}kill $pid${NC}"
    press_enter
}

# ======================== 查看结果 ========================

view_results() {
    title "扫描结果"
    local found=0

    if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
        echo -e "${GREEN}── socks.txt ──${NC}"
        local count
        count=$(wc -l < "$OUTPUT_FILE")
        echo -e "${WHITE}共 ${GREEN}${count}${WHITE} 条记录:${NC}"
        echo "────────────────────────────────"
        cat "$OUTPUT_FILE"
        echo "────────────────────────────────"
        found=1
    fi

    local verified="$INSTALL_DIR/verified.txt"
    if [ -f "$verified" ] && [ -s "$verified" ]; then
        echo ""
        echo -e "${GREEN}── verified.txt (已验证) ──${NC}"
        local vcount
        vcount=$(wc -l < "$verified")
        echo -e "${WHITE}共 ${GREEN}${vcount}${WHITE} 条记录:${NC}"
        echo "────────────────────────────────"
        cat "$verified"
        echo "────────────────────────────────"
        found=1
    fi

    [ $found -eq 0 ] && warn "暂无扫描结果"
    press_enter
}

# ======================== 卸载 ========================

uninstall() {
    title "卸载 S5 Scanner"
    warn "将删除目录: $INSTALL_DIR"
    echo ""
    if confirm "确定要卸载?"; then
        # 停止运行中的进程
        if [ -f "$PID_FILE" ]; then
            local pid
            pid=$(cat "$PID_FILE")
            kill "$pid" 2>/dev/null && info "已停止运行中的扫描 (PID: $pid)"
        fi
        rm -rf "$INSTALL_DIR"
        info "卸载完成"
    fi
    press_enter
}

# ======================== 主菜单 ========================

print_main_menu() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║${NC}    ${WHITE}${BOLD}S5 Proxy Scanner${NC}  ${BLUE}v4.0${NC}  ${WHITE}for SERV00${NC}          ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""

    # 状态
    local ip_count=0 cred_count=0 result_count=0 status_color="${RED}" status_text="未安装"
    [ -f "$IP_FILE" ] && [ -s "$IP_FILE" ] && ip_count=$(grep -cv '^\s*$\|^\s*#' "$IP_FILE" 2>/dev/null || echo 0)
    [ -f "$CRED_FILE" ] && [ -s "$CRED_FILE" ] && cred_count=$(grep -cv '^\s*$\|^\s*#' "$CRED_FILE" 2>/dev/null || echo 0)
    [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ] && result_count=$(wc -l < "$OUTPUT_FILE")
    [ -f "$INSTALL_DIR/$BIN_NAME" ] && { status_color="${GREEN}"; status_text="已安装"; }

    echo -e "  状态: ${status_color}${status_text}${NC}  |  IP: ${GREEN}${ip_count}${NC}条  |  凭证: ${GREEN}${cred_count}${NC}组  |  结果: ${GREEN}${result_count}${NC}条"

    # 检查后台扫描
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  ${YELLOW}⚡ 后台扫描运行中 (PID: $pid)${NC}"
        fi
    fi

    echo ""
    echo -e "  ${WHITE}${BOLD}── 配置 ──${NC}"
    echo -e "  ${GREEN}1.${NC} IP 地址管理"
    echo -e "  ${GREEN}2.${NC} 凭证(密码)管理"
    echo ""
    echo -e "  ${WHITE}${BOLD}── 扫描模式 ──${NC}"
    echo -e "  ${GREEN}3.${NC} 模式1: 纯扫描          ${WHITE}(快速发现, 不验证)${NC}"
    echo -e "  ${GREEN}4.${NC} 模式2: 扫描 + 验证     ${WHITE}(完整模式, 结果准确)${NC}"
    echo -e "  ${GREEN}5.${NC} 模式3: 只验证           ${WHITE}(重新验证已有结果)${NC}"
    echo -e "  ${GREEN}6.${NC} 后台扫描               ${WHITE}(nohup 不中断)${NC}"
    echo ""
    echo -e "  ${WHITE}${BOLD}── 其他 ──${NC}"
    echo -e "  ${GREEN}7.${NC} 查看扫描结果"
    echo -e "  ${GREEN}8.${NC} 安装 / 更新"
    echo -e "  ${GREEN}9.${NC} 卸载"
    echo -e "  ${RED}0.${NC} 退出"
    echo ""
}

main() {
    while true; do
        print_main_menu
        read -rp "$(echo -e "${CYAN}请选择 [0-9]: ${NC}")" choice
        case "$choice" in
            1) ip_menu ;;
            2) cred_menu ;;
            3) run_scan_only ;;
            4) run_scan_verify ;;
            5) run_verify_only ;;
            6) run_background ;;
            7) view_results ;;
            8) install_or_update; press_enter ;;
            9) uninstall ;;
            0) echo -e "\n${GREEN}再见!${NC}\n"; exit 0 ;;
            *) error "无效选择" ;;
        esac
    done
}

# ======================== 入口 ========================
main "$@"
