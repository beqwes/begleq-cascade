#!/usr/bin/env bash
# begleq-cascade — настройка каскада VPN-нод (вход → выход) на ядерном DNAT.
# Debian/Ubuntu, запуск от root.
#
# DNAT работает в ядре — пакеты идут насквозь, TCP не терминируется,
# поэтому XTLS Vision / Reality-хендшейк проходит без искажений.

set -o pipefail

VERSION="1.0.0"
CONF_DIR="/etc/begleq-cascade"
ROUTES_DB="$CONF_DIR/routes.db"          # proto|in_port|target_ip|target_port|name
SYSCTL_FILE="/etc/sysctl.d/99-begleq-cascade.conf"
LOCK_FILE="/run/begleq-cascade.lock"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

msg()  { echo -e "$1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1" >&2; }
hdr()  { echo -e "\n${CYAN}=== $1 ===${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Нужен root. Запусти через sudo."
        exit 1
    fi
}

# Единственный экземпляр — чтобы два запуска не порвали правила.
acquire_lock() {
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        err "Уже запущен другой экземпляр begleq-cascade."
        exit 1
    fi
}

default_iface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

valid_ip() {
    local ip=$1 o
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a o <<< "$ip"
    for n in "${o[@]}"; do (( n >= 0 && n <= 255 )) || return 1; done
    return 0
}

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

# --- система -----------------------------------------------------------------

# ip_forward: пишем в sysctl.d, а не в sysctl.conf.
# Грабля: `grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf` совпадает с
# ЗАКОММЕНТИРОВАННОЙ строкой, проверка проходит, форвардинг после ребута выключен.
apply_sysctl() {
    hdr "Системные параметры (conntrack, forwarding, BBR)"
    cat > "$SYSCTL_FILE" <<'EOF'
# begleq-cascade — параметры релей-ноды
net.ipv4.ip_forward=1

# Дефолты ядра (max 65536, established 432000 = 5 суток) переполняют
# таблицу conntrack на релее. Симптом: ICMP идёт, а TCP молча дропается.
net.netfilter.nf_conntrack_max=524288
net.netfilter.nf_conntrack_tcp_timeout_established=3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait=30
net.netfilter.nf_conntrack_tcp_timeout_close_wait=30

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    modprobe nf_conntrack 2>/dev/null
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1

    # hashsize задаётся не через sysctl, а параметром модуля.
    if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]]; then
        echo 131072 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null
    fi

    ok "ip_forward = $(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    ok "conntrack_max = $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)"
    ok "Параметры записаны в $SYSCTL_FILE (переживут ребут)"
}

install_deps() {
    local need=()
    for p in iptables-persistent netfilter-persistent conntrack; do
        dpkg -s "$p" >/dev/null 2>&1 || need+=("$p")
    done
    if (( ${#need[@]} )); then
        hdr "Установка зависимостей: ${need[*]}"
        export DEBIAN_FRONTEND=noninteractive
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        apt-get update -qq >/dev/null 2>&1
        if ! apt-get install -y -qq "${need[@]}" >/dev/null 2>&1; then
            warn "Не все пакеты установились — правила могут не пережить ребут."
            return 1
        fi
    fi
    ok "Зависимости на месте"
}

persist_rules() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 && ok "Правила сохранены (переживут ребут)" \
            || warn "netfilter-persistent save не отработал"
    else
        warn "netfilter-persistent не установлен — правила потеряются после ребута"
    fi
}

prepare_system() {
    mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
    touch "$ROUTES_DB"; chmod 600 "$ROUTES_DB"
    install_deps
    apply_sysctl
}

# --- маршруты ----------------------------------------------------------------

db_add() {  # proto in_port ip out_port name
    db_del "$1" "$2"
    echo "$1|$2|$3|$4|$5" >> "$ROUTES_DB"
}

db_del() {  # proto in_port
    [[ -f "$ROUTES_DB" ]] || return 0
    grep -v "^$1|$2|" "$ROUTES_DB" > "$ROUTES_DB.tmp" 2>/dev/null
    mv "$ROUTES_DB.tmp" "$ROUTES_DB"
}

# Снимает все DNAT с тем же протоколом и входящим портом (перезапись маршрута).
drop_existing_dnat() {
    local proto=$1 in_port=$2 line
    while IFS= read -r line; do
        [[ "$line" == *"-j DNAT"* ]] || continue
        [[ "$line" == *"-p $proto"* ]] || continue
        [[ "$line" == *"--dport $in_port "* || "$line" == *"--dport $in_port" ]] || continue
        # shellcheck disable=SC2086
        iptables -t nat -D ${line#-A } 2>/dev/null
    done < <(iptables -t nat -S PREROUTING 2>/dev/null)
}

# Сброс conntrack для порта — иначе живые сессии продолжат идти по старому DNAT.
flush_conntrack_port() {
    local proto=$1 port=$2
    command -v conntrack >/dev/null 2>&1 || return 0
    conntrack -D -p "$proto" --dport "$port" >/dev/null 2>&1
    conntrack -D -p "$proto" --orig-port-dst "$port" >/dev/null 2>&1
    return 0
}

add_route() {  # proto in_port target_ip target_port [name]
    local proto=$1 in_port=$2 tip=$3 tport=$4 name=${5:-}
    local iface; iface=$(default_iface)

    valid_port "$in_port" || { err "Некорректный входящий порт: $in_port"; return 1; }
    valid_ip   "$tip"     || { err "Некорректный IP выхода: $tip"; return 1; }
    valid_port "$tport"   || { err "Некорректный порт выхода: $tport"; return 1; }
    [[ -n "$iface" ]]     || { err "Не удалось определить внешний интерфейс."; return 1; }

    # Порт занят локальным сервисом? DNAT в PREROUTING перехватит трафик
    # раньше него — предупреждаем, чтобы не убить чужой сервис молча.
    if ss -tlnp 2>/dev/null | grep -qE "[:.]$in_port\b"; then
        warn "Порт $in_port уже слушает локальный сервис:"
        ss -tlnp 2>/dev/null | grep -E "[:.]$in_port\b" | sed 's/^/      /'
        warn "DNAT перехватит трафик раньше него."
    fi

    hdr "Маршрут: :$in_port/$proto → $tip:$tport (iface $iface)"
    drop_existing_dnat "$proto" "$in_port"

    if ! iptables -t nat -A PREROUTING -p "$proto" --dport "$in_port" \
            -j DNAT --to-destination "$tip:$tport"; then
        err "Не удалось создать DNAT."
        return 1
    fi
    if ! iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null; then
        if ! iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE; then
            iptables -t nat -D PREROUTING -p "$proto" --dport "$in_port" \
                -j DNAT --to-destination "$tip:$tport" 2>/dev/null
            err "Не удалось создать MASQUERADE на $iface."
            return 1
        fi
    fi
    # FORWARD может стоять в policy DROP (например, из-за docker).
    iptables -C FORWARD -p "$proto" -d "$tip" --dport "$tport" -j ACCEPT 2>/dev/null \
        || iptables -I FORWARD 1 -p "$proto" -d "$tip" --dport "$tport" -j ACCEPT 2>/dev/null

    flush_conntrack_port "$proto" "$in_port"
    db_add "$proto" "$in_port" "$tip" "$tport" "$name"
    persist_rules
    ok "Маршрут поднят: :$in_port/$proto → $tip:$tport"
    msg "${YELLOW}Проверять только С ВНЕШНЕГО хоста${NC} — DNAT живёт в PREROUTING,"
    msg "трафик с самой ноды идёт через OUTPUT и правило не поймает."
}

del_route() {  # proto in_port
    local proto=$1 in_port=$2
    drop_existing_dnat "$proto" "$in_port"
    flush_conntrack_port "$proto" "$in_port"
    db_del "$proto" "$in_port"
    persist_rules
    ok "Маршрут :$in_port/$proto удалён"
}

list_routes() {
    hdr "Активные маршруты (из iptables)"
    local found=0 line proto dport dest
    while IFS= read -r line; do
        [[ "$line" == *"-j DNAT"* ]] || continue
        proto=$(sed -n 's/.*-p \([a-z]*\).*/\1/p' <<< "$line")
        dport=$(sed -n 's/.*--dport \([0-9]*\).*/\1/p' <<< "$line")
        dest=$(sed -n 's/.*--to-destination \([0-9.:]*\).*/\1/p' <<< "$line")
        local name; name=$(awk -F'|' -v p="$proto" -v d="$dport" \
            '$1==p && $2==d {print $5}' "$ROUTES_DB" 2>/dev/null)
        printf "  ${GREEN}:%-6s${NC} %-4s → ${CYAN}%-22s${NC} %s\n" \
            "$dport" "$proto" "$dest" "${name:+[$name]}"
        found=1
    done < <(iptables -t nat -S PREROUTING 2>/dev/null)
    (( found )) || msg "  ${YELLOW}маршрутов нет${NC}"
}

replace_hop() {  # old_ip new_ip
    local old=$1 new=$2 line proto dport oport n=0
    valid_ip "$old" || { err "Некорректный старый IP"; return 1; }
    valid_ip "$new" || { err "Некорректный новый IP"; return 1; }
    hdr "Переключение выхода: $old → $new"
    while IFS= read -r line; do
        [[ "$line" == *"-j DNAT"* && "$line" == *"$old:"* ]] || continue
        proto=$(sed -n 's/.*-p \([a-z]*\).*/\1/p' <<< "$line")
        dport=$(sed -n 's/.*--dport \([0-9]*\).*/\1/p' <<< "$line")
        oport=$(sed -n "s/.*--to-destination $old:\([0-9]*\).*/\1/p" <<< "$line")
        local name; name=$(awk -F'|' -v p="$proto" -v d="$dport" \
            '$1==p && $2==d {print $5}' "$ROUTES_DB" 2>/dev/null)
        add_route "$proto" "$dport" "$new" "$oport" "$name" && n=$((n+1))
    done < <(iptables -t nat -S PREROUTING 2>/dev/null)
    (( n )) && ok "Переключено маршрутов: $n" || warn "Маршрутов с $old не найдено"
}

# --- диагностика -------------------------------------------------------------

# Главная фича: ловит сценарий «пинг идёт, TCP мёртв», который выглядит
# как блокировка провайдера, а на деле — переполненный conntrack на релее.
doctor() {
    local target=${1:-} tport=${2:-}
    msg "\n${MAGENTA}begleq-cascade doctor${NC}"

    hdr "Форвардинг"
    local fwd; fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    [[ "$fwd" == "1" ]] && ok "ip_forward = 1" || err "ip_forward = $fwd — релей работать не будет!"
    if grep -qs '^#net.ipv4.ip_forward' /etc/sysctl.conf; then
        warn "В /etc/sysctl.conf строка ip_forward закомментирована (после ребута может слететь)"
    fi

    hdr "Conntrack"
    local cnt max pct
    cnt=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null)
    max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)
    if [[ -n "$cnt" && -n "$max" && "$max" -gt 0 ]]; then
        pct=$(( cnt * 100 / max ))
        msg "  занято: $cnt / $max (${pct}%)"
        if (( pct >= 80 )); then
            err "Таблица почти полна — новые TCP будут молча дропаться (ICMP при этом идёт!)"
            msg "  Лечение: begleq-cascade tune, затем ребут для очистки таблицы."
        elif (( max <= 65536 )); then
            warn "conntrack_max = $max (дефолт). Для релея мало — запусти: begleq-cascade tune"
        else
            ok "Запас есть"
        fi
    else
        warn "nf_conntrack не загружен"
    fi
    local est; est=$(sysctl -n net.netfilter.nf_conntrack_tcp_timeout_established 2>/dev/null)
    if [[ -n "$est" ]] && (( est > 86400 )); then
        warn "tcp_timeout_established = ${est}с — мёртвые сессии висят сутками, таблица забьётся"
    fi
    if dmesg 2>/dev/null | grep -qi "nf_conntrack: table full"; then
        err "В dmesg есть 'conntrack: table full' — таблица уже переполнялась!"
    fi

    hdr "Правила"
    list_routes
    if [[ -f /etc/iptables/rules.v4 ]] && grep -q "DNAT" /etc/iptables/rules.v4 2>/dev/null; then
        ok "DNAT есть в сохранённых правилах (/etc/iptables/rules.v4)"
    else
        warn "В /etc/iptables/rules.v4 нет DNAT — после ребута маршруты пропадут"
    fi

    if [[ -n "$target" && -n "$tport" ]]; then
        hdr "Доступность выхода $target:$tport"
        local loss ok_cnt=0
        loss=$(ping -c 5 -W 2 "$target" 2>/dev/null | sed -n 's/.*, \([0-9]*\)% packet loss.*/\1/p')
        msg "  ICMP: потерь ${loss:-?}%"
        for _ in 1 2 3 4 5; do
            timeout 4 bash -c "cat < /dev/null > /dev/tcp/$target/$tport" 2>/dev/null && ok_cnt=$((ok_cnt+1))
        done
        msg "  TCP :$tport — успешных коннектов $ok_cnt/5"
        if [[ "${loss:-100}" -lt 50 && $ok_cnt -eq 0 ]]; then
            err "ICMP идёт, а TCP мёртв — почерк переполненного conntrack ЛОКАЛЬНО"
            msg "  (или фильтрации у провайдера). Сначала проверь conntrack выше."
        elif (( ok_cnt < 5 )); then
            warn "TCP нестабилен — цепочка будет рваться"
        elif (( ok_cnt == 5 )); then
            ok "Выход отвечает стабильно"
        fi
    fi
    msg ""
}

# --- меню --------------------------------------------------------------------

ask_route() {  # proto label
    local proto=$1 label=$2 in_port tip tport name
    read -r -p "Входящий порт на этой ноде: " in_port
    read -r -p "IP выходной ноды: " tip
    read -r -p "Порт выходной ноды: " tport
    read -r -p "Название (необязательно): " name
    prepare_system
    add_route "$proto" "$in_port" "$tip" "$tport" "$name"
}

show_menu() {
    while true; do
        echo ""
        echo "------------------------------------------------------"
        echo -e " ${MAGENTA}begleq-cascade${NC} v$VERSION — каскад VPN-нод на DNAT"
        echo "------------------------------------------------------"
        echo -e "1) Добавить маршрут ${CYAN}VLESS / XRay / Trojan${NC} (TCP)"
        echo -e "2) Добавить маршрут ${CYAN}WireGuard / AmneziaWG / Hysteria${NC} (UDP)"
        echo -e "3) ${YELLOW}Переключить выход на другой IP${NC}"
        echo -e "4) Показать маршруты"
        echo -e "5) ${RED}Удалить маршрут${NC}"
        echo -e "6) ${GREEN}Диагностика (doctor)${NC}"
        echo -e "7) Применить тюнинг системы (conntrack/BBR)"
        echo -e "0) Выход"
        echo "------------------------------------------------------"
        read -r -p "Выбор: " c
        case "$c" in
            1) ask_route tcp VLESS ;;
            2) ask_route udp WireGuard ;;
            3) read -r -p "Старый IP: " a; read -r -p "Новый IP: " b; replace_hop "$a" "$b" ;;
            4) list_routes ;;
            5) read -r -p "Протокол (tcp/udp): " p; read -r -p "Входящий порт: " q; del_route "$p" "$q" ;;
            6) read -r -p "IP выхода для проверки (Enter — пропустить): " t
               if [[ -n "$t" ]]; then read -r -p "Порт выхода: " tp; doctor "$t" "$tp"; else doctor; fi ;;
            7) prepare_system ;;
            0) exit 0 ;;
            *) ;;
        esac
        read -r -p "Enter для продолжения..." _
    done
}

usage() {
    cat <<EOF
begleq-cascade v$VERSION — каскад VPN-нод (вход → выход) на ядерном DNAT.

  begleq-cascade                                  интерактивное меню
  begleq-cascade add tcp IN_PORT OUT_IP OUT_PORT [NAME]
  begleq-cascade add udp IN_PORT OUT_IP OUT_PORT [NAME]
  begleq-cascade del tcp|udp IN_PORT
  begleq-cascade list
  begleq-cascade replace-hop OLD_IP NEW_IP
  begleq-cascade doctor [OUT_IP OUT_PORT]
  begleq-cascade tune

Примеры:
  begleq-cascade add tcp 8443 203.0.113.10 2053 finland
  begleq-cascade replace-hop 203.0.113.10 203.0.113.20
  begleq-cascade doctor 203.0.113.10 2053

Важно: DNAT срабатывает в PREROUTING — проверять цепочку нужно С ВНЕШНЕГО хоста,
трафик с самой релей-ноды идёт через OUTPUT и правило не поймает.
EOF
}

check_root
acquire_lock

if (( $# > 0 )); then
    case "$1" in
        add)          shift; [[ $# -ge 4 ]] || { usage; exit 2; }
                      prepare_system; add_route "$1" "$2" "$3" "$4" "${5:-}" ;;
        del|delete)   shift; [[ $# -ge 2 ]] || { usage; exit 2; }; del_route "$1" "$2" ;;
        list|ls)      list_routes ;;
        replace-hop)  shift; [[ $# -ge 2 ]] || { usage; exit 2; }; replace_hop "$1" "$2" ;;
        doctor|check) shift; doctor "${1:-}" "${2:-}" ;;
        tune)         prepare_system ;;
        -h|--help|help) usage ;;
        *) err "Неизвестная команда: $1"; usage >&2; exit 2 ;;
    esac
    exit $?
fi

show_menu
