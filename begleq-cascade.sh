#!/usr/bin/env bash
# begleq-cascade — настройка каскада VPN-нод (вход → выход) на ядерном DNAT.
# Debian/Ubuntu, запуск от root.
#
# DNAT работает в ядре — пакеты идут насквозь, TCP не терминируется,
# поэтому XTLS Vision / Reality-хендшейк проходит без искажений.

set -o pipefail

VERSION="1.5.1"
CONF_DIR="/etc/begleq-cascade"
ROUTES_DB="$CONF_DIR/routes.db"          # proto|in_port|target_ip|target_port|name
EXCEPT_DB="$CONF_DIR/except.db"          # proto|in_port|src_ip; *|*|src_ip — все маршруты
SYSCTL_FILE="/etc/sysctl.d/99-begleq-cascade.conf"
MODULES_FILE="/etc/modules-load.d/begleq-cascade.conf"
MODPROBE_FILE="/etc/modprobe.d/begleq-cascade.conf"
LOCK_FILE="/run/begleq-cascade.lock"
REPO="beqwes/begleq-cascade"
BRANCH="master"
INSTALL_PATH="/usr/local/bin/begleq-cascade"
LIB_BIN="/usr/local/lib/begleq-cascade/begleq-cascade"   # копия для юнита
UNIT_NAME="begleq-cascade.service"
UNIT_FILE="/etc/systemd/system/$UNIT_NAME"

# Метка на всех правилах скрипта: list/del/replace-hop/sync трогают только их.
TAG="begleq-cascade"
CMT=(-m comment --comment "$TAG")

UPDATED_PATH=""     # заполняет self_update: куда записана новая версия
NO_PERSIST=0        # 1 — add_route не сохраняет правила сам (пакетные операции)
DROPPED_DESTS=()    # заполняет drop_existing_dnat: ip:port снятых DNAT

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

# Интерфейс, через который реально уходит трафик к выходу (может быть не
# дефолтным — например, туннель).
route_iface() {  # ip
    local dev
    dev=$(ip route get "$1" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
    echo "${dev:-$(default_iface)}"
}

valid_ip() {
    local ip=$1 o n
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a o <<< "$ip"
    # Ведущие нули запрещены: bash и iptables читают 010 как восьмеричное 8.
    for n in "${o[@]}"; do
        [[ "$n" =~ ^(0|[1-9][0-9]*)$ ]] && (( 10#$n <= 255 )) || return 1
    done
    return 0
}

valid_port() {
    [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 ))
}

valid_proto() {
    [[ "$1" == tcp || "$1" == udp ]]
}

# '|' и перевод строки ломают формат routes.db.
valid_name() {
    [[ "$1" != *"|"* && "$1" != *$'\n'* ]]
}

# Проверка аргументов маршрута до любых изменений в системе.
check_route_args() {  # proto in_port target_ip target_port [name]
    valid_proto "$1"   || { err "Протокол должен быть tcp или udp: $1"; return 1; }
    valid_port  "$2"   || { err "Некорректный входящий порт: $2"; return 1; }
    valid_ip    "$3"   || { err "Некорректный IP выхода: $3"; return 1; }
    valid_port  "$4"   || { err "Некорректный порт выхода: $4"; return 1; }
    valid_name "${5:-}" || { err "Название не должно содержать '|'"; return 1; }
}

# --- система -----------------------------------------------------------------

# ip_forward: пишем в sysctl.d, а не в sysctl.conf.
# Грабля: `grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf` совпадает с
# ЗАКОММЕНТИРОВАННОЙ строкой, проверка проходит, форвардинг после ребута выключен.
# nf_conntrack_max по объёму памяти: запись занимает ~320 байт, таблице
# отдаём не больше 1/16 RAM. 512 МБ → 131072, 2 ГБ → ~420k, потолок 1M.
conntrack_limit() {
    local mem_kb max
    mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
    max=$(( ${mem_kb:-0} * 1024 / 16 / 320 ))
    (( max < 131072 )) && max=131072
    (( max > 1048576 )) && max=1048576
    echo "$max"
}

apply_sysctl() {
    hdr "Системные параметры (conntrack, forwarding, BBR)"
    local ct_max; ct_max=$(conntrack_limit)
    local ct_hash=$(( ct_max / 4 ))
    cat > "$SYSCTL_FILE" <<EOF
# begleq-cascade — параметры релей-ноды
net.ipv4.ip_forward=1

# Дефолты ядра (max 65536, established 432000 = 5 суток) переполняют
# таблицу conntrack на релее. Симптом: ICMP идёт, а TCP молча дропается.
net.netfilter.nf_conntrack_max=$ct_max
net.netfilter.nf_conntrack_tcp_timeout_established=3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait=30
net.netfilter.nf_conntrack_tcp_timeout_close_wait=30

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    # systemd-sysctl применяет sysctl.d рано, до загрузки nf_conntrack, —
    # ключи net.netfilter.* после ребута молча не применятся. Грузим модули
    # через modules-load.d: systemd-sysctl стартует после systemd-modules-load.
    cat > "$MODULES_FILE" <<'EOF'
# begleq-cascade — нужны до применения sysctl.d
nf_conntrack
tcp_bbr
EOF
    # hashsize задаётся не через sysctl, а параметром модуля.
    echo "options nf_conntrack hashsize=$ct_hash" > "$MODPROBE_FILE"

    modprobe nf_conntrack 2>/dev/null
    modprobe tcp_bbr 2>/dev/null
    local out
    if ! out=$(sysctl -p "$SYSCTL_FILE" 2>&1 >/dev/null); then
        warn "Часть параметров не применилась:"
        sed 's/^/      /' <<< "$out"
    fi

    if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]]; then
        echo "$ct_hash" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null
    fi

    ok "ip_forward = $(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    ok "conntrack_max = $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)"
    ok "Параметры записаны в $SYSCTL_FILE, модули — в $MODULES_FILE (переживут ребут)"
}

pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

# iptables-persistent больше не ставим: он конфликтует с ufw (apt снёс бы ufw),
# а `netfilter-persistent save` с docker сохраняет его динамические правила,
# и после ребута они задваиваются. Маршруты восстанавливает свой юнит.
install_deps() {
    local need=() p
    for p in iptables conntrack; do
        pkg_installed "$p" || need+=("$p")
    done
    if (( ${#need[@]} )); then
        hdr "Установка зависимостей: ${need[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null 2>&1
        if ! apt-get install -y -qq "${need[@]}" >/dev/null 2>&1; then
            warn "Не все пакеты установились: ${need[*]}"
            return 1
        fi
    fi
    ok "Зависимости на месте"
}

# systemd-юнит, который при загрузке вызывает `sync` и поднимает маршруты
# из routes.db. Юнит запускает копию скрипта — она не зависит от того,
# откуда и как скачан исходный файл.
install_boot_unit() {
    command -v systemctl >/dev/null 2>&1 \
        || { warn "Нет systemd — маршруты не восстановятся после ребута"; return 1; }
    local self; self=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
    if [[ -f "$self" && "$self" != "$LIB_BIN" ]]; then
        install -D -m 755 "$self" "$LIB_BIN"
    fi
    [[ -x "$LIB_BIN" ]] \
        || { warn "Не удалось сохранить копию скрипта в $LIB_BIN"; return 1; }

    local unit
    unit=$(cat <<EOF
[Unit]
Description=begleq-cascade: восстановление DNAT-маршрутов
Wants=network-online.target
After=network-online.target netfilter-persistent.service docker.service

[Service]
Type=oneshot
ExecStart=$LIB_BIN sync --boot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
)
    if [[ "$(cat "$UNIT_FILE" 2>/dev/null)" != "$unit" ]]; then
        printf '%s\n' "$unit" > "$UNIT_FILE"
        systemctl daemon-reload
    fi
    systemctl is-enabled --quiet "$UNIT_NAME" 2>/dev/null \
        || systemctl enable --quiet "$UNIT_NAME" 2>/dev/null \
        || { warn "Не удалось включить $UNIT_NAME"; return 1; }
}

persist_rules() {
    (( NO_PERSIST )) && return 0
    install_boot_unit && ok "Маршруты восстановятся после ребута ($UNIT_NAME)"
    # Если rules.v4 ведёт netfilter-persistent, держим его актуальным —
    # кроме хостов с docker (см. install_deps).
    if command -v netfilter-persistent >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || warn "netfilter-persistent save не отработал"
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
    chmod 600 "$ROUTES_DB.tmp"
    mv "$ROUTES_DB.tmp" "$ROUTES_DB"
}

# Поля из строки `iptables -S` с DNAT.
dnat_proto() { sed -n 's/.*-p \([a-z]*\) .*/\1/p' <<< "$1"; }
dnat_dport() { sed -n 's/.*--dport \([0-9]*\).*/\1/p' <<< "$1"; }
dnat_dest()  { sed -n 's/.*--to-destination \([0-9.]*:[0-9]*\).*/\1/p' <<< "$1"; }

# Правила begleq-cascade в цепочке (строки `iptables -S` с нашей меткой).
tagged_rules() {  # table chain
    iptables -t "$1" -S "$2" 2>/dev/null | grep -F -- "--comment $TAG"
}

# Содержит ли правило все фрагменты. Пробел в конце строки и фрагментов —
# граница слова: "--dport 44 " не совпадёт с "--dport 443".
rule_has() {  # line frag...
    local line="$1 " f; shift
    for f; do [[ "$line" == *"$f"* ]] || return 1; done
}

# Снимает помеченные правила, содержащие все фрагменты.
del_tagged() {  # table chain frag...
    local t=$1 c=$2 line rules; shift 2
    mapfile -t rules < <(tagged_rules "$t" "$c")
    for line in "${rules[@]}"; do
        rule_has "$line" "$@" || continue
        # shellcheck disable=SC2086
        iptables -t "$t" -D ${line#-A } 2>/dev/null
    done
}

# Есть ли наш DNAT с точно таким назначением (и, если задан, входящим портом).
dnat_exists() {  # proto ip:port [in_port]
    local line frags=("-p $1 " "-j DNAT " "--to-destination $2 ")
    [[ -n "${3:-}" ]] && frags+=("--dport $3 ")
    while IFS= read -r line; do
        rule_has "$line" "${frags[@]}" && return 0
    done < <(tagged_rules nat PREROUTING)
    return 1
}

# Снимает все DNAT с тем же протоколом и входящим портом — и чужие тоже:
# два DNAT на один порт всё равно не работают, сработает первый.
# Снятые назначения складывает в DROPPED_DESTS — для чистки FORWARD/MASQUERADE.
drop_existing_dnat() {
    local proto=$1 in_port=$2 line rules
    DROPPED_DESTS=()
    # Сначала читаем цепочку целиком, потом правим — не меняем её на ходу.
    mapfile -t rules < <(iptables -t nat -S PREROUTING 2>/dev/null)
    for line in "${rules[@]}"; do
        rule_has "$line" "-j DNAT " "-p $proto " "--dport $in_port " || continue
        [[ "$line" == *"--comment $TAG"* ]] \
            || warn "Снимаю чужое DNAT-правило на том же порту: $line"
        # shellcheck disable=SC2086
        iptables -t nat -D ${line#-A } 2>/dev/null && DROPPED_DESTS+=("$(dnat_dest "$line")")
    done
}

# Ставит правила маршрута; каждое — только если его ещё нет (идемпотентно).
apply_route_rules() {  # proto in_port target_ip target_port iface
    local proto=$1 in_port=$2 tip=$3 tport=$4 iface=$5
    local dnat=(-p "$proto" --dport "$in_port" "${CMT[@]}" -j DNAT --to-destination "$tip:$tport")
    # MASQUERADE только для трафика к выходу, а не для всего интерфейса.
    local masq=(-o "$iface" -p "$proto" -d "$tip" --dport "$tport" "${CMT[@]}" -j MASQUERADE)
    local fwd=(-p "$proto" -d "$tip" --dport "$tport" "${CMT[@]}" -j ACCEPT)
    # shellcheck disable=SC2054  # запятая — часть синтаксиса --ctstate
    local est=(-m conntrack --ctstate ESTABLISHED,RELATED "${CMT[@]}" -j ACCEPT)

    if ! iptables -t nat -C PREROUTING "${dnat[@]}" 2>/dev/null \
            && ! iptables -t nat -A PREROUTING "${dnat[@]}"; then
        err "Не удалось создать DNAT."
        return 1
    fi
    if ! iptables -t nat -C POSTROUTING "${masq[@]}" 2>/dev/null; then
        # Интерфейс мог смениться — старое правило для этого выхода убираем.
        del_tagged nat POSTROUTING "-p $proto " "-d $tip/32 " "--dport $tport " "-j MASQUERADE "
        if ! iptables -t nat -A POSTROUTING "${masq[@]}"; then
            iptables -t nat -D PREROUTING "${dnat[@]}" 2>/dev/null
            err "Не удалось создать MASQUERADE на $iface."
            return 1
        fi
    fi
    # FORWARD может стоять в policy DROP (например, из-за docker или ufw).
    # Нужны оба направления: ACCEPT к выходу и ESTABLISHED для ответов,
    # иначе ответные пакеты выхода → клиент дропнутся.
    iptables -C FORWARD "${fwd[@]}" 2>/dev/null || iptables -I FORWARD 1 "${fwd[@]}"
    iptables -C FORWARD "${est[@]}" 2>/dev/null || iptables -I FORWARD 1 "${est[@]}"
    return 0
}

# Правила FORWARD/MASQUERADE для назначения больше не нужны, если на него
# не ссылается ни один наш DNAT — снимаем, чтобы не копился мусор.
cleanup_dest() {  # proto ip:port
    local proto=$1 dest=$2 ip port
    [[ -n "$dest" ]] || return 0
    dnat_exists "$proto" "$dest" && return 0
    ip=${dest%:*}; port=${dest#*:}
    del_tagged filter FORWARD "-p $proto " "-d $ip/32 " "--dport $port " "-j ACCEPT "
    del_tagged nat POSTROUTING "-p $proto " "-d $ip/32 " "--dport $port " "-j MASQUERADE "
    # Правило версии 1.0 — без метки.
    while iptables -D FORWARD -p "$proto" -d "$ip" --dport "$port" -j ACCEPT 2>/dev/null; do :; done
    # ESTABLISHED нужен, пока жив хоть один маршрут.
    if ! tagged_rules nat PREROUTING | grep -qF -- "-j DNAT"; then
        del_tagged filter FORWARD "-m conntrack "
    fi
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

    check_route_args "$proto" "$in_port" "$tip" "$tport" "$name" || return 1
    local iface; iface=$(route_iface "$tip")
    [[ -n "$iface" ]] || { err "Не удалось определить интерфейс до $tip."; return 1; }

    # Порт занят локальным сервисом? DNAT в PREROUTING перехватит трафик
    # раньше него — предупреждаем, чтобы не убить чужой сервис молча.
    local ssflag=-tlnp; [[ "$proto" == udp ]] && ssflag=-ulnp
    if ss "$ssflag" 2>/dev/null | grep -qE "[:.]$in_port\b"; then
        warn "Порт $in_port/$proto уже слушает локальный сервис:"
        ss "$ssflag" 2>/dev/null | grep -E "[:.]$in_port\b" | sed 's/^/      /'
        warn "DNAT перехватит трафик раньше него."
        msg "  Если Reality на выходе берёт маскировочный сайт отсюда (target = домен"
        msg "  этого сервера), исключи выход из пересылки, иначе будет петля:"
        msg "    begleq-cascade except add $proto $in_port $tip"
    fi

    hdr "Маршрут: :$in_port/$proto → $tip:$tport (iface $iface)"
    drop_existing_dnat "$proto" "$in_port"
    local old_dests=("${DROPPED_DESTS[@]}") d

    apply_route_rules "$proto" "$in_port" "$tip" "$tport" "$iface" || return 1
    for d in "${old_dests[@]}"; do
        [[ "$d" == "$tip:$tport" ]] || cleanup_dest "$proto" "$d"
    done

    flush_conntrack_port "$proto" "$in_port"
    db_add "$proto" "$in_port" "$tip" "$tport" "$name"
    sync_excepts   # исключения «для всех маршрутов» касаются и нового
    persist_rules
    ok "Маршрут поднят: :$in_port/$proto → $tip:$tport"
    msg "${YELLOW}Проверять только С ВНЕШНЕГО хоста${NC} — DNAT живёт в PREROUTING,"
    msg "трафик с самой ноды идёт через OUTPUT и правило не поймает."
}

del_route() {  # proto in_port
    local proto=$1 in_port=$2 d
    valid_proto "$proto"  || { err "Протокол должен быть tcp или udp: $proto"; return 1; }
    valid_port "$in_port" || { err "Некорректный входящий порт: $in_port"; return 1; }
    drop_existing_dnat "$proto" "$in_port"
    if (( ${#DROPPED_DESTS[@]} == 0 )); then
        warn "DNAT для :$in_port/$proto не найден"
    fi
    for d in "${DROPPED_DESTS[@]}"; do cleanup_dest "$proto" "$d"; done
    flush_conntrack_port "$proto" "$in_port"
    db_del "$proto" "$in_port"
    except_drop_port "$proto" "$in_port"
    persist_rules
    ok "Маршрут :$in_port/$proto удалён"
}

route_name() {  # proto in_port
    awk -F'|' -v p="$1" -v d="$2" '$1==p && $2==d {print $5}' "$ROUTES_DB" 2>/dev/null
}

# IP-исключения маршрута: свои (proto|port|ip) и общие (*|*|ip, с пометкой).
route_excepts() {  # proto in_port
    awk -F'|' -v p="$1" -v d="$2" '
        $1==p && $2==d { out = out sep $3; sep = ", " }
        $1=="*"        { out = out sep $3 " (все маршруты)"; sep = ", " }
        END { print out }' "$EXCEPT_DB" 2>/dev/null
}

list_routes() {
    hdr "Активные маршруты (из iptables)"
    local found=0 line proto dport dest name exc foreign orphans
    while IFS= read -r line; do
        [[ "$line" == *"-j DNAT"* ]] || continue
        proto=$(dnat_proto "$line"); dport=$(dnat_dport "$line"); dest=$(dnat_dest "$line")
        name=$(route_name "$proto" "$dport")
        printf "  ${GREEN}:%-6s${NC} %-4s → ${CYAN}%-22s${NC} %s\n" \
            "$dport" "$proto" "$dest" "${name:+[$name]}"
        # Исключения — не маршруты, а адреса, которые этот маршрут пропускает
        # в локальный сервис. Показываем их под маршрутом.
        exc=$(route_excepts "$proto" "$dport")
        [[ -n "$exc" ]] && printf "          ${YELLOW}кроме подключений с:${NC} %s → идут в локальный сервис\n" "$exc"
        found=1
    done < <(tagged_rules nat PREROUTING)
    (( found )) || msg "  ${YELLOW}маршрутов нет${NC}"
    # Исключения для порта, на котором маршрута нет (например, ещё не добавлен).
    orphans=$(awk -F'|' '$1!="*" && $3!="" {print $1 "|" $2 "|" $3}' "$EXCEPT_DB" 2>/dev/null \
        | while IFS='|' read -r proto dport line; do
              route_exists "$proto" "$dport" || echo "  :$dport/$proto — $line"
          done)
    if [[ -n "$orphans" ]]; then
        msg "  Исключения без маршрута (заработают, когда маршрут появится):"
        msg "$orphans"
    fi
    foreign=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -F -- "-j DNAT" \
        | grep -cvF -- "--comment $TAG")
    (( foreign )) && msg "  (ещё DNAT-правил не от begleq-cascade: $foreign — не трогаю)"
    return 0
}

replace_hop() {  # old_ip new_ip
    local old=$1 new=$2 line proto dport oport rules n=0
    valid_ip "$old" || { err "Некорректный старый IP"; return 1; }
    valid_ip "$new" || { err "Некорректный новый IP"; return 1; }
    hdr "Переключение выхода: $old → $new"
    # Снимок цепочки до изменений: add_route правит PREROUTING по ходу цикла.
    mapfile -t rules < <(tagged_rules nat PREROUTING)
    NO_PERSIST=1
    for line in "${rules[@]}"; do
        # Точное совпадение IP: подстрока "$old:" ловила бы и 11.2.3.4 при old=1.2.3.4.
        [[ "$line" == *"-j DNAT"* && "$line" == *"--to-destination $old:"* ]] || continue
        proto=$(dnat_proto "$line"); dport=$(dnat_dport "$line")
        oport=${line##*--to-destination "$old":}; oport=${oport%% *}
        add_route "$proto" "$dport" "$new" "$oport" "$(route_name "$proto" "$dport")" && n=$((n+1))
    done
    NO_PERSIST=0
    if (( n )); then
        persist_rules
        ok "Переключено маршрутов: $n"
    else
        warn "Маршрутов с $old не найдено"
    fi
}

# --- исключения -------------------------------------------------------------
# Подключения с этих IP не пересылаются, а попадают в локальный сервис.
# Нужно, когда Reality на выходе берёт маскировочный сайт отсюда (target =
# домен этого сервера): без исключения её запрос за сайтом уйдёт по DNAT
# обратно на неё же — петля, сайт не открывается.
#
# Исключение бывает для одного маршрута (tcp|443|IP) или для всех (*|*|IP).
# «Для всех» разворачивается в RETURN на порт каждого маршрута, а не в общий
# `-s IP -j RETURN`: тот увёл бы IP и мимо `-j DOCKER`, сломав ему
# опубликованные порты контейнеров.

except_src() { sed -n 's/.*-s \([0-9.]*\)\/32 .*/\1/p' <<< "$1"; }

route_exists() {  # proto in_port
    awk -F'|' -v p="$1" -v d="$2" '$1==p && $2==d {f=1} END {exit !f}' "$ROUTES_DB" 2>/dev/null
}

# Удаляет из файла строки, точно равные данной.
file_drop_line() {  # file line
    [[ -f "$1" ]] || return 0
    grep -vxF -- "$2" "$1" > "$1.tmp" 2>/dev/null
    chmod 600 "$1.tmp"; mv "$1.tmp" "$1"
}

# Пары «proto port», на которые действует исключение.
except_ports() {  # proto in_port
    if [[ "$1" == "*" ]]; then
        awk -F'|' 'NF >= 2 && $1 != "" {print $1, $2}' "$ROUTES_DB" 2>/dev/null
    else
        echo "$1 $2"
    fi
}

# RETURN всегда вставляется в начало цепочки, а DNAT добавляется в конец —
# так исключение срабатывает раньше пересылки, в том числе после sync.
apply_except_rule() {  # proto in_port src_ip
    local p d r rc=0
    while read -r p d; do
        r=(-s "$3" -p "$p" --dport "$d" "${CMT[@]}" -j RETURN)
        iptables -t nat -C PREROUTING "${r[@]}" 2>/dev/null \
            || iptables -t nat -I PREROUTING 1 "${r[@]}" || rc=1
    done < <(except_ports "$1" "$2")
    return $rc
}

check_except_args() {  # proto in_port src_ip
    if [[ "$1" != "*" || "$2" != "*" ]]; then
        valid_proto "$1" || { err "Протокол должен быть tcp или udp: $1"; return 1; }
        valid_port  "$2" || { err "Некорректный входящий порт: $2"; return 1; }
    fi
    valid_ip "$3" || { err "Некорректный IP: $3"; return 1; }
}

except_desc() {  # proto in_port
    if [[ "$1" == "*" ]]; then echo "все маршруты"; else echo ":$2/$1"; fi
}

except_add() {  # proto in_port src_ip   (или * * src_ip — для всех маршрутов)
    check_except_args "$@" || return 1
    mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
    apply_except_rule "$@" || { err "Не удалось добавить исключение."; return 1; }
    if ! grep -qxF -- "$1|$2|$3" "$EXCEPT_DB" 2>/dev/null; then
        echo "$1|$2|$3" >> "$EXCEPT_DB"
    fi
    chmod 600 "$EXCEPT_DB"
    # Уже открытые соединения с этого IP идут по старому DNAT — сбрасываем.
    if command -v conntrack >/dev/null 2>&1; then
        local p d
        while read -r p d; do
            conntrack -D -p "$p" -s "$3" --orig-port-dst "$d" >/dev/null 2>&1
        done < <(except_ports "$1" "$2")
    fi
    persist_rules
    ok "Исключение: подключения с $3 ($(except_desc "$1" "$2")) идут в локальный сервис"
    if [[ "$1" == "*" ]]; then
        [[ -s "$ROUTES_DB" ]] || warn "Маршрутов пока нет — исключение заработает вместе с ними"
    else
        route_exists "$1" "$2" || warn "Маршрута :$2/$1 пока нет — исключение заработает вместе с ним"
    fi
}

except_del() {  # proto in_port src_ip   (или * * src_ip)
    check_except_args "$@" || return 1
    if ! grep -qxF -- "$1|$2|$3" "$EXCEPT_DB" 2>/dev/null; then
        warn "Исключения для $3 ($(except_desc "$1" "$2")) нет"
        return 1
    fi
    file_drop_line "$EXCEPT_DB" "$1|$2|$3"
    sync_excepts   # снимет RETURN, которые больше ничем не покрыты
    persist_rules
    ok "Исключение для $3 ($(except_desc "$1" "$2")) снято"
}

# Исключения порта без маршрута бессмысленны — снимаются вместе с маршрутом.
# Исключения «для всех» остаются в базе, их RETURN на этот порт уберёт sync.
except_drop_port() {  # proto in_port
    if [[ -f "$EXCEPT_DB" ]]; then
        awk -F'|' -v p="$1" -v d="$2" '!($1==p && $2==d)' "$EXCEPT_DB" > "$EXCEPT_DB.tmp"
        chmod 600 "$EXCEPT_DB.tmp"; mv "$EXCEPT_DB.tmp" "$EXCEPT_DB"
    fi
    sync_excepts
}

# Ручное исключение вида `-s IP -p tcp --dport 443 -j RETURN` для порта
# нашего маршрута (или общее `-s IP -j RETURN`) берём под управление: помечаем и пишем в базу, иначе
# после ребута юнит поднимет DNAT, а исключение пропадёт — вернётся петля.
adopt_manual_excepts() {
    [[ -s "$ROUTES_DB" ]] || return 0
    local rules line src proto port n=0
    local re='^-A PREROUTING -s ([0-9.]+)/32 -p (tcp|udp) -m (tcp|udp) --dport ([0-9]+) -j RETURN$'
    local re_all='^-A PREROUTING -s ([0-9.]+)/32 -j RETURN$'
    mapfile -t rules < <(iptables -t nat -S PREROUTING 2>/dev/null)
    for line in "${rules[@]}"; do
        if [[ "$line" =~ $re ]]; then
            src=${BASH_REMATCH[1]}; proto=${BASH_REMATCH[2]}; port=${BASH_REMATCH[4]}
            route_exists "$proto" "$port" || continue
        elif [[ "$line" =~ $re_all ]]; then
            src=${BASH_REMATCH[1]}; proto="*"; port="*"
        else
            continue
        fi
        NO_PERSIST=1 except_add "$proto" "$port" "$src" >/dev/null || continue
        # shellcheck disable=SC2086
        iptables -t nat -D ${line#-A } 2>/dev/null
        ok "Ручное исключение $src ($(except_desc "$proto" "$port")) взято под управление (переживёт ребут)"
        n=$((n+1))
    done
    (( n )) && persist_rules
    return 0
}

# Поднимает исключения из базы и снимает помеченные, которых в базе нет.
sync_excepts() {
    local proto port src line rules keys=" "
    if [[ -f "$EXCEPT_DB" ]]; then
        while IFS='|' read -r proto port src; do
            [[ -n "$proto" ]] || continue
            check_except_args "$proto" "$port" "$src" 2>/dev/null || continue
            local p d
            while read -r p d; do keys+="$p/$d/$src "; done < <(except_ports "$proto" "$port")
            apply_except_rule "$proto" "$port" "$src"
        done < "$EXCEPT_DB"
    fi
    mapfile -t rules < <(tagged_rules nat PREROUTING)
    for line in "${rules[@]}"; do
        [[ "$line" == *"-j RETURN"* ]] || continue
        [[ "$keys" == *" $(dnat_proto "$line")/$(dnat_dport "$line")/$(except_src "$line") "* ]] && continue
        # shellcheck disable=SC2086
        iptables -t nat -D ${line#-A } 2>/dev/null
    done
}

# v1.0 ставила правила без метки. Помечаем те, что совпадают с routes.db, —
# дальше скрипт работает только с помеченными.
migrate_legacy() {
    [[ -s "$ROUTES_DB" ]] || return 0
    local rules line proto in_port tip tport name iface n=0
    mapfile -t rules < <(iptables -t nat -S PREROUTING 2>/dev/null)
    while IFS='|' read -r proto in_port tip tport name; do
        valid_proto "$proto" && valid_port "$in_port" && valid_ip "$tip" && valid_port "$tport" || continue
        for line in "${rules[@]}"; do
            [[ "$line" == *"--comment"* ]] && continue
            rule_has "$line" "-j DNAT " "-p $proto " "--dport $in_port " "--to-destination $tip:$tport " || continue
            iface=$(route_iface "$tip")
            [[ -n "$iface" ]] || continue
            # shellcheck disable=SC2086
            iptables -t nat -D ${line#-A } 2>/dev/null
            while iptables -D FORWARD -p "$proto" -d "$tip" --dport "$tport" -j ACCEPT 2>/dev/null; do :; done
            apply_route_rules "$proto" "$in_port" "$tip" "$tport" "$iface" && n=$((n+1))
        done
    done < "$ROUTES_DB"
    if (( n )); then
        ok "Правила версии 1.0 помечены меткой $TAG: $n"
        persist_rules
    fi
}

# Приводит iptables к routes.db: ставит недостающие маршруты и снимает
# помеченные, которых в базе нет. Юнит вызывает это при загрузке.
sync_routes() {
    hdr "Синхронизация маршрутов с $ROUTES_DB"
    local proto in_port tip tport name iface line d rules old n=0 keys=" "
    if [[ -f "$ROUTES_DB" ]]; then
        while IFS='|' read -r proto in_port tip tport name; do
            [[ -n "$proto" ]] || continue
            if ! check_route_args "$proto" "$in_port" "$tip" "$tport" "$name" 2>/dev/null; then
                warn "Пропущена битая строка базы: $proto|$in_port|$tip|$tport"
                continue
            fi
            keys+="$proto/$in_port "
            iface=$(route_iface "$tip")
            [[ -n "$iface" ]] || { warn "Нет маршрута до $tip — :$in_port/$proto пропущен"; continue; }
            old=()
            if ! dnat_exists "$proto" "$tip:$tport" "$in_port"; then
                drop_existing_dnat "$proto" "$in_port"
                old=("${DROPPED_DESTS[@]}")
            fi
            apply_route_rules "$proto" "$in_port" "$tip" "$tport" "$iface" && n=$((n+1))
            for d in "${old[@]}"; do
                [[ "$d" == "$tip:$tport" ]] || cleanup_dest "$proto" "$d"
            done
        done < "$ROUTES_DB"
    fi
    # Помеченные DNAT не из базы (например, восстановленные из старого rules.v4).
    mapfile -t rules < <(tagged_rules nat PREROUTING)
    for line in "${rules[@]}"; do
        [[ "$line" == *"-j DNAT"* ]] || continue
        proto=$(dnat_proto "$line"); in_port=$(dnat_dport "$line")
        [[ "$keys" == *" $proto/$in_port "* ]] && continue
        # shellcheck disable=SC2086
        iptables -t nat -D ${line#-A } 2>/dev/null
        cleanup_dest "$proto" "$(dnat_dest "$line")"
        warn "Снят маршрут, которого нет в базе: :$in_port/$proto"
    done
    sync_excepts
    ok "Маршрутов в работе: $n"
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
    # Локальный сервис на порту маршрута, а выход не исключён — признак
    # будущей петли, если Reality на выходе берёт сайт отсюда.
    local r_proto r_port r_ip _rest ssflag
    while IFS='|' read -r r_proto r_port r_ip _rest; do
        [[ -n "$r_proto" ]] || continue
        ssflag=-tlnp; [[ "$r_proto" == udp ]] && ssflag=-ulnp
        ss "$ssflag" 2>/dev/null | grep -qE "[:.]$r_port\b" || continue
        grep -qxF -e "$r_proto|$r_port|$r_ip" -e "*|*|$r_ip" "$EXCEPT_DB" 2>/dev/null && continue
        warn ":$r_port/$r_proto слушает локальный сервис, но $r_ip не исключён из пересылки."
        msg "  Если Reality на $r_ip берёт сайт отсюда — это петля. Лечение:"
        msg "    begleq-cascade except add $r_proto $r_port $r_ip"
    done < <(cat "$ROUTES_DB" 2>/dev/null)
    if systemctl is-enabled --quiet "$UNIT_NAME" 2>/dev/null; then
        ok "Автовосстановление после ребута включено ($UNIT_NAME)"
    elif [[ -s "$ROUTES_DB" ]]; then
        warn "$UNIT_NAME не включён — после ребута маршруты пропадут. Запусти: begleq-cascade sync"
    fi
    local line
    while IFS= read -r line; do
        [[ "$line" =~ ^-A\ POSTROUTING\ -o\ ([^ ]+)\ -j\ MASQUERADE$ ]] || continue
        warn "Общее правило MASQUERADE на ${BASH_REMATCH[1]} (так делала v1.0) — маскирует весь трафик."
        msg "  Если оно не нужно другим сервисам: iptables -t nat -D POSTROUTING -o ${BASH_REMATCH[1]} -j MASQUERADE"
    done < <(iptables -t nat -S POSTROUTING 2>/dev/null)
    if command -v docker >/dev/null 2>&1 && command -v netfilter-persistent >/dev/null 2>&1; then
        warn "docker + netfilter-persistent: rules.v4 не обновляю (правила docker задвоятся после ребута)."
        msg "  Маршруты поднимает $UNIT_NAME, rules.v4 для них не нужен."
    fi

    if [[ -n "$target" || -n "$tport" ]] && ! { valid_ip "$target" && valid_port "$tport"; }; then
        err "Проверка выхода пропущена: нужен корректный IP и порт ($target $tport)"
    elif [[ -n "$target" ]]; then
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

# --- обновление --------------------------------------------------------------

fetch() {  # url [header] → stdout
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 30 ${2:+-H "$2"} "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- --timeout=30 ${2:+--header="$2"} "$1"
    else
        err "Нет ни curl, ни wget."; return 1
    fi
}

# Качает свежую версию и ставит её вместо текущей.
# Файл берётся по SHA последнего коммита, а не по имени ветки: raw.githubusercontent
# кэширует ветку до ~5 минут и может отдать старую версию.
self_update() {
    hdr "Обновление begleq-cascade"
    local sha url tmp target new_ver
    sha=$(fetch "https://api.github.com/repos/$REPO/commits/$BRANCH" \
        "Accept: application/vnd.github.sha" 2>/dev/null)
    if [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
        url="https://raw.githubusercontent.com/$REPO/$sha/begleq-cascade.sh"
    else
        warn "GitHub API недоступен — качаю по ветке (может отдать версию из кэша)"
        url="https://raw.githubusercontent.com/$REPO/$BRANCH/begleq-cascade.sh"
        sha=""
    fi

    tmp=$(mktemp) || return 1
    if ! fetch "$url" > "$tmp" || [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"; err "Не удалось скачать $url"; return 1
    fi
    # Проверяем, что скачался именно скрипт и он синтаксически цел.
    if [[ "$(head -n1 "$tmp")" != "#!/usr/bin/env bash" ]] \
            || ! grep -q '^VERSION=' "$tmp" || ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"; err "Скачанный файл не похож на begleq-cascade — обновление отменено."; return 1
    fi
    new_ver=$(sed -n 's/^VERSION="\(.*\)"/\1/p' "$tmp" | head -n1)

    # Ставим туда, откуда запущены; при запуске не из файла — в $INSTALL_PATH.
    target=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
    [[ -f "$target" && "$target" != "$LIB_BIN" ]] || target=$INSTALL_PATH

    if cmp -s "$tmp" "$target"; then
        rm -f "$tmp"
        ok "Уже последняя версия: v$VERSION${sha:+ (${sha:0:7})}"
        return 0
    fi
    # Через mv, а не перезаписью: bash читает скрипт по ходу выполнения,
    # и правка файла под работающим процессом его ломает. mv подменяет inode.
    if ! install -m 755 "$tmp" "$target.new" || ! mv -f "$target.new" "$target"; then
        rm -f "$tmp" "$target.new"; err "Не удалось записать $target"; return 1
    fi
    # Копию для юнита обновляем сразу — иначе при ребуте отработает старая.
    [[ -f "$LIB_BIN" ]] && install -m 755 "$tmp" "$LIB_BIN"
    rm -f "$tmp"
    ok "Обновлено: v$VERSION → v$new_ver${sha:+ (${sha:0:7})}"
    UPDATED_PATH=$target
}

# --- меню --------------------------------------------------------------------

ask_route() {  # proto
    local proto=$1 in_port tip tport name
    read -r -p "Входящий порт на этой ноде: " in_port
    read -r -p "IP выходной ноды: " tip
    read -r -p "Порт выходной ноды: " tport
    read -r -p "Название (необязательно): " name
    check_route_args "$proto" "$in_port" "$tip" "$tport" "$name" || return 1
    prepare_system
    add_route "$proto" "$in_port" "$tip" "$tport" "$name"
}

# Исключение из меню: для одного маршрута (по номеру, IP по умолчанию — его
# выход) или для всех маршрутов сразу по IP. Повтор того же снимает исключение.
ask_except() {
    hdr "Исключение из пересылки"
    msg "Нужно, если на этом сервере стоит маскировочный сайт, а Reality на выходе"
    msg "берёт его отсюда (target = домен этого сервера). Подключения с указанного"
    msg "IP пойдут в локальный nginx, а не обратно на выход — иначе петля."
    local routes=() line i proto port tip tport name ip mode a
    while IFS= read -r line; do
        [[ -n "$line" ]] && routes+=("$line")
    done < <(cat "$ROUTES_DB" 2>/dev/null)
    list_routes
    msg ""
    msg "  1) Для одного маршрута"
    msg "  2) Для всех маршрутов — по IP"
    read -r -p "Выбор [1]: " mode
    if [[ "$mode" == 2 ]]; then
        read -r -p "IP, который не пересылать: " ip
        proto="*"; port="*"
    else
        if (( ${#routes[@]} == 0 )); then
            warn "Маршрутов нет — выбери 2 или сначала добавь маршрут (пункт 1 или 2)."
            return 1
        fi
        for i in "${!routes[@]}"; do
            IFS='|' read -r proto port tip tport name <<< "${routes[i]}"
            printf "  %d) :%s/%s → %s:%s %s\n" $((i+1)) "$port" "$proto" "$tip" "$tport" "${name:+[$name]}"
        done
        read -r -p "Номер маршрута: " i
        if ! [[ "$i" =~ ^[0-9]+$ ]] || (( i < 1 || i > ${#routes[@]} )); then
            err "Нет маршрута с номером '$i'"; return 1
        fi
        IFS='|' read -r proto port tip tport name <<< "${routes[i-1]}"
        read -r -p "IP, который не пересылать [Enter — $tip, выход]: " ip
        ip=${ip:-$tip}
    fi
    if grep -qxF -- "$proto|$port|$ip" "$EXCEPT_DB" 2>/dev/null; then
        read -r -p "Исключение для $ip уже есть. Снять его? (y/N): " a
        [[ "$a" == [yYдД]* ]] && except_del "$proto" "$port" "$ip"
        return 0
    fi
    except_add "$proto" "$port" "$ip"
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
        echo -e "8) Восстановить маршруты из базы (sync)"
        echo -e "9) Исключение: не пересылать подключения с IP"
        echo -e "u) Обновить скрипт"
        echo -e "0) Выход"
        echo "------------------------------------------------------"
        read -r -p "Выбор: " c
        case "$c" in
            1) ask_route tcp ;;
            2) ask_route udp ;;
            3) read -r -p "Старый IP: " a; read -r -p "Новый IP: " b; replace_hop "$a" "$b" ;;
            4) list_routes ;;
            5) read -r -p "Протокол (tcp/udp): " p; read -r -p "Входящий порт: " q; del_route "$p" "$q" ;;
            6) read -r -p "IP выхода для проверки (Enter — пропустить): " t
               if [[ -n "$t" ]]; then read -r -p "Порт выхода: " tp; doctor "$t" "$tp"; else doctor; fi ;;
            7) prepare_system ;;
            8) sync_routes; persist_rules ;;
            9) ask_except ;;
            u|U) UPDATED_PATH=""; self_update
                 # Перезапуск уже новой версией (лок освободится при exec).
                 if [[ -n "$UPDATED_PATH" ]]; then
                     read -r -p "Enter — перезапустить меню..." _
                     exec "$UPDATED_PATH"
                 fi ;;
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
  begleq-cascade except add|del tcp|udp IN_PORT SRC_IP
                                                  не пересылать SRC_IP на этом маршруте
  begleq-cascade except add|del SRC_IP            не пересылать SRC_IP ни на одном маршруте
  begleq-cascade sync                             поднять маршруты из базы
  begleq-cascade update                           обновить скрипт с GitHub
  begleq-cascade tune

Примеры:
  begleq-cascade add tcp 8443 203.0.113.10 2053 finland
  begleq-cascade replace-hop 203.0.113.10 203.0.113.20
  begleq-cascade doctor 203.0.113.10 2053
  begleq-cascade except add tcp 443 203.0.113.10  (Reality берёт сайт отсюда)

Только IPv4. Маршруты хранятся в $ROUTES_DB и поднимаются
после ребута юнитом $UNIT_NAME.

Важно: DNAT срабатывает в PREROUTING — проверять цепочку нужно С ВНЕШНЕГО хоста,
трафик с самой релей-ноды идёт через OUTPUT и правило не поймает.
EOF
}

case "${1:-}" in -h|--help|help) usage; exit 0 ;; esac

check_root
acquire_lock
migrate_legacy
adopt_manual_excepts

if (( $# > 0 )); then
    case "$1" in
        add)          shift; [[ $# -ge 4 ]] || { usage; exit 2; }
                      check_route_args "$1" "$2" "$3" "$4" "${5:-}" || exit 2
                      prepare_system; add_route "$1" "$2" "$3" "$4" "${5:-}" ;;
        del|delete)   shift; [[ $# -ge 2 ]] || { usage; exit 2; }; del_route "$1" "$2" ;;
        list|ls)      list_routes ;;
        replace-hop)  shift; [[ $# -ge 2 ]] || { usage; exit 2; }; replace_hop "$1" "$2" ;;
        doctor|check) shift; doctor "${1:-}" "${2:-}" ;;
        except)       shift
                      case "${1:-}" in
                          add|del|delete)
                              fn=except_add; [[ "$1" == add ]] || fn=except_del; shift
                              case $# in
                                  1) "$fn" "*" "*" "$1" ;;
                                  3) "$fn" "$1" "$2" "$3" ;;
                                  *) usage >&2; exit 2 ;;
                              esac ;;
                          list|"")    list_routes ;;
                          *)          usage >&2; exit 2 ;;
                      esac ;;
        update)       self_update ;;
        sync)         sync_routes; [[ "${2:-}" == --boot ]] || persist_rules ;;
        tune)         prepare_system ;;
        *) err "Неизвестная команда: $1"; usage >&2; exit 2 ;;
    esac
    exit $?
fi

show_menu
