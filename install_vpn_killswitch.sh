#!/usr/bin/env bash
set -Eeuo pipefail

# --------- Parámetros opcionales (exporta antes de ejecutar) ----------
: "${LAN_IFACE:=}"           # ej: export LAN_IFACE=eth0  (lan_in)
: "${LAN_SUBNET:=}"          # ej: export LAN_SUBNET=192.168.100.0/24
: "${LAN_OUT_IFACE:=}"       # ej: export LAN_OUT_IFACE=eth1 (lan_out)
: "${ALLOW_LAN_IN:=}"        # ej: export ALLOW_LAN_IN=192.168.100.0/24
: "${ALLOW_SSH_PORT:=22}"
# ----------------------------------------------------------------------

# importante instalar con: LAN_IFACE=ens19 LAN_SUBNET=10.0.0.0/24 LAN_OUT_IFACE=ens18 ALLOW_LAN_IN=10.0.0.0/24 ./install_vpn_killswitch.sh

require_root() { [[ $EUID -eq 0 ]] || { echo "[ERROR] Necesitas root" >&2; exit 1; }; }

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf      >/dev/null 2>&1; then echo "dnf"
  elif command -v yum      >/dev/null 2>&1; then echo "yum"
  elif command -v pacman   >/dev/null 2>&1; then echo "pacman"
  else echo "unknown"; fi
}

install_deps() {
  local pm; pm=$(detect_pkg_mgr)
  case "$pm" in
    apt)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iptables iproute2 openvpn wireguard-tools grep sed gawk curl iputils-ping resolvconf rsync
      ;;
    dnf)    dnf install -y iptables iproute openvpn wireguard-tools grep sed gawk curl iputils ;;
    yum)    yum install -y iptables iproute openvpn wireguard-tools grep sed gawk curl iputils ;;
    pacman) pacman -Sy --noconfirm iptables iproute2 openvpn wireguard-tools grep sed gawk curl iputils ;;
    *) echo "[WARN] Instala manualmente: iptables iproute2 openvpn wireguard-tools grep sed gawk curl iputils-ping" ;;
  esac
}

write_main_script() {
  install -d /usr/local/sbin /etc/vpn-profiles /etc/systemd/system
  cat > /usr/local/sbin/vpn_killswitch.sh <<'EOF_VPN'
#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# vpn_killswitch.sh
# -----------------------------------------------------------------------------
# Gateway en cebolla con killswitch de iptables + selección aleatoria de
# proveedor/tecnología/perfil desde:
#   - /etc/gwsec.conf   (proveedores activos)
#   - /etc/vpn-profiles/<proveedor>/<tecnologia>/*.(conf|ovpn)
#
# Soporta:
#  - WireGuard (wg-quick con ruta absoluta a .conf)
#  - OpenVPN (con/sin user-pass; inyección de auth en runtime)
#  - Killswitch estricto: OUTPUT solo por VPN, políticas DROP
#  - NAT (MASQUERADE) EXCLUSIVAMENTE por la interfaz VPN
#  - IPv4 forward NO persistente y ordenado: solo tras reglas + verificación
#  - Healthcheck + autoreconexión
# -----------------------------------------------------------------------------

set -Eeuo pipefail

export PATH="$PATH:/usr/local/sbin:/sbin"

# --------------------- Configurable ---------------------
PROFILES_DIR="/etc/vpn-profiles"
GWSEC_FILE="/etc/gwsec.conf"

STATE_DIR="/run/vpn-killswitch"
LOG_FILE="${STATE_DIR}/vpn-killswitch.log"

VPN_PREFER_ORDER=("wireguard" "openvpn")

ALLOW_DNS_BEFORE_VPN=true
DNS_UDP_PORTS=(53)

ALLOW_LAN_IN=""          # ej: "192.168.1.0/24" — vacío = no permitir
ALLOW_SSH_PORT=22

VPN_UP_TIMEOUT=30
HEALTHCHECK_INTERVAL=20
HEALTHCHECK_IP="1.1.1.1"

VPN_IFACE=""

# --- Gateway/Forwarding/NAT ---
LAN_IFACE=""             # lan_in (p.ej. "eth0")
LAN_SUBNET=""            # p.ej. "192.168.100.0/24"
LAN_OUT_IFACE=""         # lan_out (p.ej. "eth1")
ALLOW_FORWARD_LAN_TO_VPN=true
PERSIST_SYSCTL=false     # NO persistir ip_forward
# ------------------- Fin configurable -------------------

mkdir -p "$STATE_DIR"
: >"$LOG_FILE"

log() { echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"; }
require_root() { [[ $EUID -eq 0 ]] || { echo "[ERROR] Necesitas root" >&2; exit 1; }; }

get_wan_iface() { ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'; }
get_current_vpn_iface() { ip -o link show | awk -F': ' '{print $2}' | grep -E '^(tun|tap|wg)[0-9]+' || true; }

# ---------------- IPTABLES helpers ----------------
iptables_flush_all() {
  for t in filter nat mangle raw; do iptables -t "$t" -F || true; iptables -t "$t" -X || true; done
  iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP
}
iptables_common_base() {
  iptables -A INPUT  -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -p icmp -j ACCEPT
  if [[ -n "$ALLOW_LAN_IN" ]]; then
    iptables -A INPUT -p tcp -s "$ALLOW_LAN_IN" --dport "$ALLOW_SSH_PORT" -j ACCEPT
  fi
}
iptables_allow_pre_vpn() {
  local wan_if="${LAN_OUT_IFACE:-$(get_wan_iface || true)}"
  [[ -z $wan_if ]] && return
  if [[ "$ALLOW_DNS_BEFORE_VPN" == true ]]; then
    for p in "${DNS_UDP_PORTS[@]}"; do iptables -A OUTPUT -o "$wan_if" -p udp --dport "$p" -j ACCEPT; done
  fi
  # Permitir levantar el túnel desde el host
  iptables -A OUTPUT -o "$wan_if" -p udp --dport 1194  -j ACCEPT   # OpenVPN UDP
  iptables -A OUTPUT -o "$wan_if" -p tcp --dport 1194  -j ACCEPT   # OpenVPN TCP (algunos proveedores)
  iptables -A OUTPUT -o "$wan_if" -p tcp --dport 443   -j ACCEPT   # OpenVPN TCP
  iptables -A OUTPUT -o "$wan_if" -p udp --dport 443   -j ACCEPT   # OpenVPN UDP (casos raros)
  iptables -A OUTPUT -o "$wan_if" -p udp --dport 51820 -j ACCEPT   # WireGuard
}
iptables_lock_to_vpn_iface() {
  local vpn_if=$1; [[ -z $vpn_if ]] && return 1

  # SALIDA: todo por la VPN (killswitch)
  iptables -A OUTPUT -o "$vpn_if" -j ACCEPT

  # ENTRADA por la VPN:
  # solo respuestas (ESTABLISHED,RELATED). Nada de conexiones NEW.
  # Nota: ya hay un ACCEPT global de ESTABLISHED,RELATED en INPUT,
  # pero lo dejamos explícito y reforzamos el DROP de NEW.
  iptables -A INPUT -i "$vpn_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -i "$vpn_if" -m conntrack --ctstate NEW -j DROP
}
apply_forwarding_and_nat() {
  local vpn_if=$1
  if [[ "$ALLOW_FORWARD_LAN_TO_VPN" == true && -n "$LAN_IFACE" && -n "$LAN_SUBNET" ]]; then
    iptables -A FORWARD -i "$LAN_IFACE" -s "$LAN_SUBNET" -o "$vpn_if" \
             -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i "$vpn_if" -o "$LAN_IFACE" -d "$LAN_SUBNET" \
             -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A POSTROUTING -o "$vpn_if" -s "$LAN_SUBNET" -j MASQUERADE
    iptables -A FORWARD -i "$LAN_IFACE" ! -o "$vpn_if" -s "$LAN_SUBNET" -j DROP
    if [[ -n "${LAN_OUT_IFACE:-}" ]]; then
      iptables -A FORWARD -i "$LAN_IFACE" -o "$LAN_OUT_IFACE" -s "$LAN_SUBNET" -j DROP
      iptables -A FORWARD -i "$LAN_OUT_IFACE" -o "$LAN_IFACE" -d "$LAN_SUBNET" -j DROP
    fi
  fi
}
set_ipv4_forward() {
  local enable=$1
  if [[ $enable == 1 ]]; then
    log "Activando net.ipv4.ip_forward=1 (no persistente)"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
  else
    log "Desactivando net.ipv4.ip_forward=0"
    sysctl -w net.ipv4.ip_forward=0 >/dev/null
  fi
}
iptables_show() {
  echo "==== iptables -S (filter) ===="; iptables -S
  echo; echo "==== iptables -t nat -S ===="; iptables -t nat -S
}
killswitch_is_active() {
  local vpn_if="$1"
  local pol; pol=$(iptables -S 2>/dev/null)
  echo "$pol" | grep -q "^-P INPUT DROP$"    || return 1
  echo "$pol" | grep -q "^-P FORWARD DROP$"  || return 1
  echo "$pol" | grep -q "^-P OUTPUT DROP$"   || return 1
  [[ -n "$vpn_if" ]] && echo "$pol" | grep -q "^-A OUTPUT -o ${vpn_if} -j ACCEPT$" || return 1
  if [[ -n "${LAN_OUT_IFACE:-}" && -n "${LAN_IFACE:-}" ]]; then
    iptables -S FORWARD | grep -Eq -- "-A FORWARD -i ${LAN_IFACE} -o ${LAN_OUT_IFACE} .* -j ACCEPT" && return 1
  fi
  return 0
}

# ---------------- VPN helpers ----------------
stop_openvpn() {
  if [[ -f "${STATE_DIR}/openvpn.pid" ]]; then
    local pid; pid=$(cat "${STATE_DIR}/openvpn.pid" || true)
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then kill "$pid" || true; sleep 1; kill -9 "$pid" 2>/dev/null || true; fi
    rm -f "${STATE_DIR}/openvpn.pid"
  fi
  pkill -f "openvpn --config" 2>/dev/null || true
}
stop_wireguard() {
  ip -o link show | awk -F': ' '{print $2}' | grep -E '^wg[0-9]+' | while read -r w; do wg-quick down "$w" || true; done
}
start_openvpn() {
  local cfg="$1"; local pidfile="${STATE_DIR}/openvpn.pid"
  log "Arrancando OpenVPN: $cfg"
  openvpn --config "$cfg" --daemon ovpn_kill --writepid "$pidfile"
}
start_openvpn_with_auth() {
  local cfg="$1" auth_file="$2"; local pidfile="${STATE_DIR}/openvpn.pid"
  log "Arrancando OpenVPN (auth): $cfg"
  openvpn --config "$cfg" --auth-user-pass "$auth_file" --daemon ovpn_kill --writepid "$pidfile"
}
start_wireguard() {
  local cfg="$1"
  log "Arrancando WireGuard: $cfg"
  WG_QUICK_USERSPACE_IMPLEMENTATION="" wg-quick up "$cfg" 2>&1 | tee -a "$LOG_FILE"
}

# ---------------- Selector proveedor/perfil ----------------
read_gwsec() {
  [[ -f "$GWSEC_FILE" ]] || { log "[ERROR] No existe $GWSEC_FILE"; return 1; }
  awk -F: 'NF>=2 && $1 !~ /^\s*#/' "$GWSEC_FILE" | sed 's/\r$//' | sed '/^\s*$/d'
}
pick_random_provider_from_gwsec() {
  local lines; mapfile -t lines < <(read_gwsec || true)
  [[ ${#lines[@]} -gt 0 ]] || return 1
  local ordered=() t entry prov tech user pass dir
  for t in "${VPN_PREFER_ORDER[@]}"; do
    for entry in "${lines[@]}"; do
      IFS=: read -r prov tech user pass <<<"$entry"
      [[ "$tech" != "$t" ]] && continue
      dir="$PROFILES_DIR/$prov/$tech"
      if [[ -d "$dir" ]]; then
        if [[ "$tech" == "wireguard" ]]; then comp=( "$dir"/*.conf ); else comp=( "$dir"/*.ovpn ); fi
        [[ -e "${comp[0]:-}" ]] && ordered+=( "$entry" )
      fi
    done
  done
  if [[ ${#ordered[@]} -eq 0 ]]; then
    for entry in "${lines[@]}"; do
      IFS=: read -r prov tech user pass <<<"$entry"
      dir="$PROFILES_DIR/$prov/$tech"; comp=( "$dir"/* )
      [[ -d "$dir" && -e "${comp[0]:-}" ]] && ordered+=( "$entry" )
    done
  fi
  [[ ${#ordered[@]} -gt 0 ]] || return 1
  printf '%s\n' "${ordered[@]}" | awk 'BEGIN{srand()} {print rand()"\t"$0}' | sort -n | cut -f2- | head -n1
}
pick_random_profile_for_provider() {
  local prov="$1" tech="$2" dir="$PROFILES_DIR/$prov/$tech"
  if [[ "$tech" == "wireguard" ]]; then
    find "$dir" -maxdepth 1 -type f -name "*.conf" | awk 'BEGIN{srand()} {print rand()"\t"$0}' | sort -n | cut -f2- | head -n1
  else
    find "$dir" -maxdepth 1 -type f -name "*.ovpn" | awk 'BEGIN{srand()} {print rand()"\t"$0}' | sort -n | cut -f2- | head -n1
  fi
}
bringup_any_vpn_random() {
  local entry prov tech user pass profile
  entry=$(pick_random_provider_from_gwsec || true) || { log "[ERROR] No hay proveedores/tecnologías válidos en $GWSEC_FILE"; return 1; }
  IFS=: read -r prov tech user pass <<<"$entry"
  profile=$(pick_random_profile_for_provider "$prov" "$tech" || true)
  [[ -n "$profile" ]] || { log "[ERROR] Sin perfiles en $PROFILES_DIR/$prov/$tech"; return 1; }
  log "Proveedor: $prov | Tecnología: $tech | Perfil: $profile"
  echo "$prov:$tech" >"${STATE_DIR}/active_provider"
  echo "$profile"   >"${STATE_DIR}/active_profile"
  if [[ "$tech" == "wireguard" ]]; then
    start_wireguard "$profile" || true
  else
    if [[ -n "${user:-}" || -n "${pass:-}" ]]; then
      local auth_tmp="${STATE_DIR}/${prov}.auth"
      printf '%s\n%s\n' "${user:-}" "${pass:-}" > "$auth_tmp"; chmod 600 "$auth_tmp"
      start_openvpn_with_auth "$profile" "$auth_tmp" || true
    else
      start_openvpn "$profile" || true
    fi
  fi
  local waited=0
  while [[ $waited -lt $VPN_UP_TIMEOUT ]]; do
    sleep 1; ((waited++))
    local vifs; vifs=$(get_current_vpn_iface || true)
    if [[ -n "$vifs" ]]; then
      VPN_IFACE=$(echo "$vifs" | head -n1)
      log "Interfaz VPN detectada: $VPN_IFACE"
      if ping -I "$VPN_IFACE" -c1 -W 3 "$HEALTHCHECK_IP" &>/dev/null; then
        log "Healthcheck OK a $HEALTHCHECK_IP por $VPN_IFACE"
        return 0
      fi
    fi
  done
  log "[ALERTA] No se consiguió levantar VPN operativa"
  return 1
}

# ---------------- Flow ----------------
apply_killswitch_pre() {
  # Asegura SIN forwarding mientras se preparan reglas
  set_ipv4_forward 0
  iptables_flush_all
  iptables_common_base
  iptables_allow_pre_vpn
}
apply_killswitch_post() {
  [[ -z $VPN_IFACE ]] && VPN_IFACE=$(get_current_vpn_iface | head -n1 || true)
  [[ -z $VPN_IFACE ]] && { log "[ERROR] No se detectó interfaz VPN"; return 1; }

  # Reglas completas SIN forwarding aún
  iptables_flush_all
  iptables_common_base
  iptables_lock_to_vpn_iface "$VPN_IFACE"

  if [[ -n $LAN_IFACE && -n $LAN_SUBNET ]]; then
    apply_forwarding_and_nat "$VPN_IFACE"
  fi

  # Verifica killswitch y SOLO entonces habilita ip_forward
  if killswitch_is_active "$VPN_IFACE"; then
    set_ipv4_forward 1
  else
    log "[ABORT] Killswitch no verificado; ip_forward se mantiene en 0"
    set_ipv4_forward 0
    return 1
  fi
}
health_loop() {
  log "Iniciando health loop cada ${HEALTHCHECK_INTERVAL}s"
  while true; do
    sleep "$HEALTHCHECK_INTERVAL"
    if ! ip link show "$VPN_IFACE" &>/dev/null; then
      log "[ALERTA] Interfaz $VPN_IFACE desapareció. Reintentando..."
      stop_openvpn || true; stop_wireguard || true
      apply_killswitch_pre
      if bringup_any_vpn_random; then apply_killswitch_post; else log "[ERROR] No se pudo restablecer VPN. Killswitch activo."; fi
      continue
    fi
    
    error=0
    for i in {1..3}; do
      if ! ping -I "$VPN_IFACE" -c1 -W 5 "$HEALTHCHECK_IP" &>/dev/null; then
        ((error+=1))
      fi
    done
    
    if (( error == 3 )); then
      log "[ALERTA] Healthcheck fallido. Reintentando reconexión..."
      stop_openvpn || true; stop_wireguard || true
      apply_killswitch_pre
      if bringup_any_vpn_random; then apply_killswitch_post; else log "[ERROR] No se pudo restablecer VPN. Killswitch activo."; fi
    fi
  done
}

cmd_start() {
  require_root
  trap 'log "Señal recibida"; cmd_stop; exit 0' SIGINT SIGTERM
  apply_killswitch_pre
  if bringup_any_vpn_random; then
    apply_killswitch_post
    iptables_show | tee -a "$LOG_FILE"
    health_loop
  else
    log "[ERROR] Falló el arranque de cualquier VPN. Killswitch activo."
    exit 1
  fi
}
cmd_stop() {
  require_root
  stop_openvpn || true
  stop_wireguard || true
  [[ -n $LAN_IFACE && -n $LAN_SUBNET ]] && set_ipv4_forward 0 || true
  for t in filter nat mangle raw; do iptables -t "$t" -F || true; iptables -t "$t" -X || true; done
  iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
  log "Servicio detenido y reglas limpiadas"
}
cmd_status() {
  echo "LAN_IFACE=${LAN_IFACE:-n/d}  LAN_SUBNET=${LAN_SUBNET:-n/d}  LAN_OUT_IFACE=${LAN_OUT_IFACE:-n/d}"
  echo "WAN_IFACE=${LAN_OUT_IFACE:-$(get_wan_iface || echo n/d)}"
  echo "VPN_IFACE=${VPN_IFACE:-$(get_current_vpn_iface | head -n1 || echo n/d)}"
  [[ -f "${STATE_DIR}/active_provider" ]] && echo "Proveedor activo: $(cat "${STATE_DIR}/active_provider")"
  [[ -f "${STATE_DIR}/active_profile"  ]] && echo "Perfil activo:    $(cat "${STATE_DIR}/active_profile")"
  echo; ip -brief addr; echo; iptables_show
}

case "${1:-}" in
  start)  cmd_start  ;;
  stop)   cmd_stop   ;;
  status) cmd_status ;;
  *) echo "Uso: $0 {start|stop|status}"; exit 1 ;;
esac
EOF_VPN
  chmod +x /usr/local/sbin/vpn_killswitch.sh
}

write_service() {
  cat > /etc/systemd/system/vpn-killswitch.service <<'EOF'
[Unit]
Description=VPN Killswitch + Random Provider Layered Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/vpn_killswitch.sh start
ExecStop=/usr/local/sbin/vpn_killswitch.sh stop
Restart=always
RestartSec=5
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
}

write_gwsec_example() {
  if [[ ! -f /etc/gwsec.conf ]]; then
    cat > /etc/gwsec.conf <<'EOF'
# proveedor:tecnologia:usuario:password
windscribe:wireguard:miusuario:mipassword
mullvad:openvpn::
EOF
    chmod 600 /etc/gwsec.conf
  fi
}

write_readme_profiles() {
  install -d /etc/vpn-profiles/example_provider/wireguard
  install -d /etc/vpn-profiles/example_provider/openvpn
  cat > /etc/vpn-profiles/README.txt <<'EOF'
Estructura:
/etc/vpn-profiles/<proveedor>/<tecnologia>/
WireGuard: *.conf
OpenVPN:  *.ovpn
EOF
}

patch_runtime_config() {
  [[ -n "${LAN_IFACE}"     ]] && sed -i "s|^LAN_IFACE=\"\"|LAN_IFACE=\"${LAN_IFACE}\"|g" /usr/local/sbin/vpn_killswitch.sh
  [[ -n "${LAN_SUBNET}"    ]] && sed -i "s|^LAN_SUBNET=\"\"|LAN_SUBNET=\"${LAN_SUBNET}\"|g" /usr/local/sbin/vpn_killswitch.sh
  [[ -n "${LAN_OUT_IFACE}" ]] && sed -i "s|^LAN_OUT_IFACE=\"\"|LAN_OUT_IFACE=\"${LAN_OUT_IFACE}\"|g" /usr/local/sbin/vpn_killswitch.sh
  [[ -n "${ALLOW_LAN_IN}"  ]] && sed -i "s|^ALLOW_LAN_IN=\"\"|ALLOW_LAN_IN=\"${ALLOW_LAN_IN}\"|g" /usr/local/sbin/vpn_killswitch.sh
  [[ -n "${ALLOW_SSH_PORT}" ]] && sed -i "s|^ALLOW_SSH_PORT=22|ALLOW_SSH_PORT=${ALLOW_SSH_PORT}|g" /usr/local/sbin/vpn_killswitch.sh
}

enable_start_service() {
  systemctl daemon-reload
  systemctl enable --now vpn-killswitch.service
  systemctl status vpn-killswitch.service --no-pager || true
}

main() {
  require_root
  install_deps
  write_main_script
  write_service
  write_gwsec_example
  write_readme_profiles
  patch_runtime_config
  echo "[OK] Archivos instalados."
  echo "[OK] Coloca tus perfiles en /etc/vpn-profiles/<proveedor>/<tecnologia>/"
  echo "[OK] Revisa /etc/gwsec.conf y ajusta proveedores/credenciales."
  enable_start_service
  echo "[OK] Listo."
}
main "$@"

