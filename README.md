# Guía rápida · Instalador y servicio `vpn-killswitch`

## Instalador: `install_vpn_killswitch.sh`

### Variables de entorno (opcionales)
- `LAN_IFACE` → interfaz **lan_in** (donde están tus VMs).
- `LAN_SUBNET` → subred CIDR de **lan_in** (ej. `10.0.0.0/24`).
- `LAN_OUT_IFACE` → interfaz **lan_out** (sale a Internet por DHCP).
- `ALLOW_LAN_IN` → (opcional) subred desde la que **permitir SSH** al host.
- `ALLOW_SSH_PORT` → (opcional) puerto SSH permitido (por defecto `22`).

**Ejemplo (tus valores):**
```bash
sudo LAN_IFACE=ens19 \
     LAN_SUBNET=10.0.0.0/24 \
     LAN_OUT_IFACE=ens18 \
     ALLOW_LAN_IN=10.0.0.0/24 \
     ./install_vpn_killswitch.sh
```

### Qué hace el instalador
- Instala dependencias: `iptables`, `iproute2`, `openvpn`, `wireguard-tools`, `grep`, `sed`, **`gawk`**, `curl`, `iputils-ping`.
- Crea `/usr/local/sbin/vpn_killswitch.sh` (killswitch estricto, **NAT solo por la VPN**, `ip_forward` **no persistente** y activado **solo después** de aplicar reglas y verificar).
- Crea la unidad `systemd` `vpn-killswitch.service`.
- Crea (si no existen): `/etc/gwsec.conf` y la estructura `/etc/vpn-profiles/…`.

### Dónde colocar perfiles y credenciales
**Perfiles VPN**
```
/etc/vpn-profiles/<proveedor>/wireguard/*.conf
/etc/vpn-profiles/<proveedor>/openvpn/*.ovpn
```
**Proveedores activos** (`/etc/gwsec.conf`)
```
<proveedor>:<tecnologia>:<usuario>:<password>
# Ejemplos:
windscribe:wireguard:miusuario:mipassword
mullvad:openvpn::
```
> El script elige aleatoriamente proveedor/tecnología/perfil de entre los activos y con ficheros presentes.

---

## Servicio: `vpn-killswitch.service`

### Operativa básica (systemd)
```bash
# Arrancar
sudo systemctl start vpn-killswitch

# Parar (apaga ip_forward y limpia reglas)
sudo systemctl stop vpn-killswitch

# Reiniciar (relee selección VPN y rehace reglas)
sudo systemctl restart vpn-killswitch

# Estado
systemctl status vpn-killswitch --no-pager

# Logs en vivo
sudo journalctl -u vpn-killswitch -f
```

**Arranque automático al boot**
```bash
sudo systemctl enable vpn-killswitch
# Para deshabilitar:
sudo systemctl disable vpn-killswitch
```

### Comandos del script (diagnóstico)
> Úsalos **solo** si el servicio NO está en marcha (evita conflictos).
```bash
# Estado detallado (interfaces, perfil seleccionado, iptables, NAT)
sudo /usr/local/sbin/vpn_killswitch.sh status

# Arranque en primer plano (bloquea terminal con health-check)
sudo /usr/local/sbin/vpn_killswitch.sh start

# Parada segura (ip_forward=0, reglas limpias)
sudo /usr/local/sbin/vpn_killswitch.sh stop
```

---

## Verificaciones rápidas
```bash
# ip_forward solo activo con el servicio en marcha y killswitch verificado
sysctl net.ipv4.ip_forward

# NAT (MASQUERADE) únicamente por la interfaz VPN
sudo iptables -t nat -S | grep POSTROUTING

# Sin "leaks" por lan_out (deberías ver solo handshakes de la VPN)
sudo tcpdump -ni ens18 not port 1194 and not port 443 and not port 51820
```

---

## Modelo de seguridad (resumen)
- Políticas por defecto `DROP` en `INPUT/FORWARD/OUTPUT`.
- **Salida** a Internet solo por **VPN**; antes de subir el túnel, se permiten **solo** DNS/puertos de la VPN vía `lan_out` para que el host levante el túnel.
- **NAT sólo por la VPN** (`POSTROUTING -o <tun|wg> -s $LAN_SUBNET -j MASQUERADE`).
- **Prohibido** `lan_in → lan_out` y cualquier `lan_in → !VPN`.
- `ip_forward`:
  - **OFF** antes de preparar reglas.
  - Reglas completas + verificación de killswitch ⇒ **ON**.
  - En parada/reintentos ⇒ **OFF** **antes** de limpiar reglas.

**Entrada por la interfaz VPN (endurecida):**
```bash
# Sólo ESTABLISHED/RELATED; bloquea NEW por la VPN
iptables -A INPUT -i "$VPN_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i "$VPN_IFACE" -m conntrack --ctstate NEW -j DROP
```
> Si necesitas abrir un puerto específico por la VPN, añade una regla **antes del DROP de NEW** (whitelist puntual).

---

## Rutas y archivos
- Script: `/usr/local/sbin/vpn_killswitch.sh`
- Servicio: `/etc/systemd/system/vpn-killswitch.service`
- Perfiles: `/etc/vpn-profiles/<proveedor>/<tecnologia>/`
- Proveedores/credenciales: `/etc/gwsec.conf`
- Estado/log:
  - `/run/vpn-killswitch/active_provider`
  - `/run/vpn-killswitch/active_profile`
  - `/run/vpn-killswitch/vpn-killswitch.log`
