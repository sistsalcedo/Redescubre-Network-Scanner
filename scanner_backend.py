import socket
import ipaddress
import threading
import os
import sys
import shutil
import csv
from pathlib import Path
from scapy.all import ARP, Ether, srp, conf, IP, TCP, ICMP, sr1

# --- Variables Globales ---
# Usaremos nuestro propio diccionario para la base de datos de fabricantes MAC.
# Se carga una vez al inicio.
mac_vendor_db = {}

# --- Funciones de Detección de Red ---

def get_default_network_range():
    """
    Detecta la red local activa y devuelve el rango en notación CIDR.
    Ejemplo: '192.168.1.0/24'. Incluye métodos de respaldo.
    """
    # Método 1: Usar Scapy para encontrar la ruta activa. Es el más fiable.
    try:
        # Conectarse a una IP externa para que el SO elija la interfaz de salida principal.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        # Buscar en la tabla de rutas de Scapy la que corresponde a nuestra IP local.
        for network_addr, netmask, _, interface, address, _ in conf.route.routes:
            if netmask != 0 and address == local_ip:
                network_str = str(ipaddress.IPv4Address(network_addr))
                prefix_len = bin(netmask).count('1')
                cidr_range = f"{network_str}/{prefix_len}"
                print(f"[*] Red detectada automáticamente con Scapy: {cidr_range} en la interfaz {interface}")
                return cidr_range
        raise ConnectionError("No se encontró una ruta de red local válida en Scapy.")
    except (OSError, IndexError, ConnectionError) as e:
        print(f"[!] No se pudo detectar la red con Scapy ({e}). Usando método de respaldo.")
        # Método 2: Usar el hostname. Menos fiable pero buen respaldo.
        try:
            hostname = socket.gethostname()
            ip_addr = socket.gethostbyname(hostname)
            # Asumir una máscara de subred /24, que es la más común en redes domésticas/pequeñas.
            network = ipaddress.ip_network(f"{ip_addr}/24", strict=False)
            cidr_range = str(network.with_prefixlen)
            print(f"[*] Red detectada con método de respaldo: {cidr_range}")
            return cidr_range
        except socket.gaierror:
            print("[!] Error crítico: No se pudo detectar la red. Por favor, ingrésala manualmente.")
            return None

# --- Funciones de Búsqueda y Resolución (Ejecutadas en Hilos) ---

def _resolve_hostname(ip_addr, update_callback):
    """
    Resuelve el hostname de una IP. Se ejecuta en un hilo para no bloquear la GUI.
    """
    hostname = "Desconocido"
    try:
        # Intenta obtener el nombre de host a través de una búsqueda DNS inversa.
        hostname = socket.gethostbyaddr(ip_addr)[0]
    except socket.herror:
        # Si falla, comprobamos si es el gateway por defecto.
        try:
            if ip_addr == conf.route.route("0.0.0.0")[2]:
                hostname = "Gateway/Router"
        except (IndexError, OSError):
            # Si todo falla, se queda como "Desconocido".
            pass
    
    if update_callback:
        update_callback({"ip": ip_addr, "hostname": hostname})

def _resolve_manufacturer(mac_db, mac_addr, ip_addr, update_callback):
    """
    Busca el fabricante de una MAC en nuestro diccionario local. Se ejecuta en un hilo.
    """
    manufacturer = "Desconocido"
    try:
        if mac_db and mac_addr:
            # Normaliza la MAC al formato XX-XX-XX y toma los primeros 8 caracteres.
            prefix = mac_addr.upper().replace(':', '-')[:8]
            # Busca el prefijo en el diccionario. Si no lo encuentra, devuelve "Desconocido".
            manufacturer = mac_db.get(prefix, "Desconocido")
        elif not mac_db:
            manufacturer = "BD no cargada"
        else: # mac_addr es None o vacío
            manufacturer = "N/A"
    except Exception as e:
        print(f"[!] Error al resolver fabricante para {mac_addr}: {e}")
        manufacturer = "Error de búsqueda"

    if update_callback:
        update_callback({"ip": ip_addr, "manufacturer": manufacturer})

# --- Gestión de la Base de Datos de Fabricantes ---

def get_data_directory():
    """
    Obtiene la ruta del directorio de datos de la aplicación, creándolo si no existe.
    - En modo "congelado" (.exe), usa %APPDATA%/NetworkScanner.
    - En modo desarrollo (.py), usa una carpeta 'data' local.
    """
    if getattr(sys, 'frozen', False):
        # %APPDATA% es la ubicación estándar para datos de aplicación por usuario en Windows.
        app_data_dir = os.environ.get('APPDATA', Path.home())
        base_dir = Path(app_data_dir) / 'NetworkScanner'
    else:
        # En desarrollo, usa una carpeta local para facilidad de acceso.
        base_dir = Path(__file__).parent / "data"

    base_dir.mkdir(parents=True, exist_ok=True)
    return str(base_dir)

def _copy_db_if_needed(data_dir):
    """
    Si se ejecuta como .exe, copia la base de datos desde el paquete a un directorio persistente.
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # _MEIPASS es la carpeta temporal donde PyInstaller extrae los datos.
        embedded_db_path = Path(sys._MEIPASS) / "mac_vendors.txt"
        target_db_path = Path(data_dir) / "mac_vendors.txt"

        # Copia el archivo solo si no existe en el destino.
        if embedded_db_path.exists() and not target_db_path.exists():
            print(f"[*] Copiando base de datos MAC embebida a {target_db_path}")
            try:
                shutil.copy2(str(embedded_db_path), str(target_db_path))
            except Exception as e:
                print(f"[!] Error al copiar la base de datos: {e}")

def _load_mac_vendors_from_file(file_path):
    """
    Carga los fabricantes de MAC desde un archivo CSV a un diccionario en memoria.
    """
    db = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Omitir la línea de cabecera del CSV.
            next(f, None)
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    # Columna 0: Prefijo MAC, Columna 1: Nombre del fabricante.
                    # Normalizamos el prefijo al formato XX-XX-XX para consistencia.
                    prefix = row[0].upper().replace(':', '-')[:8]
                    vendor = row[1]
                    db[prefix] = vendor
        return db, f"[*] Base de datos MAC cargada desde {file_path}.\n"
    except FileNotFoundError:
        return {}, "[!] Error: Archivo de base de datos MAC no encontrado.\n"
    except Exception as e:
        return {}, f"[!] Error al leer la base de datos MAC: {e}\n"

def setup_mac_database():
    """
    Configura y carga la base de datos de fabricantes MAC en memoria.
    Retorna: (dict, str) - El diccionario de fabricantes y un mensaje de estado.
    """
    global mac_vendor_db
    data_dir = get_data_directory()
    _copy_db_if_needed(data_dir)
    
    db_file = os.path.join(data_dir, "mac_vendors.txt")
    status_message = ""
    
    if os.path.exists(db_file):
        mac_vendor_db, msg = _load_mac_vendors_from_file(db_file)
        status_message += msg
        if mac_vendor_db:
            try:
                size_kb = os.path.getsize(db_file) / 1024
                status_message += f"[*] Usando base de datos existente ({len(mac_vendor_db)} entradas, {size_kb:.1f} KB).\n"
            except OSError:
                pass
            status_message += "[*] Base de datos MAC cargada en memoria.\n"
    else:
        status_message += "[!] Error crítico: No se encontró el archivo de la base de datos MAC.\n"
    
    return mac_vendor_db, status_message

# --- Funciones Principales de Escaneo ---

def _get_hosts_to_scan(ip_range):
    """
    Parsea el rango de IP de entrada y devuelve una lista de objetos IP a escanear.
    """
    hosts_to_scan = []
    network = None
    
    if "-" in ip_range:
        start_ip_str, end_ip_str = ip_range.split('-')
        start_ip = ipaddress.ip_address(start_ip_str.strip())
        end_ip = ipaddress.ip_address(end_ip_str.strip())
        current_ip = start_ip
        while current_ip <= end_ip:
            hosts_to_scan.append(current_ip)
            current_ip += 1
        # Usamos la IP de inicio para determinar la red para la superposición.
        network = ipaddress.ip_network(f"{start_ip}/{start_ip.max_prefixlen}", strict=False)
    else:
        network = ipaddress.ip_network(ip_range.strip(), strict=False)
        if network.num_addresses == 1:
            hosts_to_scan.append(network.network_address)
        else:
            hosts_to_scan = list(network.hosts())
            
    return hosts_to_scan, network

def scan_network(mac_db_instance, ip_range, progress_callback=None, result_callback=None, update_callback=None, cancel_event=None):
    """
    Escanea la red para encontrar dispositivos activos. Usa ARP para redes locales y ICMP para remotas.
    """
    print(f"[*] Iniciando escaneo de red: {ip_range}...")
    
    try:
        hosts_to_scan, network_to_scan = _get_hosts_to_scan(ip_range)
        total_hosts = len(hosts_to_scan)
        if total_hosts == 0:
            print("[!] No hay hosts para escanear en el rango proporcionado.")
            return
    except ValueError as e:
        print(f"[!] Rango de IP inválido: {ip_range} ({e})")
        if progress_callback:
            progress_callback(1.0)
        return

    # Determina si el escaneo es local para usar ARP (más rápido y obtiene MACs).
    local_network_str = get_default_network_range()
    is_local_scan = local_network_str and network_to_scan and ipaddress.ip_network(local_network_str).overlaps(network_to_scan)
    print(f"[*] Modo de escaneo: {'Local (ARP)' if is_local_scan else 'Remoto (ICMP)'}")

    for i, host in enumerate(hosts_to_scan):
        if cancel_event and cancel_event.is_set():
            print("[*] Escaneo cancelado por el usuario.")
            break

        host_ip = str(host)
        device = None

        try:
            if is_local_scan:
                # Escaneo ARP para redes locales
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host_ip)
                answered, _ = srp(arp_request, timeout=0.2, verbose=0, retry=1)
                if answered:
                    response = answered[0][1]
                    device = {"ip": response.psrc, "mac": response.hwsrc}
            else:
                # Escaneo ICMP (ping) para redes remotas
                icmp_packet = IP(dst=host_ip) / ICMP()
                response = sr1(icmp_packet, timeout=0.5, verbose=0)
                if response:
                    device = {"ip": response.src, "mac": "N/A"}
        except Exception as e:
            print(f"[!] Error al escanear {host_ip}: {e}")
            continue

        if device:
            device.update({"manufacturer": "Buscando...", "hostname": "Resolviendo..."})
            if result_callback:
                result_callback(device)

            # Iniciar hilos para tareas que pueden ser lentas (resolución de nombres y fabricantes)
            threading.Thread(target=_resolve_hostname, args=(device["ip"], update_callback), daemon=True).start()
            if is_local_scan:
                threading.Thread(target=_resolve_manufacturer, args=(mac_db_instance, device["mac"], device["ip"], update_callback), daemon=True).start()

        if progress_callback:
            progress_callback((i + 1) / total_hosts)

    print("[*] Fase de descubrimiento de red completada.")

def scan_ports(host_ip, ports_to_scan, progress_callback=None):
    """
    Escanea una lista de puertos TCP en un host específico para ver si están abiertos.
    """
    open_ports = []
    total_ports = len(ports_to_scan)
    print(f"[*] Escaneando puertos en {host_ip}...")

    for i, port in enumerate(ports_to_scan):
        try:
            # Envía un paquete TCP SYN para iniciar un handshake
            packet = IP(dst=host_ip) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=0.5, verbose=0)

            # Si recibimos un SYN-ACK (0x12), el puerto está abierto.
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                # Enviamos un RST para cerrar la conexión limpiamente.
                sr1(IP(dst=host_ip) / TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
                open_ports.append(port)
                print(f"[+] Puerto {port} abierto en {host_ip}")
        except Exception as e:
            print(f"[!] Error al escanear puerto {port} en {host_ip}: {e}")
        
        if progress_callback:
            progress_callback((i + 1) / total_ports)

    print(f"[*] Escaneo de puertos en {host_ip} completado. Puertos abiertos: {open_ports}")
    return open_ports

# --- Bloque de Ejecución de Prueba ---

if __name__ == "__main__":
    """
    Este bloque se ejecuta solo cuando se corre scanner_backend.py directamente.
    Es útil para pruebas rápidas del backend sin la GUI.
    """
    print("--- Iniciando prueba del backend ---")
    
    # 1. Probar la configuración de la base de datos MAC
    db_instance, status_msg = setup_mac_database()
    print(status_msg)
    if not db_instance:
        print("[!] La prueba no puede continuar sin la base de datos MAC.")
        sys.exit(1)
        
    # 2. Probar la detección de red
    target_range = get_default_network_range()
    if target_range:
        print(f"\n[+] Prueba de detección de red completada. Rango detectado: {target_range}")
    else:
        print("[!] La prueba no puede continuar sin un rango de red.")
        sys.exit(1)
        
    # 3. Probar un escaneo simple (solo para demostración)
    print("\n--- Ejecutando un escaneo de red de demostración ---")
    
    def demo_result(device):
        print(f"  [+] Dispositivo encontrado: {device['ip']} ({device['mac']})")

    def demo_update(update):
        print(f"  [*] Actualización para {update['ip']}: {update}")

    scan_network(db_instance, target_range, result_callback=demo_result, update_callback=demo_update)
    
    print("\n--- Prueba del backend completada ---")
    print("[+] Para la aplicación completa, ejecute gui_scanner.py")
