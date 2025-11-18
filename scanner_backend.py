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
# Se carga una vez al inicio en configurar_base_de_datos_mac().
bd_fabricantes_mac = {}

# --- Funciones de Detección de Red ---

def obtener_rango_red_por_defecto():
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
            ip_local = s.getsockname()[0]

        # Buscar en la tabla de rutas de Scapy la que corresponde a nuestra IP local.
        for dir_red, mascara_red, _, interfaz, direccion, _ in conf.route.routes:
            if mascara_red != 0 and direccion == ip_local:
                red_str = str(ipaddress.IPv4Address(dir_red))
                longitud_prefijo = bin(mascara_red).count('1')
                rango_cidr = f"{red_str}/{longitud_prefijo}"
                print(f"[*] Red detectada automáticamente con Scapy: {rango_cidr} en la interfaz {interfaz}")
                return rango_cidr
        raise ConnectionError("No se encontró una ruta de red local válida en Scapy.")
    except (OSError, IndexError, ConnectionError) as e:
        print(f"[!] No se pudo detectar la red con Scapy ({e}). Usando método de respaldo.")
        # Método 2: Usar el hostname. Menos fiable pero buen respaldo.
        try:
            hostname = socket.gethostname()
            ip_addr = socket.gethostbyname(hostname)
            # Asumir una máscara de subred /24, que es la más común en redes domésticas/pequeñas.
            red = ipaddress.ip_network(f"{ip_addr}/24", strict=False)
            rango_cidr = str(red.with_prefixlen)
            print(f"[*] Red detectada con método de respaldo: {rango_cidr}")
            return rango_cidr
        except socket.gaierror:
            print("[!] Error crítico: No se pudo detectar la red. Por favor, ingrésala manualmente.")
            return None

# --- Funciones de Búsqueda y Resolución (Ejecutadas en Hilos) ---

def _resolver_hostname(dir_ip, callback_actualizacion):
    """
    Resuelve el hostname de una IP. Se ejecuta en un hilo para no bloquear la GUI.
    """
    hostname = "Desconocido"
    try:
        # Intenta obtener el nombre de host a través de una búsqueda DNS inversa.
        hostname = socket.gethostbyaddr(dir_ip)[0]
    except socket.herror:
        # Si falla, comprobamos si es el gateway por defecto.
        try:
            if dir_ip == conf.route.route("0.0.0.0")[2]:
                hostname = "Gateway/Router"
        except (IndexError, OSError):
            # Si todo falla, se queda como "Desconocido".
            pass
    
    if callback_actualizacion:
        callback_actualizacion({"ip": dir_ip, "hostname": hostname})

def _medir_latencia(dir_ip, callback_actualizacion, num_pings=3):
    """Mide la latencia a una IP enviando varios pings y calculando el promedio."""
    latencias = []
    for _ in range(num_pings):
        try:
            # sr1 devuelve el primer paquete de respuesta
            respuesta = sr1(IP(dst=dir_ip)/ICMP(), timeout=0.2, verbose=0)
            if respuesta:
                # La latencia es la diferencia entre el tiempo de recepción y envío
                latencia_ms = (respuesta.time - respuesta.sent_time) * 1000
                latencias.append(latencia_ms)
        except Exception:
            pass # Ignorar errores de ping
    
    if latencias:
        latencia_promedio = sum(latencias) / len(latencias)
        if callback_actualizacion:
            callback_actualizacion({"ip": dir_ip, "latency": latencia_promedio})
    else:
        if callback_actualizacion:
            callback_actualizacion({"ip": dir_ip, "latency": -1}) # -1 indica que no se pudo medir

def _resolver_fabricante(bd_mac, dir_mac, dir_ip, callback_actualizacion):
    """
    Busca el fabricante de una MAC en nuestro diccionario local. Se ejecuta en un hilo.
    """
    manufacturer = "Desconocido"
    try:
        if bd_mac and dir_mac:
            # Normaliza la MAC al formato XX-XX-XX y toma los primeros 8 caracteres.
            prefijo = dir_mac.upper().replace(':', '-')[:8]
            # Busca el prefijo en el diccionario. Si no lo encuentra, devuelve "Desconocido".
            manufacturer = bd_mac.get(prefijo, "Desconocido")
        elif not bd_mac:
            manufacturer = "BD no cargada"
        else: # dir_mac es None o vacío
            manufacturer = "N/A"
    except Exception as e:
        print(f"[!] Error al resolver fabricante para {dir_mac}: {e}")
        manufacturer = "Error de búsqueda"

    if callback_actualizacion:
        callback_actualizacion({"ip": dir_ip, "manufacturer": manufacturer})

# --- Gestión de la Base de Datos de Fabricantes ---

def get_data_directory():
    """
    Obtiene la ruta del directorio de datos de la aplicación, creándolo si no existe.
    - En modo "congelado" (.exe), usa %APPDATA%/NetworkScanner.
    - En modo desarrollo (.py), usa una carpeta 'data' local.
    """
    if getattr(sys, 'frozen', False):
        # %APPDATA% es la ubicación estándar para datos de aplicación por usuario en Windows.
        dir_app_data = os.environ.get('APPDATA', Path.home())
        dir_base = Path(dir_app_data) / 'NetworkScanner'
    else:
        # En desarrollo, usa una carpeta local para facilidad de acceso.
        dir_base = Path(__file__).parent / "data"

    dir_base.mkdir(parents=True, exist_ok=True)
    return str(dir_base)

def _copiar_bd_si_es_necesario(directorio_datos):
    """
    Si se ejecuta como .exe, copia la base de datos desde el paquete a un directorio persistente.
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # _MEIPASS es la carpeta temporal donde PyInstaller extrae los datos.
        ruta_bd_embebida = Path(sys._MEIPASS) / "mac_vendors.txt"
        ruta_bd_destino = Path(directorio_datos) / "mac_vendors.txt"

        # Copia el archivo solo si no existe en el destino.
        if ruta_bd_embebida.exists() and not ruta_bd_destino.exists():
            print(f"[*] Copiando base de datos MAC embebida a {ruta_bd_destino}")
            try:
                shutil.copy2(str(ruta_bd_embebida), str(ruta_bd_destino))
            except Exception as e:
                print(f"[!] Error al copiar la base de datos: {e}")

def _cargar_fabricantes_mac_desde_archivo(ruta_archivo):
    """
    Carga los fabricantes de MAC desde un archivo CSV a un diccionario en memoria.
    """
    bd = {}
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            # Omitir la línea de cabecera del CSV.
            next(f, None)
            lector = csv.reader(f)
            for row in lector:
                if len(row) >= 2:
                    # Columna 0: Prefijo MAC, Columna 1: Nombre del fabricante.
                    # Normalizamos el prefijo al formato XX-XX-XX para consistencia.
                    prefijo = row[0].upper().replace(':', '-')[:8]
                    fabricante = row[1]
                    bd[prefijo] = fabricante
        return bd, f"[*] Base de datos MAC cargada desde {ruta_archivo}.\n"
    except FileNotFoundError:
        return {}, "[!] Error: Archivo de base de datos MAC no encontrado.\n"
    except Exception as e:
        return {}, f"[!] Error al leer la base de datos MAC: {e}\n"

def configurar_base_de_datos_mac():
    """
    Configura y carga la base de datos de fabricantes MAC en memoria.
    Retorna: (dict, str) - El diccionario de fabricantes y un mensaje de estado.
    """
    global bd_fabricantes_mac
    directorio_datos = get_data_directory()
    _copiar_bd_si_es_necesario(directorio_datos)
    
    archivo_bd = os.path.join(directorio_datos, "mac_vendors.txt")
    mensaje_estado = ""
    
    if os.path.exists(archivo_bd):
        bd_fabricantes_mac, msg = _cargar_fabricantes_mac_desde_archivo(archivo_bd)
        mensaje_estado += msg
        if bd_fabricantes_mac:
            try:
                tamano_kb = os.path.getsize(archivo_bd) / 1024
                mensaje_estado += f"[*] Usando base de datos existente ({len(bd_fabricantes_mac)} entradas, {tamano_kb:.1f} KB).\n"
            except OSError:
                pass
            mensaje_estado += "[*] Base de datos MAC cargada en memoria.\n"
    else:
        mensaje_estado += "[!] Error crítico: No se encontró el archivo de la base de datos MAC.\n"
    
    return bd_fabricantes_mac, mensaje_estado

# --- Funciones Principales de Escaneo ---

def _obtener_hosts_a_escanear(rango_ip):
    """
    Parsea el rango de IP de entrada y devuelve una lista de objetos IP a escanear.
    """
    hosts_to_scan = []
    red = None
    
    if "-" in rango_ip:
        ip_inicio_str, ip_fin_str = rango_ip.split('-')
        ip_inicio = ipaddress.ip_address(ip_inicio_str.strip())
        ip_fin = ipaddress.ip_address(ip_fin_str.strip())
        ip_actual = ip_inicio
        while ip_actual <= ip_fin:
            hosts_to_scan.append(ip_actual)
            ip_actual += 1
        # Usamos la IP de inicio para determinar la red para la superposición.
        red = ipaddress.ip_network(f"{ip_inicio}/{ip_inicio.max_prefixlen}", strict=False)
    else:
        red = ipaddress.ip_network(rango_ip.strip(), strict=False)
        if red.num_addresses == 1:
            hosts_to_scan.append(red.network_address)
        else:
            hosts_to_scan = list(red.hosts())
            
    return hosts_to_scan, red

def escanear_red(instancia_bd_mac, rango_ip, callback_progreso=None, callback_resultado=None, callback_actualizacion=None, evento_cancelar=None):
    """
    Escanea la red para encontrar dispositivos activos. Usa ARP para redes locales y ICMP para remotas.
    """
    print(f"[*] Iniciando escaneo de red: {rango_ip}...")
    dispositivos_encontrados = []
    
    try:
        hosts_to_scan, red_a_escanear = _obtener_hosts_a_escanear(rango_ip)
        total_hosts = len(hosts_to_scan)
        if total_hosts == 0:
            print("[!] No hay hosts para escanear en el rango proporcionado.")
            return []
    except ValueError as e:
        print(f"[!] Rango de IP inválido: {rango_ip} ({e})")
        if callback_progreso:
            callback_progreso(1.0)
        return []

    # Determina si el escaneo es local para usar ARP (más rápido y obtiene MACs).
    red_local_str = obtener_rango_red_por_defecto()
    es_escaneo_local = red_local_str and red_a_escanear and ipaddress.ip_network(red_local_str).overlaps(red_a_escanear)
    print(f"[*] Modo de escaneo: {'Local (ARP)' if es_escaneo_local else 'Remoto (ICMP)'}")

    for i, host in enumerate(hosts_to_scan):
        if evento_cancelar and evento_cancelar.is_set():
            print("[*] Escaneo cancelado por el usuario.")
            break

        ip_host = str(host)
        dispositivo = None

        try:
            if es_escaneo_local:
                # Escaneo ARP para redes locales
                solicitud_arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_host)
                respondidos, _ = srp(solicitud_arp, timeout=0.2, verbose=0, retry=1)
                if respondidos:
                    respuesta = respondidos[0][1]
                    dispositivo = {"ip": respuesta.psrc, "mac": respuesta.hwsrc}
            else:
                # Escaneo ICMP (ping) para redes remotas
                paquete_icmp = IP(dst=ip_host) / ICMP()
                respuesta = sr1(paquete_icmp, timeout=0.5, verbose=0)
                if respuesta:
                    dispositivo = {"ip": respuesta.src, "mac": "N/A"}
        except Exception as e:
            print(f"[!] Error al escanear {ip_host}: {e}")
            continue

        if dispositivo:
            dispositivo.update({"manufacturer": "Buscando...", "hostname": "Resolviendo...", "latency": -1.0})
            dispositivos_encontrados.append(dispositivo)
            if callback_resultado:
                callback_resultado(dispositivo)

            # Iniciar hilos para tareas que pueden ser lentas (resolución de nombres y fabricantes)
            threading.Thread(target=_medir_latencia, args=(dispositivo["ip"], callback_actualizacion), daemon=True).start()
            threading.Thread(target=_resolver_hostname, args=(dispositivo["ip"], callback_actualizacion), daemon=True).start()
            if es_escaneo_local:
                threading.Thread(target=_resolver_fabricante, args=(instancia_bd_mac, dispositivo["mac"], dispositivo["ip"], callback_actualizacion), daemon=True).start()

        if callback_progreso:
            callback_progreso((i + 1) / total_hosts)

    print("[*] Fase de descubrimiento de red completada.")
    return dispositivos_encontrados

def escanear_puertos(ip_host, puertos_a_escanear, callback_progreso=None):
    """
    Escanea una lista de puertos TCP en un host específico para ver si están abiertos.
    """
    open_ports = []
    total_ports = len(puertos_a_escanear)
    print(f"[*] Escaneando puertos en {ip_host}...")

    for i, port in enumerate(puertos_a_escanear):
        try:
            # Envía un paquete TCP SYN para iniciar un handshake
            paquete = IP(dst=ip_host) / TCP(dport=port, flags="S")
            respuesta = sr1(paquete, timeout=0.5, verbose=0)

            # Si recibimos un SYN-ACK (0x12), el puerto está abierto.
            if respuesta and respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x12:
                # Enviamos un RST para cerrar la conexión limpiamente.
                sr1(IP(dst=ip_host) / TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
                open_ports.append(port)
                print(f"[+] Puerto {port} abierto en {ip_host}")
        except Exception as e:
            print(f"[!] Error al escanear puerto {port} en {ip_host}: {e}")
        
        if callback_progreso:
            callback_progreso((i + 1) / total_ports)

    print(f"[*] Escaneo de puertos en {ip_host} completado. Puertos abiertos: {open_ports}")
    return open_ports

# --- Bloque de Ejecución de Prueba ---

if __name__ == "__main__":
    """
    Este bloque se ejecuta solo cuando se corre scanner_backend.py directamente.
    Es útil para pruebas rápidas del backend sin la GUI.
    """
    print("--- Iniciando prueba del backend ---")
    
    # 1. Probar la configuración de la base de datos MAC
    instancia_bd, msg_estado = configurar_base_de_datos_mac()
    print(msg_estado)
    if not instancia_bd:
        print("[!] La prueba no puede continuar sin la base de datos MAC.")
        sys.exit(1)
        
    # 2. Probar la detección de red
    rango_objetivo = obtener_rango_red_por_defecto()
    if rango_objetivo:
        print(f"\n[+] Prueba de detección de red completada. Rango detectado: {rango_objetivo}")
    else:
        print("[!] La prueba no puede continuar sin un rango de red.")
        sys.exit(1)
        
    # 3. Probar un escaneo simple (solo para demostración)
    print("\n--- Ejecutando un escaneo de red de demostración ---")
    
    def demo_resultado(dispositivo):
        print(f"  [+] Dispositivo encontrado: {dispositivo['ip']} ({dispositivo['mac']})")

    def demo_actualizacion(actualizacion):
        print(f"  [*] Actualización para {actualizacion['ip']}: {actualizacion}")

    escanear_red(instancia_bd, rango_objetivo, callback_resultado=demo_resultado, callback_actualizacion=demo_actualizacion)
    
    print("\n--- Prueba del backend completada ---")
    print("[+] Para la aplicación completa, ejecute gui_scanner.py")
