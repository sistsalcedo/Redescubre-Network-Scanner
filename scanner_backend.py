import socket
import ipaddress
import threading
from scapy.all import ARP, Ether, srp, conf, IP, TCP, sr1, ICMP
from scapy.layers.l2 import getmacbyip
from mac_vendor_lookup import MacLookup

def get_default_network_range():
    """
    Detecta la red local activa y devuelve el rango en notación CIDR.
    Ejemplo: '192.168.1.0/24'
    """
    try:
        # 1. Obtener la IP local que se usa para conexiones externas
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        # 2. Buscar la interfaz y la red correspondientes a esa IP en la tabla de Scapy
        for network_addr, netmask, _, interface, address, _ in conf.route.routes:
            # La máscara 0.0.0.0 es inútil, y la IP debe coincidir
            if netmask != 0 and address == local_ip:
                # 3. Construir el rango de red a partir de los datos encontrados
                # Convertir los enteros de red y máscara a un formato de texto válido
                network_str = str(ipaddress.IPv4Address(network_addr))
                prefix_len = bin(netmask).count('1')
                
                cidr_range = f"{network_str}/{prefix_len}"
                print(f"[*] Red detectada automáticamente: {cidr_range} en la interfaz {interface}")
                return cidr_range
        # Si el bucle termina sin encontrar una ruta, pasamos al método de respaldo
        raise StopIteration("No se encontró una ruta de red local válida en Scapy.")
    except (StopIteration, IndexError, socket.error) as e:
        print(f"[!] No se pudo detectar la red con Scapy ({e}). Usando método de respaldo.")
        # Si scapy falla, usamos un método de respaldo con socket
        try:
            hostname = socket.gethostname()
            ip_addr = socket.gethostbyname(hostname)
            # Asumimos una máscara de subred /24, que es la más común en redes domésticas/pequeñas
            network = ipaddress.ip_network(f"{ip_addr}/24", strict=False).network_address
            print(f"[*] No se pudo usar Scapy para detectar la red. Asumiendo red común: {network}")
            return f"{network}/24"
        except socket.gaierror:
            print("[!] Error: No se pudo detectar la red. Por favor, ingrésala manualmente.")
            return None

def _resolve_hostname(ip_addr, update_callback):
    """
    Función auxiliar para resolver el hostname en un hilo separado para no bloquear.
    """
    try:
        # 1. Intento principal: DNS Inverso (rápido si funciona)
        hostname = socket.gethostbyaddr(ip_addr)[0]
    except socket.herror:
        # Si el DNS inverso falla, intentamos identificar si es el gateway
        # o lo marcamos como desconocido.
        try:
            if ip_addr == conf.route.route("0.0.0.0")[2]:
                hostname = "Gateway/Router"
            else:
                hostname = "Desconocido"
        except (IndexError, OSError): # OSError puede ocurrir si no hay ruta
            hostname = "Desconocido"

    if update_callback:
        update_callback({"ip": ip_addr, "hostname": hostname})

def _resolve_manufacturer(mac_addr, ip_addr, update_callback):
    """
    Función auxiliar para buscar el fabricante de la MAC en un hilo separado.
    """
    try:
        manufacturer = MacLookup().lookup(mac_addr)
    except (KeyError, Exception):
        manufacturer = "Desconocido"

    if update_callback:
        update_callback({"ip": ip_addr, "manufacturer": manufacturer})

def scan_network(ip_range, progress_callback=None, result_callback=None, update_callback=None, cancel_event=None):
    """
    Escanea la red local usando un barrido ARP para encontrar dispositivos activos.

    Args:
        ip_range (str): El rango de IPs a escanear (ej. "192.168.1.0/24").
        cancel_event (threading.Event): Evento para señalar la cancelación.

    No devuelve nada, usa callbacks para reportar resultados y progreso.
    """
    print(f"[*] Escaneando la red: {ip_range}...")
    local_network_str = get_default_network_range()
    
    hosts_to_scan = []
    try:
        # Detectar si es un rango con guion, una IP única o una red CIDR
        if "-" in ip_range:
            start_ip_str, end_ip_str = ip_range.split('-')
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())
            current_ip = start_ip
            while current_ip <= end_ip:
                hosts_to_scan.append(current_ip)
                current_ip += 1
            network = ipaddress.ip_network(f"{start_ip}/{start_ip.max_prefixlen}", strict=False) # Para la comprobación de red local
        else:
            network = ipaddress.ip_network(ip_range.strip(), strict=False)
            if network.num_addresses == 1:
                hosts_to_scan.append(network.network_address) # Escanear la IP única
            else:
                hosts_to_scan = list(network.hosts()) # Escanear los hosts de la red

        is_local_scan = local_network_str and ipaddress.ip_network(local_network_str).overlaps(network)
        total_hosts = len(hosts_to_scan)
    except ValueError as e:
        print(f"[!] Rango de IP inválido: {ip_range} ({e})")
        if progress_callback:
            progress_callback(1.0) # Finaliza el progreso si hay error
        return

    print(f"[*] Modo de escaneo: {'Local (ARP)' if is_local_scan else 'Remoto (ICMP)'}")

    for i, host in enumerate(hosts_to_scan):
        # --- Punto de control para la cancelación ---
        if cancel_event and cancel_event.is_set():
            print("[*] Escaneo cancelado por el usuario.")
            break

        host_ip = str(host)
        response = None
        device = None

        if is_local_scan:
            # Escaneo ARP para redes locales
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host_ip)
            answered, _ = srp(arp_request, timeout=0.2, verbose=0, retry=1)
            if answered:
                response = answered[0][1]
                device = {
                    "ip": response.psrc,
                    "mac": response.hwsrc,
                    "manufacturer": "Buscando...",
                    "hostname": "Resolviendo..."
                }
        else:
            # Escaneo ICMP (Ping) para redes remotas/WAN
            icmp_packet = IP(dst=host_ip)/ICMP()
            response = sr1(icmp_packet, timeout=1, verbose=0)
            if response:
                device = {
                    "ip": response.src,
                    "mac": "N/A",  # No se puede obtener MAC en escaneos WAN
                    "manufacturer": "N/A",
                    "hostname": "Resolviendo..."
                }

        if device:
            if result_callback:
                # Usamos la IP como iid porque la MAC puede no estar disponible o repetirse (N/A)
                result_callback(device)

            # Inicia un hilo para resolver el hostname sin bloquear el escaneo principal.
            # Esto se hace para ambos tipos de escaneo.
            hostname_resolver_thread = threading.Thread(target=_resolve_hostname, args=(device["ip"], update_callback))
            hostname_resolver_thread.daemon = True
            hostname_resolver_thread.start()

            # Inicia un hilo para resolver el fabricante solo si es un escaneo local
            if is_local_scan:
                manufacturer_resolver_thread = threading.Thread(target=_resolve_manufacturer, args=(device["mac"], device["ip"], update_callback))
                manufacturer_resolver_thread.daemon = True
                manufacturer_resolver_thread.start()

        if progress_callback:
            progress_callback((i + 1) / total_hosts)

    print("[*] Fase de descubrimiento completada.")

def scan_ports(host_ip, ports_to_scan, progress_callback=None):
    """
    Escanea una lista de puertos TCP en un host específico.

    Args:
        host_ip (str): La dirección IP del host a escanear.
        ports_to_scan (list): Una lista de enteros representando los puertos.
        progress_callback (function, optional): Función para reportar el progreso.

    Returns:
        list: Una lista de puertos abiertos.
    """
    open_ports = []
    total_ports = len(ports_to_scan)
    print(f"[*] Escaneando puertos en {host_ip}...")

    for i, port in enumerate(ports_to_scan):
        # Crear paquete TCP SYN
        packet = IP(dst=host_ip)/TCP(dport=port, flags="S")
        # Enviar y esperar una respuesta (sr1)
        response = sr1(packet, timeout=0.5, verbose=0)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12: # SYN-ACK
            # Enviar un RST para cerrar la conexión que abrimos
            sr1(IP(dst=host_ip)/TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
            open_ports.append(port)
            print(f"[+] Puerto {port} está abierto en {host_ip}")
        
        if progress_callback:
            progress_callback((i + 1) / total_ports)

    print(f"[*] Escaneo de puertos en {host_ip} completado. Puertos abiertos: {open_ports}")
    return open_ports

# --- Bloque de prueba para ejecutar el script directamente ---
if __name__ == "__main__":
    target_range = get_default_network_range()
    if target_range:
        # La función ahora usa callbacks, por lo que el bloque de prueba original ya no es aplicable.
        # Este bloque ahora solo sirve para probar la detección de red.
        print(f"\n[+] Prueba de detección de red completada. Rango detectado: {target_range}")
        print("[+] Para un escaneo completo, ejecute el archivo gui_scanner.py")