import networkx as nx
from pysnmp.hlapi import (nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                          ContextData, ObjectType, ObjectIdentity)
import ipaddress

def _snmp_get_fdb_table(ip_address, community_string='public'):
    """
    Consulta la tabla FDB (Forwarding Database) de un dispositivo SNMP para
    mapear direcciones MAC a puertos del switch.
    Retorna un diccionario {mac_address: port_index} o None si falla.
    """
    mac_port_map = {}
    # OID para la tabla de reenvío del bridge (dot1dTpFdbTable)
    # .1.3.6.1.2.1.17.4.3.1.1 -> dot1dTpFdbAddress (MAC)
    # .1.3.6.1.2.1.17.4.3.1.2 -> dot1dTpFdbPort (Puerto)
    oid_mac = '1.3.6.1.2.1.17.4.3.1.1'
    oid_port = '1.3.6.1.2.1.17.4.3.1.2'

    # Usamos un generador para iterar sobre los resultados de SNMP
    cmd_generator = nextCmd(
        SnmpEngine(),
        CommunityData(community_string, mpModel=0),
        UdpTransportTarget((ip_address, 161), timeout=0.5, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid_mac)),
        ObjectType(ObjectIdentity(oid_port)),
        lexicographicMode=False
    )

    try:
        for errorIndication, errorStatus, errorIndex, varBinds in cmd_generator:
            if errorIndication or errorStatus:
                # Si hay un error, el dispositivo podría no ser un switch o no tener SNMP habilitado
                return None

            # varBinds es una lista de tuplas [(OID, valor), (OID, valor)]
            mac_val = varBinds[0][1]
            port_val = varBinds[1][1]

            # Convertir la MAC a un formato legible y el puerto a un entero
            mac_address = ':'.join(['%02x' % x for x in mac_val.asOctets()])
            port_index = int(port_val)
            mac_port_map[mac_address] = port_index
    except Exception:
        return None # Fallo en la comunicación SNMP

    return mac_port_map if mac_port_map else None

def build_topology(devices, snmp_community='public'):
    """
    Construye un grafo de topología de red a partir de una lista de dispositivos.
    devices: una lista de diccionarios, donde cada diccionario representa un dispositivo.
    """
    G = nx.Graph()
    if not devices:
        return G
    
    # 1. Añadir todos los dispositivos como nodos
    for device in devices:
        # Asegurarnos de que el nodo tenga los datos del dispositivo
        G.add_node(device['ip'], ip=device['ip'], mac=device.get('mac'), hostname=device.get('hostname'), latency=device.get('latency', -1.0))
    device_ips = {d['ip'] for d in devices}

    # 2. Encontrar el gateway (router)
    gateway_ip = None
    # Primero, buscar por hostname "Gateway/Router"
    for ip, data in G.nodes(data=True):
        if data.get('hostname') == "Gateway/Router":
            gateway_ip = ip
            break
    # Si no se encuentra, asumimos que el dispositivo con la IP más baja (ej: .1) es el gateway
    if not gateway_ip:
        try:
            gateway_ip = min(G.nodes(), key=lambda ip: ipaddress.IPv4Address(ip))
        except (ValueError, ipaddress.AddressValueError):
            gateway_ip = list(G.nodes())[0] # Plan C

    # 3. Fase de descubrimiento SNMP
    discovered_switches = {} # {ip_switch: {mac: puerto}}
    unconnected_devices = list(devices)

    print("[Topology] Iniciando fase de descubrimiento SNMP...")
    for device in devices:
        ip = device['ip']
        if ip == gateway_ip: continue
        
        print(f"[Topology] Probando SNMP en {ip}...")
        fdb_table = _snmp_get_fdb_table(ip, snmp_community)
        if fdb_table:
            print(f"[+] Switch SNMP descubierto en {ip} con {len(fdb_table)} entradas FDB.")
            discovered_switches[ip] = fdb_table
            G.nodes[ip]['type'] = 'switch_snmp' # Marcar como switch
            # Conectar el switch descubierto al gateway
            G.add_edge(gateway_ip, ip, type='confirmed')
            # Si este dispositivo era un dispositivo normal, ya no necesita conexión
            if device in unconnected_devices:
                unconnected_devices.remove(device)

    # 4. Conectar dispositivos a los switches descubiertos por SNMP
    print("[Topology] Mapeando dispositivos a switches SNMP...")
    devices_to_connect_later = []
    for device in unconnected_devices:
        mac = device.get('mac')
        if not mac:
            devices_to_connect_later.append(device)
            continue
        
        connected = False
        for switch_ip, fdb in discovered_switches.items():
            if mac in fdb:
                G.add_edge(switch_ip, device['ip'], type='snmp_confirmed', port=fdb[mac])
                print(f"[+] Conectado {device['ip']} a switch {switch_ip} (MAC encontrada en FDB)")
                connected = True
                break
        if not connected:
            devices_to_connect_later.append(device)

    # 5. Fallback a la lógica de latencia para dispositivos restantes
    print(f"[Topology] {len(devices_to_connect_later)} dispositivos restantes. Usando inferencia por latencia.")
    
    # Lógica de Clustering por Latencia
    # Filtramos dispositivos que ya están conectados o no tienen latencia válida
    devices_for_clustering = [
        d for d in devices_to_connect_later 
        if d['ip'] != gateway_ip and G.degree(d['ip']) == 0 and d.get('latency', -1) >= 0
    ]
    
    if not devices_for_clustering:
        # Si no hay dispositivos para agrupar, pasamos directamente a conectar los huérfanos.
        pass
    else:
        # Ordenar dispositivos por latencia para facilitar el agrupamiento
        devices_for_clustering.sort(key=lambda d: d['latency'])

        clusters = []
        if devices_for_clustering:
            current_cluster = [devices_for_clustering[0]]
            # Umbral para decidir si un dispositivo pertenece a un nuevo cluster (ej. 5ms de diferencia)
            CLUSTER_GAP_THRESHOLD = 5.0

            for i in range(1, len(devices_for_clustering)):
                prev_latency = devices_for_clustering[i-1]['latency']
                current_latency = devices_for_clustering[i]['latency']
                if current_latency - prev_latency > CLUSTER_GAP_THRESHOLD:
                    clusters.append(current_cluster)
                    current_cluster = [devices_for_clustering[i]]
                else:
                    current_cluster.append(devices_for_clustering[i])
            clusters.append(current_cluster)

        for i, cluster in enumerate(clusters):
            virtual_switch_node = f"Cluster Virtual {i+1}"
            G.add_node(virtual_switch_node, hostname=f"Cluster {i+1}", type='virtual_switch')
            G.add_edge(gateway_ip, virtual_switch_node, type='confirmed')
            for device in cluster:
                G.add_edge(virtual_switch_node, device['ip'], type='inferred_latency')

    # 6. Conexión final para nodos huérfanos
    # Cualquier nodo que no sea el gateway y que aún no tenga conexiones se conecta directamente al gateway.
    # Esto asegura que ningún dispositivo quede flotando.
    for node in G.nodes():
        if node != gateway_ip and G.degree(node) == 0:
            G.add_edge(gateway_ip, node, type='inferred_wifi_or_remote')

    return G