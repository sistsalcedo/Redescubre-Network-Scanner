import logging
import threading

# Configuración de logging para depuración
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importaciones robustas: Si faltan librerías, no crasheamos inmediatamente,
# sino que deshabilitamos la funcionalidad.
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    from pysnmp.hlapi import (nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                              ContextData, ObjectType, ObjectIdentity)
    import ipaddress
    DEPENDENCIES_INSTALLED = True
except ImportError as e:
    logger.error(f"Faltan dependencias para topología: {e}")
    DEPENDENCIES_INSTALLED = False
    # Definimos clases dummy o variables para evitar NameErrors si se intenta usar sin deps
    nx = None
    plt = None

def _snmp_get_fdb_table(ip_address, community_string='public'):
    """
    Consulta la tabla FDB (Forwarding Database) de un dispositivo SNMP.
    Retorna {mac: port} o None si falla.
    """
    if not DEPENDENCIES_INSTALLED:
        return None

    mac_port_map = {}
    # OIDs estándar para Bridge MIB
    oid_mac = '1.3.6.1.2.1.17.4.3.1.1'
    oid_port = '1.3.6.1.2.1.17.4.3.1.2'

    try:
        # Timeout corto (0.5s) y sin reintentos para no bloquear demasiado tiempo
        cmd_generator = nextCmd(
            SnmpEngine(),
            CommunityData(community_string, mpModel=0), # SNMP v1
            UdpTransportTarget((ip_address, 161), timeout=0.5, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid_mac)),
            ObjectType(ObjectIdentity(oid_port)),
            lexicographicMode=False
        )

        for errorIndication, errorStatus, errorIndex, varBinds in cmd_generator:
            if errorIndication:
                # Error de transporte (ej: timeout, host inalcanzable)
                return None
            if errorStatus:
                # Error devuelto por el agente SNMP
                return None

            # varBinds[0] -> MAC, varBinds[1] -> Puerto
            mac_val = varBinds[0][1]
            port_val = varBinds[1][1]

            # Convertir MAC bytes a string hex (ej: "00:11:22:...")
            try:
                mac_address = ':'.join(['%02x' % x for x in mac_val.asOctets()])
                port_index = int(port_val)
                mac_port_map[mac_address] = port_index
            except Exception:
                continue # Saltar entradas malformadas

    except Exception as e:
        logger.debug(f"Error SNMP en {ip_address}: {e}")
        return None

    return mac_port_map if mac_port_map else None

def build_topology(devices, snmp_community='public'):
    """
    Construye un grafo NetworkX a partir de la lista de dispositivos.
    """
    if not DEPENDENCIES_INSTALLED:
        logger.warning("No se puede construir topología: Faltan dependencias.")
        return None

    G = nx.Graph()
    if not devices:
        return G
    
    logger.info("Iniciando construcción de topología...")

    # 1. Añadir Nodos
    for device in devices:
        G.add_node(device['ip'], 
                   label=device.get('hostname', device['ip']),
                   mac=device.get('mac'),
                   type='device')

    # 2. Identificar Gateway (Router)
    gateway_ip = None
    # Buscar explícitamente
    for ip, data in G.nodes(data=True):
        if "Gateway" in str(data.get('label', '')):
            gateway_ip = ip
            break
    
    # Si no, usar la IP más baja (heurística común)
    if not gateway_ip:
        try:
            gateway_ip = min(G.nodes(), key=lambda x: ipaddress.IPv4Address(x))
        except Exception:
            gateway_ip = list(G.nodes())[0]
    
    G.nodes[gateway_ip]['type'] = 'router'
    logger.info(f"Gateway identificado: {gateway_ip}")

    # 3. Descubrimiento SNMP (Switches)
    unconnected = list(devices)
    if gateway_ip:
        # El gateway siempre está "conectado" a la nube, lo sacamos de la lista de huérfanos
        unconnected = [d for d in unconnected if d['ip'] != gateway_ip]

    # Diccionario para guardar qué switch tiene qué MACs en qué puertos
    switch_fdb_cache = {} 

    for device in devices:
        ip = device['ip']
        if ip == gateway_ip: continue # No escaneamos el router como switch por ahora

        fdb = _snmp_get_fdb_table(ip, snmp_community)
        if fdb:
            logger.info(f"Switch SNMP encontrado: {ip} ({len(fdb)} entradas)")
            G.nodes[ip]['type'] = 'switch'
            switch_fdb_cache[ip] = fdb
            # Asumimos que el switch está conectado al router (topología estrella simple)
            # En una red real, habría que analizar STP o LLDP para ver conexiones entre switches
            G.add_edge(gateway_ip, ip, method='snmp_uplink')
            
            # Si este dispositivo estaba en unconnected, lo quitamos
            unconnected = [d for d in unconnected if d['ip'] != ip]

    # 4. Conectar dispositivos a Switches
    for device in list(unconnected): # Copia para iterar seguro
        mac = device.get('mac')
        if not mac: continue

        for switch_ip, fdb in switch_fdb_cache.items():
            if mac in fdb:
                # ¡Bingo! Este dispositivo está conectado a este switch
                G.add_edge(switch_ip, device['ip'], method='snmp_fdb', port=fdb[mac])
                if device in unconnected:
                    unconnected.remove(device)
                break

import logging
import threading

# Configuración de logging para depuración
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importaciones robustas: Si faltan librerías, no crasheamos inmediatamente,
# sino que deshabilitamos la funcionalidad.
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    from pysnmp.hlapi import (nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                              ContextData, ObjectType, ObjectIdentity)
    import ipaddress
    DEPENDENCIES_INSTALLED = True
except ImportError as e:
    logger.error(f"Faltan dependencias para topología: {e}")
    DEPENDENCIES_INSTALLED = False
    # Definimos clases dummy o variables para evitar NameErrors si se intenta usar sin deps
    nx = None
    plt = None

def _snmp_get_fdb_table(ip_address, community_string='public'):
    """
    Consulta la tabla FDB (Forwarding Database) de un dispositivo SNMP.
    Retorna {mac: port} o None si falla.
    """
    if not DEPENDENCIES_INSTALLED:
        return None

    mac_port_map = {}
    # OIDs estándar para Bridge MIB
    oid_mac = '1.3.6.1.2.1.17.4.3.1.1'
    oid_port = '1.3.6.1.2.1.17.4.3.1.2'

    try:
        # Timeout corto (0.5s) y sin reintentos para no bloquear demasiado tiempo
        cmd_generator = nextCmd(
            SnmpEngine(),
            CommunityData(community_string, mpModel=0), # SNMP v1
            UdpTransportTarget((ip_address, 161), timeout=0.5, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid_mac)),
            ObjectType(ObjectIdentity(oid_port)),
            lexicographicMode=False
        )

        for errorIndication, errorStatus, errorIndex, varBinds in cmd_generator:
            if errorIndication:
                # Error de transporte (ej: timeout, host inalcanzable)
                return None
            if errorStatus:
                # Error devuelto por el agente SNMP
                return None

            # varBinds[0] -> MAC, varBinds[1] -> Puerto
            mac_val = varBinds[0][1]
            port_val = varBinds[1][1]

            # Convertir MAC bytes a string hex (ej: "00:11:22:...")
            try:
                mac_address = ':'.join(['%02x' % x for x in mac_val.asOctets()])
                port_index = int(port_val)
                mac_port_map[mac_address] = port_index
            except Exception:
                continue # Saltar entradas malformadas

    except Exception as e:
        logger.debug(f"Error SNMP en {ip_address}: {e}")
        return None

    return mac_port_map if mac_port_map else None

def build_topology(devices, snmp_community='public'):
    """
    Construye un grafo NetworkX a partir de la lista de dispositivos.
    """
    if not DEPENDENCIES_INSTALLED:
        logger.warning("No se puede construir topología: Faltan dependencias.")
        return None

    G = nx.Graph()
    if not devices:
        return G
    
    logger.info("Iniciando construcción de topología...")

    # 1. Añadir Nodos
    for device in devices:
        G.add_node(device['ip'], 
                   label=device.get('hostname', device['ip']),
                   mac=device.get('mac'),
                   type='device')

    # 2. Identificar Gateway (Router)
    gateway_ip = None
    # Buscar explícitamente
    for ip, data in G.nodes(data=True):
        if "Gateway" in str(data.get('label', '')):
            gateway_ip = ip
            break
    
    # Si no, usar la IP más baja (heurística común)
    if not gateway_ip:
        try:
            gateway_ip = min(G.nodes(), key=lambda x: ipaddress.IPv4Address(x))
        except Exception:
            gateway_ip = list(G.nodes())[0]
    
    G.nodes[gateway_ip]['type'] = 'router'
    logger.info(f"Gateway identificado: {gateway_ip}")

    # 3. Descubrimiento SNMP (Switches)
    unconnected = list(devices)
    if gateway_ip:
        # El gateway siempre está "conectado" a la nube, lo sacamos de la lista de huérfanos
        unconnected = [d for d in unconnected if d['ip'] != gateway_ip]

    # Diccionario para guardar qué switch tiene qué MACs en qué puertos
    switch_fdb_cache = {} 

    for device in devices:
        ip = device['ip']
        if ip == gateway_ip: continue # No escaneamos el router como switch por ahora

        fdb = _snmp_get_fdb_table(ip, snmp_community)
        if fdb:
            logger.info(f"Switch SNMP encontrado: {ip} ({len(fdb)} entradas)")
            G.nodes[ip]['type'] = 'switch'
            switch_fdb_cache[ip] = fdb
            # Asumimos que el switch está conectado al router (topología estrella simple)
            # En una red real, habría que analizar STP o LLDP para ver conexiones entre switches
            G.add_edge(gateway_ip, ip, method='snmp_uplink')
            
            # Si este dispositivo estaba en unconnected, lo quitamos
            unconnected = [d for d in unconnected if d['ip'] != ip]

    # 4. Conectar dispositivos a Switches
    for device in list(unconnected): # Copia para iterar seguro
        mac = device.get('mac')
        if not mac: continue

        for switch_ip, fdb in switch_fdb_cache.items():
            if mac in fdb:
                # ¡Bingo! Este dispositivo está conectado a este switch
                G.add_edge(switch_ip, device['ip'], method='snmp_fdb', port=fdb[mac])
                if device in unconnected:
                    unconnected.remove(device)
                break

    # 5. Fallback: Conectar huérfanos al Gateway
            gateway_ip = list(G.nodes())[0]
    
    G.nodes[gateway_ip]['type'] = 'router'
    logger.info(f"Gateway identificado: {gateway_ip}")

    # 3. Descubrimiento SNMP (Switches)
    unconnected = list(devices)
    if gateway_ip:
        # El gateway siempre está "conectado" a la nube, lo sacamos de la lista de huérfanos
        unconnected = [d for d in unconnected if d['ip'] != gateway_ip]

    # Diccionario para guardar qué switch tiene qué MACs en qué puertos
    switch_fdb_cache = {} 

    for device in devices:
        ip = device['ip']
        if ip == gateway_ip: continue # No escaneamos el router como switch por ahora

        fdb = _snmp_get_fdb_table(ip, snmp_community)
        if fdb:
            logger.info(f"Switch SNMP encontrado: {ip} ({len(fdb)} entradas)")
            G.nodes[ip]['type'] = 'switch'
            switch_fdb_cache[ip] = fdb
            # Asumimos que el switch está conectado al router (topología estrella simple)
            # En una red real, habría que analizar STP o LLDP para ver conexiones entre switches
            G.add_edge(gateway_ip, ip, method='snmp_uplink')
            
            # Si este dispositivo estaba en unconnected, lo quitamos
            unconnected = [d for d in unconnected if d['ip'] != ip]

    # 4. Conectar dispositivos a Switches
    for device in list(unconnected): # Copia para iterar seguro
        mac = device.get('mac')
        if not mac: continue

        for switch_ip, fdb in switch_fdb_cache.items():
            if mac in fdb:
                # ¡Bingo! Este dispositivo está conectado a este switch
                G.add_edge(switch_ip, device['ip'], method='snmp_fdb', port=fdb[mac])
                if device in unconnected:
                    unconnected.remove(device)
                break

import logging
import threading

# Configuración de logging para depuración
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importaciones robustas: Si faltan librerías, no crasheamos inmediatamente,
# sino que deshabilitamos la funcionalidad.
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    from pysnmp.hlapi import (nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                              ContextData, ObjectType, ObjectIdentity)
    import ipaddress
    DEPENDENCIES_INSTALLED = True
except ImportError as e:
    logger.error(f"Faltan dependencias para topología: {e}")
    DEPENDENCIES_INSTALLED = False
    # Definimos clases dummy o variables para evitar NameErrors si se intenta usar sin deps
    nx = None
    plt = None

def _snmp_get_fdb_table(ip_address, community_string='public'):
    """
    Consulta la tabla FDB (Forwarding Database) de un dispositivo SNMP.
    Retorna {mac: port} o None si falla.
    """
    if not DEPENDENCIES_INSTALLED:
        return None

    mac_port_map = {}
    # OIDs estándar para Bridge MIB
    oid_mac = '1.3.6.1.2.1.17.4.3.1.1'
    oid_port = '1.3.6.1.2.1.17.4.3.1.2'

    try:
        # Timeout corto (0.5s) y sin reintentos para no bloquear demasiado tiempo
        cmd_generator = nextCmd(
            SnmpEngine(),
            CommunityData(community_string, mpModel=0), # SNMP v1
            UdpTransportTarget((ip_address, 161), timeout=0.5, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid_mac)),
            ObjectType(ObjectIdentity(oid_port)),
            lexicographicMode=False
        )

        for errorIndication, errorStatus, errorIndex, varBinds in cmd_generator:
            if errorIndication:
                # Error de transporte (ej: timeout, host inalcanzable)
                return None
            if errorStatus:
                # Error devuelto por el agente SNMP
                return None

            # varBinds[0] -> MAC, varBinds[1] -> Puerto
            mac_val = varBinds[0][1]
            port_val = varBinds[1][1]

            # Convertir MAC bytes a string hex (ej: "00:11:22:...")
            try:
                mac_address = ':'.join(['%02x' % x for x in mac_val.asOctets()])
                port_index = int(port_val)
                mac_port_map[mac_address] = port_index
            except Exception:
                continue # Saltar entradas malformadas

    except Exception as e:
        logger.debug(f"Error SNMP en {ip_address}: {e}")
        return None

    return mac_port_map if mac_port_map else None

def build_topology(devices, snmp_community='public'):
    """
    Construye un grafo NetworkX a partir de la lista de dispositivos.
    """
    if not DEPENDENCIES_INSTALLED:
        logger.warning("No se puede construir topología: Faltan dependencias.")
        return None

    G = nx.Graph()
    if not devices:
        return G
    
    logger.info("Iniciando construcción de topología...")

    # 1. Añadir Nodos
    for device in devices:
        G.add_node(device['ip'], 
                   label=device.get('hostname', device['ip']),
                   mac=device.get('mac'),
                   type='device')

    # 2. Identificar Gateway (Router)
    gateway_ip = None
    # Buscar explícitamente
    for ip, data in G.nodes(data=True):
        if "Gateway" in str(data.get('label', '')):
            gateway_ip = ip
            break
    
    # Si no, usar la IP más baja (heurística común)
    if not gateway_ip:
        try:
            gateway_ip = min(G.nodes(), key=lambda x: ipaddress.IPv4Address(x))
        except Exception:
            gateway_ip = list(G.nodes())[0]
    
    G.nodes[gateway_ip]['type'] = 'router'
    logger.info(f"Gateway identificado: {gateway_ip}")

    # 3. Descubrimiento SNMP (Switches)
    unconnected = list(devices)
    if gateway_ip:
        # El gateway siempre está "conectado" a la nube, lo sacamos de la lista de huérfanos
        unconnected = [d for d in unconnected if d['ip'] != gateway_ip]

    # Diccionario para guardar qué switch tiene qué MACs en qué puertos
    switch_fdb_cache = {} 

    for device in devices:
        ip = device['ip']
        if ip == gateway_ip: continue # No escaneamos el router como switch por ahora

        fdb = _snmp_get_fdb_table(ip, snmp_community)
        if fdb:
            logger.info(f"Switch SNMP encontrado: {ip} ({len(fdb)} entradas)")
            G.nodes[ip]['type'] = 'switch'
            switch_fdb_cache[ip] = fdb
            # Asumimos que el switch está conectado al router (topología estrella simple)
            # En una red real, habría que analizar STP o LLDP para ver conexiones entre switches
            G.add_edge(gateway_ip, ip, method='snmp_uplink')
            
            # Si este dispositivo estaba en unconnected, lo quitamos
            unconnected = [d for d in unconnected if d['ip'] != ip]

    # 4. Conectar dispositivos a Switches
    for device in list(unconnected): # Copia para iterar seguro
        mac = device.get('mac')
        if not mac: continue

        for switch_ip, fdb in switch_fdb_cache.items():
            if mac in fdb:
                # ¡Bingo! Este dispositivo está conectado a este switch
                G.add_edge(switch_ip, device['ip'], method='snmp_fdb', port=fdb[mac])
                if device in unconnected:
                    unconnected.remove(device)
                break

    # 5. Fallback: Conectar huérfanos al Gateway
    # AQUI INTEGRAMOS LA TOPOLOGIA MANUAL
    from topology_manager import TopologyManager
    tm = TopologyManager()

    for device in unconnected:
        ip = device['ip']
        
        # 5.1 Verificar si tiene un padre manual asignado
        manual_uplink = tm.get_uplink(ip)
        
        if manual_uplink:
            # Verificar si el padre existe en el grafo, si no, agregarlo temporalmente o conectar al gateway
            if not G.has_node(manual_uplink):
                # Si el padre no fue escaneado (ej: switch en otra subred), lo añadimos como nodo fantasma
                G.add_node(manual_uplink, label=f"Switch Manual\n{manual_uplink}", type='switch')
            
            G.add_edge(manual_uplink, ip, method='manual')
            logger.info(f"Conexión manual: {ip} -> {manual_uplink}")
        else:
            # 5.2 Si no tiene padre manual, fallback al Gateway
            G.add_edge(gateway_ip, ip, method='fallback')

    # 6. Aplicar tipos manuales (Iconos)
    for node in G.nodes():
        manual_type = tm.get_device_type(node)
        if manual_type:
            G.nodes[node]['type'] = manual_type

    return G

import logging
import threading

# Configuración de logging para depuración
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importaciones robustas: Si faltan librerías, no crasheamos inmediatamente,
# sino que deshabilitamos la funcionalidad.
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    from pysnmp.hlapi import (nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                              ContextData, ObjectType, ObjectIdentity)
    import ipaddress
    DEPENDENCIES_INSTALLED = True
except ImportError as e:
    logger.error(f"Faltan dependencias para topología: {e}")
    DEPENDENCIES_INSTALLED = False
    # Definimos clases dummy o variables para evitar NameErrors si se intenta usar sin deps
    nx = None
    plt = None

def _snmp_get_fdb_table(ip_address, community_string='public'):
    """
    Consulta la tabla FDB (Forwarding Database) de un dispositivo SNMP.
    Retorna {mac: port} o None si falla.
    """
    if not DEPENDENCIES_INSTALLED:
        return None

    mac_port_map = {}
    # OIDs estándar para Bridge MIB
    oid_mac = '1.3.6.1.2.1.17.4.3.1.1'
    oid_port = '1.3.6.1.2.1.17.4.3.1.2'

    try:
        # Timeout corto (0.5s) y sin reintentos para no bloquear demasiado tiempo
        cmd_generator = nextCmd(
            SnmpEngine(),
            CommunityData(community_string, mpModel=0), # SNMP v1
            UdpTransportTarget((ip_address, 161), timeout=0.5, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid_mac)),
            ObjectType(ObjectIdentity(oid_port)),
            lexicographicMode=False
        )

        for errorIndication, errorStatus, errorIndex, varBinds in cmd_generator:
            if errorIndication:
                # Error de transporte (ej: timeout, host inalcanzable)
                return None
            if errorStatus:
                # Error devuelto por el agente SNMP
                return None

            # varBinds[0] -> MAC, varBinds[1] -> Puerto
            mac_val = varBinds[0][1]
            port_val = varBinds[1][1]

            # Convertir MAC bytes a string hex (ej: "00:11:22:...")
            try:
                mac_address = ':'.join(['%02x' % x for x in mac_val.asOctets()])
                port_index = int(port_val)
                mac_port_map[mac_address] = port_index
            except Exception:
                continue # Saltar entradas malformadas

    except Exception as e:
        logger.debug(f"Error SNMP en {ip_address}: {e}")
        return None

    return mac_port_map if mac_port_map else None

def build_topology(devices, snmp_community='public'):
    """
    Construye un grafo NetworkX a partir de la lista de dispositivos.
    """
    if not DEPENDENCIES_INSTALLED:
        logger.warning("No se puede construir topología: Faltan dependencias.")
        return None

    G = nx.Graph()
    if not devices:
        return G
    
    logger.info("Iniciando construcción de topología...")

    # 1. Añadir Nodos
    for device in devices:
        G.add_node(device['ip'], 
                   label=device.get('hostname', device['ip']),
                   mac=device.get('mac'),
                   type='device')

    # 2. Identificar Gateway (Router)
    gateway_ip = None
    # Buscar explícitamente
    for ip, data in G.nodes(data=True):
        if "Gateway" in str(data.get('label', '')):
            gateway_ip = ip
            break
    
    # Si no, usar la IP más baja (heurística común)
    if not gateway_ip:
        try:
            gateway_ip = min(G.nodes(), key=lambda x: ipaddress.IPv4Address(x))
        except Exception:
            gateway_ip = list(G.nodes())[0]
    
    G.nodes[gateway_ip]['type'] = 'router'
    logger.info(f"Gateway identificado: {gateway_ip}")

    # 3. Descubrimiento SNMP (Switches)
    unconnected = list(devices)
    if gateway_ip:
        # El gateway siempre está "conectado" a la nube, lo sacamos de la lista de huérfanos
        unconnected = [d for d in unconnected if d['ip'] != gateway_ip]

    # Diccionario para guardar qué switch tiene qué MACs en qué puertos
    switch_fdb_cache = {} 

    for device in devices:
        ip = device['ip']
        if ip == gateway_ip: continue # No escaneamos el router como switch por ahora

        fdb = _snmp_get_fdb_table(ip, snmp_community)
        if fdb:
            logger.info(f"Switch SNMP encontrado: {ip} ({len(fdb)} entradas)")
            G.nodes[ip]['type'] = 'switch'
            switch_fdb_cache[ip] = fdb
            # Asumimos que el switch está conectado al router (topología estrella simple)
            # En una red real, habría que analizar STP o LLDP para ver conexiones entre switches
            G.add_edge(gateway_ip, ip, method='snmp_uplink')
            
            # Si este dispositivo estaba en unconnected, lo quitamos
            unconnected = [d for d in unconnected if d['ip'] != ip]

    # 4. Conectar dispositivos a Switches
    for device in list(unconnected): # Copia para iterar seguro
        mac = device.get('mac')
        if not mac: continue

        for switch_ip, fdb in switch_fdb_cache.items():
            if mac in fdb:
                # ¡Bingo! Este dispositivo está conectado a este switch
                G.add_edge(switch_ip, device['ip'], method='snmp_fdb', port=fdb[mac])
                if device in unconnected:
                    unconnected.remove(device)
                break

    # 5. Fallback: Conectar huérfanos al Gateway
    # AQUI INTEGRAMOS LA TOPOLOGIA MANUAL
    from topology_manager import TopologyManager
    tm = TopologyManager()

    for device in unconnected:
        ip = device['ip']
        
        # 5.1 Verificar si tiene un padre manual asignado
        manual_uplink = tm.get_uplink(ip)
        
        if manual_uplink:
            # Verificar si el padre existe en el grafo, si no, agregarlo temporalmente o conectar al gateway
            if not G.has_node(manual_uplink):
                # Si el padre no fue escaneado (ej: switch en otra subred), lo añadimos como nodo fantasma
                G.add_node(manual_uplink, label=f"Switch Manual\n{manual_uplink}", type='switch')
            
            G.add_edge(manual_uplink, ip, method='manual')
            logger.info(f"Conexión manual: {ip} -> {manual_uplink}")
        else:
            # 5.2 Si no tiene padre manual, fallback al Gateway
            G.add_edge(gateway_ip, ip, method='fallback')

    # 6. Aplicar tipos manuales (Iconos)
    for node in G.nodes():
        manual_type = tm.get_device_type(node)
        if manual_type:
            G.nodes[node]['type'] = manual_type

    return G

def generate_interactive_topology(G, output_file="mapa_red.html"):
    """
    Genera un mapa interactivo HTML usando Pyvis.
    Retorna la ruta absoluta del archivo generado.
    """
    if not DEPENDENCIES_INSTALLED or not G:
        return None

    try:
        from pyvis.network import Network
        import os

        # Crear red Pyvis
        net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", select_menu=True)
        
        # Configuración de física para que los nodos se repelan y no se amontonen
        net.force_atlas_2based()
        
        # Añadir nodos con estilos personalizados
        for node, attr in G.nodes(data=True):
            node_type = attr.get('type', 'device')
            label = attr.get('label', node)
            title = f"IP: {node}\nMAC: {attr.get('mac', 'N/A')}\nTipo: {node_type}"
            
            color = "#97C2FC" # Azul claro por defecto (Device)
            shape = "dot"
            size = 15
            
            if node_type == 'router':
                color = "#FF5733" # Naranja rojizo
                size = 30
                shape = "star"
            elif node_type == 'switch':
                color = "#FFC300" # Amarillo
                size = 25
                shape = "triangle"
            
            net.add_node(node, label=label, title=title, color=color, shape=shape, size=size)

        # Añadir conexiones
        for source, target, attr in G.edges(data=True):
            net.add_edge(source, target, color="#aaaaaa")

        # Guardar archivo
        # Usamos path absoluto para evitar problemas de ubicación
        full_path = os.path.abspath(output_file)
        net.save_graph(full_path)
        logger.info(f"Mapa interactivo guardado en: {full_path}")
        return full_path

    except Exception as e:
        logger.error(f"Error generando mapa interactivo: {e}")
        return None