import logging
from pysnmp.hlapi import *
import ipaddress
import sys
import socket

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

def check_snmp(ip, community='public'):
    """
    Intenta obtener la descripción del sistema (sysDescr) vía SNMP.
    """
    print(f"Probando {ip} con comunidad '{community}'...", end=" ")
    
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community, mpModel=0), # SNMP v1
                   UdpTransportTarget((ip, 161), timeout=1.0, retries=1),
                   ContextData(),
                   ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))) # sysDescr
        )

        if errorIndication:
            print(f"❌ Fallo: {errorIndication}")
            return False
        elif errorStatus:
            print(f"❌ Error SNMP: {errorStatus.prettyPrint()}")
            return False
        else:
            print("✅ ¡ÉXITO!")
            for varBind in varBinds:
                print(f"   📝 Info: {varBind[1].prettyPrint()}")
            return True

    except Exception as e:
        print(f"❌ Excepción: {e}")
        return False

def scan_range(network_range):
    try:
        # Convertir "192.168.1.0/24" a lista de hosts
        net = ipaddress.ip_network(network_range, strict=False)
        print(f"\n--- Iniciando diagnóstico SNMP en {network_range} ---")
        print("Buscando dispositivos que respondan a la comunidad 'public'...\n")
        
        found = 0
        for ip in net.hosts():
            ip_str = str(ip)
            # Solo probar si el host responde a ping (opcional, para velocidad)
            # Aquí probamos directo SNMP para no depender de ICMP
            if check_snmp(ip_str):
                found += 1
                
        print(f"\n--- Fin del diagnóstico. Dispositivos SNMP encontrados: {found} ---")
        
    except ValueError as e:
        print(f"Error en el rango de red: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python snmp_tester.py <rango_ip>")
        print("Ejemplo: python snmp_tester.py 192.168.10.0/24")
    else:
        scan_range(sys.argv[1])
