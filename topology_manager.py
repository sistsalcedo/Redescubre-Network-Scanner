import json
import os
import logging
from scanner_backend import get_data_directory

logger = logging.getLogger(__name__)

class TopologyManager:
    def __init__(self):
        self.file_path = os.path.join(get_data_directory(), "topology_custom.json")
        self.data = self._load_data()

    def _load_data(self):
        """Carga la topología personalizada desde el archivo JSON."""
        if not os.path.exists(self.file_path):
            return {"nodes": {}, "links": {}} # nodes: {ip: type}, links: {child_ip: parent_ip}
        
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error cargando topología personalizada: {e}")
            return {"nodes": {}, "links": {}}

    def _save_data(self):
        """Guarda los cambios en el archivo JSON."""
        try:
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            logger.error(f"Error guardando topología personalizada: {e}")

    def set_device_type(self, ip, device_type):
        """Define el tipo de dispositivo (router, switch, device)."""
        self.data["nodes"][ip] = device_type
        self._save_data()

    def get_device_type(self, ip):
        """Obtiene el tipo de dispositivo guardado o None."""
        return self.data["nodes"].get(ip)

    def reset_device_type(self, ip):
        """Elimina la personalización de tipo de dispositivo."""
        if ip in self.data["nodes"]:
            del self.data["nodes"][ip]
            self._save_data()

    def set_uplink(self, child_ip, parent_ip):
        """Define que 'child_ip' está conectado a 'parent_ip'."""
        # Evitar ciclos simples (A->A)
        if child_ip == parent_ip:
            return False
        
        self.data["links"][child_ip] = parent_ip
        self._save_data()
        return True

    def get_uplink(self, child_ip):
        """Obtiene la IP del padre de un dispositivo."""
        return self.data["links"].get(child_ip)

    def remove_uplink(self, child_ip):
        """Elimina la conexión manual de un dispositivo."""
        if child_ip in self.data["links"]:
            del self.data["links"][child_ip]
            self._save_data()

    def get_all_switches(self):
        """Retorna una lista de IPs marcadas como switch o router."""
        return [ip for ip, dtype in self.data["nodes"].items() if dtype in ('switch', 'router')]
