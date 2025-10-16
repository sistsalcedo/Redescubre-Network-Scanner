# Redescubre - Escáner de Red con GUI

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Redescubre** es una herramienta de escaneo de red de escritorio con una interfaz gráfica moderna e intuitiva. Permite descubrir dispositivos en redes locales y WAN, identificar fabricantes, resolver nombres de host y escanear puertos abiertos.

Este proyecto fue creado como una alternativa a herramientas populares como *Advanced IP Scanner*, ofreciendo una solución de código abierto desarrollada en Python.

---

<!-- Aquí puedes agregar una captura de pantalla de la aplicación -->
<!-- ![Captura de la aplicación](ruta/a/tu/screenshot.png) -->

## ✨ Características Principales

- **Detección Automática de Red**: Detecta y sugiere automáticamente el rango de red local para escanear.
- **Escaneo Flexible**:
  - **Local (ARP)**: Escaneo rápido y eficiente para redes locales.
  - **Remoto (ICMP)**: Escaneo de IPs o rangos remotos mediante paquetes ICMP (Ping).
  - Admite notación CIDR (`192.168.1.0/24`), rangos con guion (`192.168.1.1-100`) e IPs individuales.
- **Información Detallada**:
  - Resolución de **Hostname** para identificar los nombres de los dispositivos.
  - Búsqueda del **Fabricante** a partir de la dirección MAC.
- **Interfaz Gráfica Moderna**:
  - Construida con `CustomTkinter` para una apariencia limpia y moderna.
  - Tabla de resultados interactiva con ordenamiento por columnas y filtrado en tiempo real.
  - Soporte multi-idioma (Español e Inglés).
- **Funcionalidades Avanzadas**:
  - **Menú contextual** (clic derecho) para realizar acciones rápidas: Ping, Conexión RDP, Abrir en navegador (HTTP).
  - **Escaneo de Puertos**: Escanea puertos TCP comunes con un doble clic sobre un dispositivo.
  - **Exportación a CSV**: Guarda los resultados del escaneo en un archivo CSV.
- **Diseño Asíncrono**: El escaneo se ejecuta en hilos separados para mantener la interfaz de usuario siempre responsiva, con opción de cancelación.

## 🚀 Instalación y Uso

Asegúrate de tener **Python 3.8 o superior** instalado.

> **⚠️ Nota para usuarios de Windows:** Para que el escaneo de red funcione correctamente, es **necesario** instalar **Npcap**. Esta herramienta permite a Scapy capturar y enviar paquetes de red.
>
> - **[Descarga Npcap desde su sitio oficial](https://npcap.com/#download)**
> - Durante la instalación, asegúrate de marcar la opción "Install Npcap in WinPcap API-compatible Mode".

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/tu-usuario/tu-repositorio.git
    cd tu-repositorio
    ```

2.  **Crea y activa un entorno virtual:**
    ```bash
    # En Windows
    python -m venv venv
    .\venv\Scripts\activate

    # En macOS/Linux
    python -m venv venv
    source venv/bin/activate
    ```

3.  **Instala las dependencias:**
    El proyecto utiliza las librerías listadas en `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

4.  **Ejecuta la aplicación:**
    Para iniciar la interfaz gráfica, ejecuta el siguiente comando:
    ```bash
    python gui_scanner.py
    ```

## 📦 Dependencias

- CustomTkinter: Para la interfaz gráfica.
- Scapy: Para la construcción y envío de paquetes de red (ARP, ICMP, TCP).
- mac-vendor-lookup: Para buscar el fabricante de las direcciones MAC.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

---

*Desarrollado por Milton Salcedo Cruz.*