# Plan de Implementación: Python Network Scanner

> **Objetivo del Proyecto:** Crear una aplicación de escritorio con GUI moderna para escanear la red local, identificar dispositivos y ofrecer funcionalidades de administración básica, como alternativa a herramientas bloqueadas como Advanced IP Scanner.

---

## Fase 0: Preparación y Configuración del Entorno

*   **Objetivo:** Tener todo listo para empezar a programar sin problemas.
*   **Tareas:**
    - [ ] **Instalar Python:** Asegurarse de tener Python 3.8 o superior instalado en el sistema.
    - [ ] **Crear un Entorno Virtual:** Aislar las dependencias del proyecto.
        *   Abrir una terminal en la carpeta del proyecto y ejecutar:
            ```bash
            # Crear el entorno virtual (llamado 'venv')
            python -m venv venv
            ```
        *   Activar el entorno:
            ```bash
            # En Windows (cmd o PowerShell)
            .\venv\Scripts\activate
            
            # En macOS/Linux
            source venv/bin/activate
            ```
    - [ ] **Instalar Librerías Necesarias:** Con el entorno virtual activado, instalar los paquetes base.
        ```bash
        pip install scapy customtkinter
        ```
    - [ ] **Crear Estructura de Archivos Inicial:**
        ```
        /PythonNetworkScanner/
        |-- venv/
        |-- scanner_backend.py
        |-- gui_scanner.py
        |-- PLAN.md
        ```

---

## Fase 1: Desarrollo del Núcleo de Escaneo (Backend)

*   **Objetivo:** Construir la lógica que descubre los dispositivos en la red (`scanner_backend.py`).
*   **Tareas:**
    - [ ] **Implementar el Escaneo ARP:** Crear la función `scan_network(ip_range)` usando `scapy` para obtener IPs y MACs.
    - [ ] **Añadir Resolución de Nombres (Hostname):** Mejorar la función para que intente resolver el nombre de host de cada IP con `socket`.
    - [ ] **Detección Automática del Rango de Red:** Crear una función auxiliar que detecte la IP y máscara de subred locales para proponer un rango de escaneo por defecto.
    - [ ] **Pruebas en Terminal:** Ejecutar `scanner_backend.py` directamente para verificar que el escaneo funciona y muestra los resultados en la consola.

---

## Fase 2: Construcción de la Interfaz Gráfica Básica (Frontend)

*   **Objetivo:** Crear una ventana funcional que inicie el escaneo y muestre los resultados (`gui_scanner.py`).
*   **Tareas:**
    - [ ] **Diseño de la Ventana Principal:** Usar `CustomTkinter` para crear la ventana, el campo de entrada de IP y el botón "Escanear".
    - [ ] **Crear la Tabla de Resultados:** Implementar un `ttk.Treeview` para mostrar los datos (IP, MAC, Hostname) en columnas.
    - [ ] **Integración Inicial (con congelamiento):** Conectar el botón "Escanear" para que llame a la función `scan_network` y popule la tabla.
    - [ ] **Implementar `threading` para Evitar Congelamiento:** Modificar la lógica para que el escaneo se ejecute en un hilo separado, manteniendo la GUI responsiva.
    - [ ] **Añadir Retroalimentación al Usuario:** Implementar una barra de estado para mostrar mensajes (`Escaneando...`, `Completado`, etc.) y deshabilitar el botón durante el escaneo.

---

## Fase 3: Funcionalidades Avanzadas y Refinamiento

*   **Objetivo:** Añadir características que hagan la herramienta más potente y útil.
*   **Tareas:**
    - [ ] **Implementar Menú Contextual (Clic Derecho):**
        - [ ] **Acción 1: Ping:** Añadir opción para ejecutar `ping` a la IP seleccionada.
        - [ ] **Acción 2: Iniciar Escritorio Remoto (RDP):** Añadir opción para ejecutar `mstsc /v:{ip}`.
        - [ ] **Acción 3: Abrir en Navegador (HTTP):** Añadir opción para abrir la IP en un navegador web.
    - [ ] **Implementar Escaneo de Puertos Básico:**
        - [ ] Crear una función en el backend para escanear puertos comunes en un host.
        - [ ] Integrar en la GUI (ej. al hacer doble clic en un dispositivo).
    - [ ] **Implementar Exportación de Resultados:**
        - [ ] Añadir un botón "Exportar" para guardar la tabla de resultados en un archivo CSV.
    - [x] **Mejoras de la Interfaz:**
        - [x] Añadir caja de búsqueda para filtrar resultados en tiempo real.
        - [x] Permitir ordenar los resultados haciendo clic en las columnas.

---

## Fase 4: Empaquetado y Distribución

*   **Objetivo:** Convertir el script en un archivo `.exe` independiente para Windows.
*   **Tareas:**
    - [x] **Instalar PyInstaller:**
        ```bash
        pip install pyinstaller
        ```
    - [ ] **Crear el Ejecutable:** Ejecutar PyInstaller con las opciones adecuadas para crear un único archivo sin consola.
        ```bash
        # Ejecutar desde la terminal en la carpeta del proyecto
        pyinstaller --onefile --windowed --name "PyNetScanner" gui_scanner.py
        ```
    - [ ] **Pruebas Finales:** Probar el archivo `.exe` generado en la carpeta `dist` en diferentes máquinas para asegurar su funcionamiento.
