import customtkinter as ctk
from tkinter import ttk
import threading
import os
from datetime import datetime
import webbrowser
import tkinter as tk
import json
import csv
import ipaddress
from tkinter import filedialog, simpledialog
from topology_manager import TopologyManager

# Importamos las funciones que creamos en nuestro backend
from scanner_backend import escanear_red, obtener_rango_red_por_defecto, escanear_puertos, configurar_base_de_datos_mac, get_data_directory
import topology_builder # Importamos el módulo de topología
# Importación condicional para evitar errores si falla matplotlib
try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except ImportError:
    FigureCanvasTkAgg = None
from languages import LANGUAGES 

class LanguageManager:
    def __init__(self, initial_language="Español"):
        self.languages = LANGUAGES
        self.language = initial_language

    def obtener(self, key):
        return self.languages.get(self.language, {}).get(key, key)

    def establecer_idioma(self, language):
        if language in self.languages:
            self.language = language

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configuración de la ventana principal ---
        self.lang = LanguageManager()  # Gestor de idiomas
        self.title(self.lang.obtener("window_title"))
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.language_var = ctk.StringVar(value="Español")
        self._crear_menus()

        # --- Layout de la ventana (Grid) ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Frame superior para los controles ---
        self.top_frame = ctk.CTkFrame(self, height=50)
        self.top_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.top_frame.grid_columnconfigure(1, weight=1) # La columna de entrada de IP se expande

        self.label_ip = ctk.CTkLabel(self.top_frame, text=self.lang.obtener("ip_range_label"))
        self.label_ip.grid(row=0, column=0, padx=10, pady=10)

        self.entry_ip = ctk.CTkEntry(self.top_frame, placeholder_text=self.lang.obtener("ip_range_placeholder"))
        self.entry_ip.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        self.scan_button = ctk.CTkButton(self.top_frame, text=self.lang.obtener("scan_button"), command=self.iniciar_hilo_escaneo)
        self.scan_button.grid(row=0, column=2, padx=(10, 5), pady=10)

        self.cancel_button = ctk.CTkButton(self.top_frame, text=self.lang.obtener("cancel_button"), command=self.cancelar_escaneo, state="disabled")
        self.cancel_button.grid(row=0, column=3, padx=(0, 10), pady=10)

        self.map_button = ctk.CTkButton(self.top_frame, text=self.lang.obtener("map_button"), command=self.ver_mapa_red, fg_color="#E59400", hover_color="#B37400")
        self.map_button.grid(row=0, column=4, padx=(0, 10), pady=10)

        self.top_frame.grid_columnconfigure(5, weight=1) # Columna de búsqueda se expande
        # --- Caja de búsqueda (en la misma fila) ---
        self.search_label = ctk.CTkLabel(self.top_frame, text=self.lang.obtener("search_label"))
        self.search_label.grid(row=0, column=6, padx=(20, 10), pady=10)

        self.search_entry = ctk.CTkEntry(self.top_frame, placeholder_text=self.lang.obtener("search_placeholder"))
        self.search_entry.grid(row=0, column=7, padx=10, pady=10, sticky="ew")
        self.search_entry.bind("<KeyRelease>", self.filtrar_resultados)

        # --- Frame para la tabla (ya no dentro de una pestaña) ---
        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.table_frame.grid_columnconfigure(0, weight=1)
        self.table_frame.grid_rowconfigure(0, weight=1)

        # --- Estilo y creación de la Tabla (TreeView) ---
        columns = ("Estado", "IP", "Latencia", "Hostname", "MAC", "Fabricante", "Visto por última vez")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        self.configurar_estilo_tabla()

        # Configurar encabezados y comando de ordenamiento
        for col in columns:
            self.tree.heading(col, text=self.lang.obtener(f"col_{col.lower().replace(' ', '_')}"), command=lambda _col=col: self.ordenar_columna(_col, False))
            self.tree.column(col, width=80 if col in ("Estado", "Latencia") else 180, anchor="center" if col in ("Estado", "IP", "MAC", "Latencia") else "w")

        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(self.table_frame, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # --- Menú contextual (clic derecho) ---
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label=self.lang.obtener("ctx_ping"), command=self.hacer_ping_dispositivo)
        self.context_menu.add_command(label=self.lang.obtener("ctx_rdp"), command=self.conectar_rdp_dispositivo)
        self.context_menu.add_command(label=self.lang.obtener("ctx_http"), command=self.abrir_http_dispositivo)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🔌 Marcar como Switch", command=lambda: self.marcar_dispositivo_manual("switch"))
        self.context_menu.add_command(label="🌐 Marcar como Router", command=lambda: self.marcar_dispositivo_manual("router"))
        self.context_menu.add_command(label="🔗 Conectar a...", command=self.conectar_dispositivo_manual)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="❌ Quitar conexión manual", command=self.quitar_conexion_manual)
        self.context_menu.add_command(label="🔄 Restablecer tipo", command=self.restablecer_tipo_manual)

        self.tree.bind("<Button-3>", self.mostrar_menu_contextual)
        self.tree.bind("<Double-1>", self.manejar_doble_clic)


        # --- Frame inferior para la barra de progreso y estado ---
        self.bottom_frame = ctk.CTkFrame(self, height=40)
        self.bottom_frame.grid(row=2, column=0, padx=10, pady=(5, 10), sticky="ew")
        self.bottom_frame.grid_columnconfigure(0, weight=1) # Status label
        self.bottom_frame.grid_columnconfigure(1, weight=1) # Progress bar

        self.status_label = ctk.CTkLabel(self.bottom_frame, text=self.lang.obtener("status_ready"))
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.progress_bar = ctk.CTkProgressBar(self.bottom_frame, orientation="horizontal", mode="determinate", height=20, progress_color="#2CC985")
        self.progress_bar.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.progress_bar.set(0) # Iniciar en 0

        self.export_button = ctk.CTkButton(self.bottom_frame, text=self.lang.obtener("export_button"), command=self.exportar_a_csv)
        self.export_button.grid(row=0, column=2, padx=10, pady=10)

        # --- Variables para la lógica de la app ---
        self.device_history = {} # Clave: MAC, Valor: diccionario del dispositivo
        self.history_file_path = os.path.join(get_data_directory(), "network_history.json")
        self.sort_column_name = "IP"
        self.sort_reverse = False
        self.cancel_scan_event = threading.Event()
        self.blinking_job_id = None
        self.topology_manager = TopologyManager()

        # --- Inicialización en segundo plano para un arranque rápido de la GUI ---
        self.iniciar_hilo_inicializacion()

        # Maximizar la ventana después de que todos los widgets se hayan inicializado
        self.after(10, lambda: self.state('zoomed'))

    def iniciar_hilo_inicializacion(self):
        """
        Inicia un hilo para realizar las tareas de inicialización pesadas
        (carga de DB MAC, detección de red) sin bloquear la GUI.
        """
        self.scan_button.configure(state="disabled")
        self.actualizar_estado(self.lang.obtener("status_initializing"))
        

        init_thread = threading.Thread(target=self.inicializar_app_en_segundo_plano, daemon=True)
        init_thread.start()

    def inicializar_app_en_segundo_plano(self):
        """Tareas que se ejecutan en un hilo separado al inicio."""
        # 1. Cargar la base de datos de fabricantes MAC
        self.mac_lookup_instance, status_msg = configurar_base_de_datos_mac()
        self.after(0, self.actualizar_estado, status_msg.strip())

        # 2. Obtener y mostrar el rango de IP por defecto
        default_range = obtener_rango_red_por_defecto()
        if default_range:
            self.after(0, lambda: self.entry_ip.insert(0, default_range))

        # 3. Reactivar la UI
        self.after(0, self.restablecer_ui)
        
    def _cargar_historial_desde_archivo(self):
        """Carga el historial de dispositivos y activa la notificación parpadeante si hay datos."""
        try:
            if os.path.exists(self.history_file_path):
                with open(self.history_file_path, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
                    # Asegurarnos de que el historial no esté vacío
                    if history_data:
                        self.device_history = history_data
                        # Ya no actualizamos el estado aquí para evitar sobreescribir "Escaneando..."
        except (json.JSONDecodeError, IOError) as e:
            self.actualizar_estado(self.lang.obtener("status_history_error").format(e))
            self.device_history = {}

    def guardar_historial(self):
        """Guarda el historial de dispositivos en el archivo JSON."""
        try:
            with open(self.history_file_path, 'w', encoding='utf-8') as f:
                json.dump(self.device_history, f, indent=4)
        except IOError as e:
            self.actualizar_estado(self.lang.obtener("status_history_save_error").format(e))

    def _crear_menus(self):
        """Crea (o recrea) toda la barra de menú."""
        # Si ya existe un menú, lo destruimos primero.
        if hasattr(self, 'menubar') and self.menubar:
            self.menubar.destroy()

        self.menubar = tk.Menu(self)
        self.config(menu=self.menubar)

        # Menú Archivo
        file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label=self.lang.obtener("file_menu"), menu=file_menu)
        file_menu.add_command(label=self.lang.obtener("file_menu_exit"), command=self.quit)

        # Menú Configuración
        config_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label=self.lang.obtener("config_menu"), menu=config_menu)
        language_menu = tk.Menu(config_menu, tearoff=0)
        config_menu.add_cascade(label=self.lang.obtener("config_menu_lang"), menu=language_menu)
        for lang_name in self.lang.languages.keys():
            language_menu.add_radiobutton(label=lang_name, variable=self.language_var, value=lang_name, command=self.actualizar_idioma)

        # Menú Ayuda
        help_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label=self.lang.obtener("help_menu"), menu=help_menu)
        help_menu.add_command(label=self.lang.obtener("help_menu_about"), command=self.mostrar_dialogo_acerca_de)

    def configurar_estilo_tabla(self):
        style = ttk.Style()
        style.theme_use("clam") # Usar un tema que permita más personalización

        # 2. Configurar colores para un tema claro en la tabla
        style.configure("Treeview",
                        background="#ffffff",
                        foreground="#1c1c1c",
                        rowheight=25,
                        fieldbackground="#ffffff")
        # Color de selección (fondo azul, texto blanco).
        # El estado 'focus' es importante para que se aplique correctamente en Windows.
        style.map('Treeview', background=[('selected', '#3470b6')], foreground=[('selected', 'white')])

        # 3. Configurar el resaltado al pasar el ratón (hover)
        style.map('Treeview.Heading', background=[('active', '#cce5ff')]) # type: ignore
        
        # Configurar tag para el estado "Offline"
        self.tree.tag_configure("OfflineStatus", foreground="#E53B3B", font=('TkDefaultFont', 9, 'bold')) # Rojo y negrita
        
    def iniciar_hilo_escaneo(self):
        self.scan_button.configure(state="disabled", text=self.lang.obtener("scan_button_scanning"))
        self.cancel_button.configure(state="normal")
        
        self.status_label.configure(text=self.lang.obtener("status_scanning"))
        self.progress_bar.set(0)
        
        # 2. Cargar el historial desde el archivo
        self._cargar_historial_desde_archivo()

        # 3. Marcar todos los dispositivos del historial como offline antes de empezar el nuevo escaneo
        for mac in self.device_history:
            self.device_history[mac]["status"] = "Offline"
        
        self.cancel_scan_event.clear() # Reiniciamos el evento de cancelación
        
        scan_thread = threading.Thread(target=self.realizar_escaneo, args=(self.cancel_scan_event, self.mac_lookup_instance))
        scan_thread.daemon = True
        scan_thread.start()

    def realizar_escaneo(self, cancel_event, mac_lookup_instance):
        ip_range = self.entry_ip.get()
        if not ip_range:
            self.after(0, self.actualizar_estado, self.lang.obtener("status_error_no_range"))
            self.after(0, self.restablecer_ui)
            return

        # Limpiamos la tabla visualmente antes de escanear
        self.after(0, self.limpiar_tabla)

        try:
            # Pasamos la función de actualización de progreso a nuestro backend
            # y el evento de cancelación.
            dispositivos_activos = escanear_red(mac_lookup_instance, ip_range,
                                                callback_progreso=self.actualizar_progreso,
                                                callback_resultado=self.agregar_dispositivo_a_tabla,
                                                callback_actualizacion=self.actualizar_dispositivo_en_tabla,
                                                evento_cancelar=cancel_event)

            online_count = sum(1 for device in self.device_history.values() if device.get("status") == "Online")
            if cancel_event.is_set():
                self.after(0, self.actualizar_estado, self.lang.obtener("status_scan_cancelled"))
            else:
                self.after(0, self.poblar_tabla_desde_historial)
                self.after(0, self.actualizar_estado, self.lang.obtener("status_scan_completed").format(online_count))
        except Exception as e:
            self.after(0, self.actualizar_estado, self.lang.obtener("status_error_scan").format(e))
        finally:
            self.after(0, self.guardar_historial)
            self.after(0, self.restablecer_ui)

    def actualizar_progreso(self, value):
        """Función de callback que se ejecuta desde el hilo de escaneo."""
        self.progress_bar.set(value)

    def agregar_dispositivo_a_tabla(self, device):
        """Añade un dispositivo a la lista y actualiza la tabla (thread-safe)."""
        self.after(0, self._agregar_dispositivo_thread_safe, device)

    def _agregar_dispositivo_thread_safe(self, device):
        """Esta función se ejecuta en el hilo principal de la GUI."""
        mac = device.get("mac")
        if not mac or mac == "N/A":
            return # No podemos rastrear dispositivos sin MAC

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        device["last_seen"] = now
        device["status"] = "Online"

        # Si es un dispositivo nuevo, lo añadimos. Si ya existe, actualizamos.
        if mac not in self.device_history:
            self.device_history[mac] = device
        else:
            # Conserva datos antiguos si los nuevos son genéricos
            if device.get("hostname") == "Resolviendo..." and self.device_history[mac].get("hostname") != "Desconocido":
                device["hostname"] = self.device_history[mac].get("hostname")
            self.device_history[mac].update(device)

        # Actualizamos la tabla en tiempo real
        self.actualizar_o_insertar_dispositivo_en_tabla(self.device_history[mac])

    def actualizar_dispositivo_en_tabla(self, device_update):
        """Actualiza un dispositivo existente en la tabla (thread-safe)."""
        self.after(0, self._actualizar_dispositivo_thread_safe, device_update)

    def _actualizar_dispositivo_thread_safe(self, device_update):
        """Actualiza la celda del dispositivo en el hilo principal de la GUI."""
        # Buscamos el dispositivo por IP, pero actualizamos el historial por MAC
        found_mac = None
        for mac, device in self.device_history.items():
            if device.get("ip") == device_update.get("ip"):
                self.device_history[mac].update(device_update)
                found_mac = mac
                break
        
        if found_mac:
            self.actualizar_o_insertar_dispositivo_en_tabla(self.device_history[found_mac])

    def filtrar_resultados(self, event=None):
        """Filtra los resultados de la tabla basándose en el campo de búsqueda."""
        # Esta función ahora solo filtra y llama a sort_column para reordenar y redibujar.
        search_term = self.search_entry.get().lower()

        if not search_term:
            filtered_results = list(self.device_history.values())
        else:
            filtered_results = []
            for device in self.device_history.values():
                # Comprobar si el término de búsqueda está en alguno de los campos
                if any(search_term in str(value).lower() for value in device.values()):
                    filtered_results.append(device)
        
        # Volver a aplicar el ordenamiento actual después de filtrar
        self.ordenar_columna(self.sort_column_name, keep_direction=True, data_to_sort=filtered_results)
        
    def poblar_tabla_desde_historial(self, initial_load=False):
        """Limpia y rellena la tabla con los datos del historial."""
        data_to_display = list(self.device_history.values())
        
        # Limpiar la tabla y repoblarla con los datos actualizados, manteniendo el orden actual
        self.ordenar_columna(self.sort_column_name, keep_direction=True, data_to_sort=data_to_display)

    def actualizar_o_insertar_dispositivo_en_tabla(self, device):
        """Inserta una nueva fila o actualiza una existente en la tabla."""
        mac = device.get("mac")
        if not mac: return

        # Definimos el texto de estado y la etiqueta de estilo
        status_text = ""
        tags = ()
        if device.get("status") == "Online":
            status_text = "Online"
        elif device.get("status") == "Offline":
            status_text = "Offline"
            tags = ("OfflineStatus",)

        latency = device.get('latency', -1.0)
        latency_text = f"{latency:.2f} ms" if latency >= 0 else "N/A"


        values = (status_text, device.get("ip", ""), latency_text, device.get("hostname", ""), mac, device.get("manufacturer", ""), device.get("last_seen", ""))

        if self.tree.exists(mac):
            self.tree.item(mac, values=values, tags=tags)
        else:
            self.tree.insert("", "end", iid=mac, values=values, tags=tags)

    def ordenar_columna(self, col, keep_direction=False, data_to_sort=None):
        """Ordena los datos y actualiza la tabla."""
        # Si no se pasan datos, usa los resultados filtrados actuales.
        if data_to_sort is None:
            search_term = self.search_entry.get().lower()
            if not search_term:
                data_to_sort = list(self.device_history.values())
            else:
                data_to_sort = [d for d in self.device_history.values() if any(search_term in str(v).lower() for v in d.values())]

        # Determinar la dirección del ordenamiento
        if not keep_direction:
            if self.sort_column_name == col:
                self.sort_reverse = not self.sort_reverse
            else:
                self.sort_reverse = False
            self.sort_column_name = col
        
        # Mapeo de nombres de columna de la GUI a claves del diccionario
        column_keys = {"Estado": "status", "IP": "ip", "Latencia": "latency", "Hostname": "hostname", "MAC": "mac", "Fabricante": "manufacturer", "Visto por última vez": "last_seen"}
        sort_key = column_keys.get(col, "ip")

        # Lógica de ordenamiento
        if sort_key == "ip":
            key_func = lambda d: ipaddress.ip_address(d.get(sort_key, '0.0.0.0'))
        elif sort_key == "latency":
            key_func = lambda d: d.get(sort_key, -1.0)
        else:
            key_func = lambda d: str(d.get(sort_key, '')).lower()
        data_to_sort.sort(key=key_func, reverse=self.sort_reverse)

        # Limpiar y repoblar la tabla con los datos ordenados
        self.limpiar_tabla()
        for device in data_to_sort:
            self.actualizar_o_insertar_dispositivo_en_tabla(device)

    def limpiar_tabla(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
    def actualizar_estado(self, message):
        self.status_label.configure(text=message)

    def manejar_doble_clic(self, event):
        """Maneja el evento de doble clic en la tabla."""
    def obtener_ip_seleccionada(self):
        """Obtiene la dirección IP de la fila seleccionada en la tabla."""
        selected_item = self.tree.selection()
        if selected_item:
            # values[1] es la columna de la IP. values[0] es el Estado.
            return self.tree.item(selected_item[0])['values'][1]
        return None

    def hacer_ping_dispositivo(self):
        ip = self.obtener_ip_seleccionada()
        if ip:
            # 'start cmd /k' abre una nueva terminal en Windows y ejecuta el comando, manteniéndola abierta.
            os.system(f'start cmd /k ping {ip} -t')

    def conectar_rdp_dispositivo(self):
        ip = self.obtener_ip_seleccionada()
        if ip:
            os.system(f'mstsc /v:{ip}')

    def abrir_http_dispositivo(self):
        ip = self.obtener_ip_seleccionada()
        if ip:
            webbrowser.open(f'http://{ip}')

    def cancelar_escaneo(self):
        """Activa el evento de cancelación para detener el hilo de escaneo."""
        self.status_label.configure(text=self.lang.obtener("status_cancelling"))
        self.cancel_scan_event.set()
        self.cancel_button.configure(state="disabled")

    def exportar_a_csv(self):
        """Exporta los resultados actuales de la tabla a un archivo CSV."""
        # Primero, verificar si hay algo que exportar
        if not self.tree.get_children():
            self.actualizar_estado(self.lang.obtener("export_status_no_results"))
            return

        # Abrir el diálogo para guardar archivo
        try:
            file_path = filedialog.asksaveasfilename( # type: ignore
                defaultextension=".csv",
                filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
                title=self.lang.obtener("export_dialog_title")
            )
        except Exception as e:
            self.actualizar_estado(f"Dialog error: {e}")
            return

        if not file_path:
            self.actualizar_estado(self.lang.obtener("export_status_cancelled"))
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([self.lang.obtener(f"col_{c.lower().replace(' ', '_')}") for c in self.tree["columns"]])
                for child_id in self.tree.get_children():
                    writer.writerow(self.tree.item(child_id)['values'])
            self.actualizar_estado(self.lang.obtener("export_status_success").format(os.path.basename(file_path)))
        except Exception as e:
            self.actualizar_estado(f"Export error: {e}")

    def iniciar_escaneo_puertos(self, ip):
        """Inicia el escaneo de puertos en un hilo y muestra una ventana de progreso."""
        # Crear una nueva ventana Toplevel para el progreso
        port_scan_window = ctk.CTkToplevel(self)
        port_scan_window.title(self.lang.obtener("portscan_window_title").format(ip))
        port_scan_window.geometry("400x150")
        port_scan_window.transient(self) # Mantener la ventana por encima de la principal
        port_scan_window.grab_set() # Bloquear interacción con la ventana principal

        label = ctk.CTkLabel(port_scan_window, text=self.lang.obtener("portscan_window_label").format(ip))
        label.pack(pady=20)

        progress_bar = ctk.CTkProgressBar(port_scan_window, width=350)
        progress_bar.pack(pady=10)
        progress_bar.set(0)

        def update_port_progress(value):
            progress_bar.set(value)

        def run_scan():
            # Lista de puertos comunes a escanear
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            open_ports = escanear_puertos(ip, common_ports, callback_progreso=update_port_progress)
            
            # Cuando termina, le pedimos al hilo principal que cierre la ventana de progreso
            # y muestre los resultados. Esto evita la condición de carrera.
            def finish_port_scan():
                port_scan_window.destroy()
                self.mostrar_resultados_escaneo_puertos(ip, open_ports)
            self.after(0, finish_port_scan)

        # Ejecutar el escaneo en un hilo
        threading.Thread(target=run_scan, daemon=True).start()

    def mostrar_resultados_escaneo_puertos(self, ip, open_ports):
        """Muestra los resultados del escaneo de puertos en una nueva ventana."""
        results_window = ctk.CTkToplevel(self)
        results_window.title(self.lang.obtener("portscan_results_title").format(ip))
        results_window.geometry("300x400")
        results_window.transient(self)
        results_window.grab_set()

        label = ctk.CTkLabel(results_window, text=self.lang.obtener("portscan_results_label").format(ip))
        label.pack(pady=10)

        textbox = ctk.CTkTextbox(results_window, width=280, height=320)
        textbox.pack(pady=10, padx=10, fill="both", expand=True)
        
        if open_ports:
            textbox.insert("0.0", "\n".join(map(str, open_ports)))
        else:
            textbox.insert("0.0", self.lang.obtener("portscan_results_no_ports"))
        
        textbox.configure(state="disabled") # Hacer el texto de solo lectura

    def mostrar_menu_contextual(self, event):
        """Muestra el menú contextual en la fila seleccionada."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def marcar_dispositivo_manual(self, tipo):
        """Marca el dispositivo seleccionado como Switch o Router."""
        selected_item = self.tree.selection()
        if not selected_item: return
        
        item_values = self.tree.item(selected_item[0], "values")
        ip = item_values[1] # Asumiendo que IP es la columna 1
        
        self.topology_manager.set_device_type(ip, tipo)
        tk.messagebox.showinfo("Topología", f"Dispositivo {ip} marcado como {tipo}. Actualiza el mapa para ver cambios.")

    def conectar_dispositivo_manual(self):
        """Abre un diálogo para conectar el dispositivo a otro (uplink)."""
        selected_item = self.tree.selection()
        if not selected_item: return
        
        item_values = self.tree.item(selected_item[0], "values")
        child_ip = item_values[1]
        
        # Pedir IP del padre
        parent_ip = simpledialog.askstring("Conectar a...", f"Ingresa la IP del Switch/Router al que se conecta {child_ip}:")
        
        if parent_ip:
            # Validar IP básica
            try:
                ipaddress.ip_address(parent_ip)
                self.topology_manager.set_uplink(child_ip, parent_ip)
                tk.messagebox.showinfo("Topología", f"Conexión guardada: {child_ip} -> {parent_ip}.\nActualiza el mapa para ver cambios.")
            except ValueError:
                tk.messagebox.showerror("Error", "IP inválida.")

    def quitar_conexion_manual(self):
        """Elimina la conexión manual (uplink) del dispositivo seleccionado."""
        selected_item = self.tree.selection()
        if not selected_item: return
        
        item_values = self.tree.item(selected_item[0], "values")
        ip = item_values[1]
        
        self.topology_manager.remove_uplink(ip)
        tk.messagebox.showinfo("Topología", f"Conexión manual eliminada para {ip}.")

    def restablecer_tipo_manual(self):
        """Restablece el tipo de dispositivo a su valor por defecto."""
        selected_item = self.tree.selection()
        if not selected_item: return
        
        item_values = self.tree.item(selected_item[0], "values")
        ip = item_values[1]
        
        self.topology_manager.reset_device_type(ip)
        tk.messagebox.showinfo("Topología", f"Tipo de dispositivo restablecido para {ip}.")

    def ver_mapa_red(self):
        """Inicia la generación y visualización del mapa de red."""
        # Verificar dependencias primero
        if not topology_builder.DEPENDENCIES_INSTALLED:
            self.actualizar_estado("Error: Faltan librerías (networkx, matplotlib, pysnmp).")
            return

        # Verificar si hay datos
        if not self.device_history:
            self.actualizar_estado("Error: No hay dispositivos para mapear. Escanea primero.")
            return

        self.map_button.configure(state="disabled", text="Generando...")
        self.actualizar_estado("Analizando topología de red... esto puede tardar unos segundos.")
        
        # Ejecutar en hilo para no congelar GUI
        threading.Thread(target=self._generar_topologia_thread, daemon=True).start()

    def _generar_topologia_thread(self):
        """Lógica de fondo para construir el grafo."""
        try:
            devices = list(self.device_history.values())
            G = topology_builder.build_topology(devices)
            self.after(0, self._mostrar_topologia_main_thread, G)
        except Exception as e:
            self.after(0, self.actualizar_estado, f"Error al generar topología: {e}")
            self.after(0, self._restaurar_boton_mapa)

    def _mostrar_topologia_main_thread(self, G):
        """Genera y abre el mapa interactivo en el navegador."""
        self._restaurar_boton_mapa()
        if not G:
            self.actualizar_estado("No se pudo generar el grafo.")
            return

        self.actualizar_estado("Generando mapa interactivo...")
        
        try:
            # Generar HTML
            output_path = topology_builder.generate_interactive_topology(G)
            
            if output_path and os.path.exists(output_path):
                self.actualizar_estado(f"Mapa generado. Abriendo en navegador...")
                # Abrir en navegador
                webbrowser.open('file://' + output_path)
                self.actualizar_estado(self.lang.obtener("status_ready"))
            else:
                self.actualizar_estado("Error al guardar el archivo del mapa.")

        except Exception as e:
            self.actualizar_estado(f"Error visualizando mapa: {e}")

    def _restaurar_boton_mapa(self):
        self.map_button.configure(state="normal", text=self.lang.obtener("map_button"))

    def restablecer_ui(self):
        """Restaura la UI a su estado inicial después de un escaneo."""
        self.scan_button.configure(state="normal", text=self.lang.obtener("scan_button"))
        self.cancel_button.configure(state="disabled")

    def mostrar_dialogo_acerca_de(self):
        """Muestra la ventana 'Acerca de' con información del programa."""
        about_window = ctk.CTkToplevel(self)
        about_window.title(self.lang.obtener("about_title"))
        about_window.geometry("550x400")
        about_window.transient(self) # Mantener por encima de la ventana principal
        about_window.grab_set()      # Bloquear interacción con la ventana principal
        about_window.resizable(False, False)

        about_window.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(about_window, text="Redescubre", font=ctk.CTkFont(size=28, weight="bold")) # El nombre no se traduce
        title_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        version_label = ctk.CTkLabel(about_window, text=self.lang.obtener("about_version"), font=ctk.CTkFont(size=12))
        version_label.grid(row=1, column=0, padx=20, pady=0, sticky="n")

        description_label = ctk.CTkLabel(about_window, text=self.lang.obtener("about_description"), justify="center")
        description_label.grid(row=2, column=0, padx=20, pady=20)

        author_label = ctk.CTkLabel(about_window, text=self.lang.obtener("about_author"), font=ctk.CTkFont(size=12, weight="bold"))
        author_label.grid(row=3, column=0, padx=20, pady=10)

        license_label = ctk.CTkLabel(about_window, text=self.lang.obtener("about_license"))
        license_label.grid(row=4, column=0, padx=20, pady=5)

        close_button = ctk.CTkButton(about_window, text=self.lang.obtener("close_button"), command=about_window.destroy)
        close_button.grid(row=5, column=0, padx=20, pady=(20, 20))

    def actualizar_idioma(self):
        """Actualiza el idioma de toda la GUI."""
        new_language = self.language_var.get()
        self.lang.establecer_idioma(new_language)

        # --- Actualizar todos los widgets de la ventana principal ---
        self.title(self.lang.obtener("window_title"))
        
        # 1. Recrear toda la barra de menú
        self._crear_menus()
        
        # 2. Actualizar el resto de la UI
        self.label_ip.configure(text=self.lang.obtener("ip_range_label"))
        self.entry_ip.configure(placeholder_text=self.lang.obtener("ip_range_placeholder"))
        self.scan_button.configure(text=self.lang.obtener("scan_button"))
        self.cancel_button.configure(text=self.lang.obtener("cancel_button"))
        self.map_button.configure(text=self.lang.obtener("map_button"))
        self.search_label.configure(text=self.lang.obtener("search_label"))
        self.search_entry.configure(placeholder_text=self.lang.obtener("search_placeholder"))
        
        self.tree.heading("Estado", text=self.lang.obtener("col_estado"))
        self.tree.heading("IP", text=self.lang.obtener("col_ip"))
        self.tree.heading("Latencia", text=self.lang.obtener("col_latencia"))
        self.tree.heading("Hostname", text=self.lang.obtener("col_hostname"))
        self.tree.heading("MAC", text=self.lang.obtener("col_mac"))
        self.tree.heading("Fabricante", text=self.lang.obtener("col_manufacturer"))
        self.tree.heading("Visto por última vez", text=self.lang.obtener("col_visto_por_última_vez"))

        # 3. Actualizar el menú contextual (clic derecho)
        self.context_menu.entryconfig(0, label=self.lang.obtener("ctx_ping"))
        self.context_menu.entryconfig(1, label=self.lang.obtener("ctx_rdp"))
        self.context_menu.entryconfig(2, label=self.lang.obtener("ctx_http"))

        self.status_label.configure(text=self.lang.obtener("status_ready"))
        self.export_button.configure(text=self.lang.obtener("export_button"))

if __name__ == "__main__":
    app = App()
    app.mainloop()
