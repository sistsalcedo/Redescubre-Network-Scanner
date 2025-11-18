"""
Módulo principal de la interfaz gráfica (GUI) para el escáner de red.
Utiliza CustomTkinter para crear una aplicación de escritorio moderna y responsiva
que interactúa con el backend de escaneo (scanner_backend.py).
"""
import customtkinter as ctk
from tkinter import ttk
import threading

# Librerías para las acciones del menú contextual
import ipaddress
import json
import csv
from tkinter import filedialog
import os
from datetime import datetime
import webbrowser
import tkinter as tk

# Importamos las funciones que creamos en nuestro backend
from scanner_backend import escanear_red, obtener_rango_red_por_defecto, escanear_puertos, configurar_base_de_datos_mac, get_data_directory
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
        columns = ("Estado", "IP", "Hostname", "MAC", "Fabricante", "Visto por última vez")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        self.configurar_estilo_tabla()

        # Configurar encabezados y comando de ordenamiento
        for col in columns:
            self.tree.heading(col, text=self.lang.obtener(f"col_{col.lower().replace(' ', '_')}"), command=lambda _col=col: self.ordenar_columna(_col, False))
            self.tree.column(col, width=80 if col == "Estado" else 180, anchor="center" if col in ("Estado", "IP", "MAC") else "w")

        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(self.table_frame, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # --- Menú contextual (clic derecho) ---
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label=self.lang.obtener("ctx_ping"), command=self.hacer_ping_dispositivo)
        self.context_menu.add_command(label=self.lang.obtener("ctx_rdp"), command=self.conectar_rdp_dispositivo)
        self.context_menu.add_command(label=self.lang.obtener("ctx_http"), command=self.abrir_http_dispositivo)

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

        values = (status_text, device.get("ip", ""), device.get("hostname", ""), mac, device.get("manufacturer", ""), device.get("last_seen", ""))

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
        column_keys = {"Estado": "status", "IP": "ip", "Hostname": "hostname", "MAC": "mac", "Fabricante": "manufacturer", "Visto por última vez": "last_seen"}
        sort_key = column_keys.get(col, "ip")

        # Lógica de ordenamiento
        key_func = lambda d: ipaddress.ip_address(d[sort_key]) if sort_key == "ip" else str(d.get(sort_key, '')).lower()
        data_to_sort.sort(key=key_func, reverse=self.sort_reverse)

        # Limpiar y repoblar la tabla con los datos ordenados
        self.limpiar_tabla()
        for device in data_to_sort:
            self.actualizar_o_insertar_dispositivo_en_tabla(device)

    def dibujar_topologia(self, graph):
        """Dibuja el grafo de la red en el canvas de topología."""
        canvas = self.topology_canvas
        canvas.delete("all") # Limpiar canvas anterior

        # Limpiar el mapeo de aristas
        self.edge_canvas_items.clear()

        # Forzar la actualización del canvas para obtener su tamaño real
        canvas.update_idletasks()

        if not graph or graph.number_of_nodes() == 0:
            canvas.create_text(canvas.winfo_width()/2, canvas.winfo_height()/2, text="No hay topología para mostrar", fill="white")
            return

        # Comprobar si los nodos ya tienen posiciones guardadas
        if all('pos' in data for node, data in graph.nodes(data=True)):
            print("[Topology] Cargando posiciones guardadas.")
            pos = nx.get_node_attributes(graph, 'pos')
        else:
            # Si no, calcular un nuevo layout
            print("[Topology] Calculando nuevo layout.")
            try:
                pos = nx.spring_layout(graph, seed=42, iterations=100, k=0.3)
            except Exception as e:
                print(f"Error en el layout del grafo: {e}")
                pos = nx.random_layout(graph, seed=42) # Plan B
            # Guardar las posiciones calculadas en el grafo para uso futuro
            for node_id, coords in pos.items():
                graph.nodes[node_id]['pos'] = coords

        # Escalar posiciones para que encajen en el canvas
        width, height = canvas.winfo_width(), canvas.winfo_height()
        padding = 50
        
        # Normalizar posiciones de -1 a 1
        min_x = min(p[0] for p in pos.values())
        max_x = max(p[0] for p in pos.values())
        min_y = min(p[1] for p in pos.values())
        max_y = max(p[1] for p in pos.values())

        # Evitar división por cero si todos los nodos están en la misma posición
        range_x = max_x - min_x if max_x > min_x else 1
        range_y = max_y - min_y if max_y > min_y else 1

        scaled_pos = {
            node: (
                padding + (p[0] - min_x) / range_x * (width - 2 * padding),
                padding + (p[1] - min_y) / range_y * (height - 2 * padding)
            ) for node, p in pos.items()
        }

        # Dibujar aristas (conexiones)
        for edge in graph.edges(data=True):
            u, v, data = edge
            start_pos = scaled_pos[edge[0]]
            end_pos = scaled_pos[edge[1]]
            line_item = None
            
            edge_type = data.get('type', 'inferred')
            if edge_type == 'snmp_confirmed':
                line_item = canvas.create_line(start_pos, end_pos, fill="#2CC985", width=2) # Verde sólido
            elif edge_type == 'inferred_latency':
                line_item = canvas.create_line(start_pos, end_pos, fill="#FFFFFF", width=1.5) # Blanco para cableado inferido
            elif edge_type == 'inferred_wifi_or_remote':
                line_item = canvas.create_line(start_pos, end_pos, fill="#AAAAAA", width=1, dash=(4, 4)) # Gris punteado
            else: # Fallback para cualquier otro tipo de conexión
                line_item = canvas.create_line(start_pos, end_pos, fill="#555555", width=1.5)
            
            if line_item:
                self.edge_canvas_items[tuple(sorted((u, v)))] = line_item

        # Dibujar nodos (dispositivos)
        for node, (x, y) in scaled_pos.items():
            node_data = graph.nodes[node]
            node_type = node_data.get('type')
            
            # Crear una etiqueta única para cada nodo para poder identificarlo
            node_tag = f"node_{node}"
            node_shape_tag = f"node_shape_{node}" # Etiqueta específica para la forma del nodo
            
            if node_type == 'switch_snmp' or node_type == 'virtual_switch':
                # Dibujar switches (reales o virtuales) como un cuadrado
                item = canvas.create_rectangle(x-12, y-12, x+12, y+12, fill="#E53B3B", outline="white", width=2, tags=(node_tag, "node", node_shape_tag))
                text_item = canvas.create_text(x, y+20, text=node_data.get('hostname', node), fill="white", font=('TkDefaultFont', 9, 'bold'), tags=(node_tag, "text")) # type: ignore
            elif node_data.get('hostname') == "Gateway/Router":
                # Dibujar el router de forma diferente
                item = canvas.create_rectangle(x-18, y-12, x+18, y+12, fill="#2CC985", outline="white", width=2, tags=(node_tag, "node", node_shape_tag))
                text_item = canvas.create_text(x, y+25, text=node_data.get('hostname', node), fill="white", font=('TkDefaultFont', 9), tags=(node_tag, "text"))
            else:
                # Dibujar nodos de dispositivos normales
                item = canvas.create_oval(x-15, y-15, x+15, y+15, fill="#3470b6", outline="white", width=2, tags=(node_tag, "node", node_shape_tag))
                text_item = canvas.create_text(x, y+25, text=node_data.get('hostname', node), fill="white", font=('TkDefaultFont', 9), tags=(node_tag, "text")) # type: ignore

            # Vincular eventos de hover para el tooltip
            canvas.tag_bind(item, "<Enter>", lambda event, n=node: self.show_tooltip(event, n))
            canvas.tag_bind(item, "<Leave>", self.hide_tooltip)

    def show_tooltip(self, event, node_ip):
        if self.tooltip:
            self.tooltip.destroy()

        node_data = self.topology_graph.nodes[node_ip]
        tooltip_text = (
            f"IP: {node_data.get('ip', 'N/A')}\n"
            f"MAC: {node_data.get('mac', 'N/A')}\n"
            f"Hostname: {node_data.get('hostname', 'N/A')}\n"
            f"Latencia: {node_data.get('latency', -1.0):.2f} ms"
        )

        self.tooltip = ctk.CTkToplevel(self)
        self.tooltip.wm_overrideredirect(True) # Sin bordes de ventana
        self.tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
        
        label = ctk.CTkLabel(self.tooltip, text=tooltip_text, justify="left", corner_radius=5, fg_color="#424242", text_color="white")
        label.pack(ipadx=5, ipady=5)

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def on_node_press(self, event):
        """Se llama al presionar el botón del ratón en el canvas."""
        item = self.topology_canvas.find_closest(event.x, event.y)[0]
        if "node" in self.topology_canvas.gettags(item):
            self._drag_data["item"] = item
            self._drag_data["x"] = event.x
            self._drag_data["y"] = event.y

    def on_node_drag(self, event):
        """Se llama cuando se arrastra el ratón con el botón presionado."""
        if self._drag_data.get("item"):
            delta_x = event.x - self._drag_data["x"]
            delta_y = event.y - self._drag_data["y"]

            # Mover todos los elementos del nodo (forma y texto)
            node_tag = self.topology_canvas.gettags(self._drag_data["item"])[0]
            for item_id in self.topology_canvas.find_withtag(node_tag):
                self.topology_canvas.move(item_id, delta_x, delta_y)

            # Actualizar la posición para el siguiente evento de arrastre
            self._drag_data["x"] = event.x
            self._drag_data["y"] = event.y

            # Actualizar las líneas de conexión
            node_id = node_tag.replace("node_", "")
            if self.topology_graph and self.topology_graph.has_node(node_id):
                # Obtener las coordenadas actuales del centro de la forma del nodo
                shape_items = self.topology_canvas.find_withtag(f"node_shape_{node_id}")
                if not shape_items: return
                coords = self.topology_canvas.coords(shape_items[0])
                if not coords: return # Añadir esta verificación para evitar errores si las coords no existen

                new_center_x = (coords[0] + coords[2]) / 2
                new_center_y = (coords[1] + coords[3]) / 2

                for neighbor in self.topology_graph.neighbors(node_id):
                    edge_key = tuple(sorted((node_id, neighbor)))
                    if edge_key in self.edge_canvas_items:
                        line_item = self.edge_canvas_items[edge_key]
                        self.actualizar_coordenadas_linea(line_item, neighbor, new_center_x, new_center_y)

    def on_node_release(self, event):
        """Se llama al soltar el botón del ratón."""
        if self._drag_data.get("item") and "node" in self.topology_canvas.gettags(self._drag_data["item"]):
            node_tag = self.topology_canvas.gettags(self._drag_data["item"])[0]
            node_id = node_tag.replace("node_", "")

            if self.topology_graph and self.topology_graph.has_node(node_id):
                # Obtener las coordenadas finales de la forma para guardarlas
                dragged_shape_items = self.topology_canvas.find_withtag(f"node_shape_{node_id}")
                if not dragged_shape_items: return
                coords = self.topology_canvas.coords(dragged_shape_items[0])
                if not coords: return
                x_center = (coords[0] + coords[2]) / 2
                y_center = (coords[1] + coords[3]) / 2
                
                # Des-escalar la posición para guardarla en el grafo (rango 0-1)
                width, height = self.topology_canvas.winfo_width(), self.topology_canvas.winfo_height()
                padding = 50
                
                # Evitar división por cero
                range_x = width - 2 * padding if width > 2 * padding else 1
                range_y = height - 2 * padding if height > 2 * padding else 1

                # Guardar la posición normalizada (no la del canvas)
                self.topology_graph.nodes[node_id]['pos'] = (
                    (x_center - padding) / range_x,
                    (y_center - padding) / range_y
                )
                print(f"Posición actualizada para {node_id}")

        self._drag_data["item"] = None
        self._drag_data["x"] = 0
        self._drag_data["y"] = 0

    def actualizar_coordenadas_linea(self, line_item, other_node_id, new_x, new_y):
        """Actualiza una línea conectando la nueva posición (new_x, new_y) con el centro del 'other_node_id'."""
        # Obtener el item del canvas para el nodo que no se movió
        other_node_shape_tag = f"node_shape_{other_node_id}" # Usar la etiqueta específica de la forma
        other_node_items = self.topology_canvas.find_withtag(other_node_shape_tag)
        
        if not other_node_items: return
        
        # Obtener las coordenadas del centro del nodo que no se movió
        other_item_coords = self.topology_canvas.coords(other_node_items[0])
        other_x = (other_item_coords[0] + other_item_coords[2]) / 2
        other_y = (other_item_coords[1] + other_item_coords[3]) / 2
        
        # Actualizar las coordenadas de la línea para que vaya de un punto al otro
        self.topology_canvas.coords(line_item, new_x, new_y, other_x, other_y)

    def guardar_posiciones_topologia(self):
        if not self.topology_graph:
            self.actualizar_estado("No hay topología para guardar.")
            return
        
        node_positions = {node: data['pos'] for node, data in self.topology_graph.nodes(data=True) if 'pos' in data}
        
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Archivos JSON", "*.json")], title="Guardar Disposición de Topología")
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(node_positions, f, indent=4)
            self.actualizar_estado(f"Disposición guardada en {os.path.basename(file_path)}")

    def cargar_posiciones_topologia(self):
        if not self.topology_graph:
            self.actualizar_estado("No hay topología para cargar la disposición.")
            return
        
        file_path = filedialog.askopenfilename(filetypes=[("Archivos JSON", "*.json")], title="Cargar Disposición de Topología")
        if file_path:
            with open(file_path, 'r') as f:
                node_positions = json.load(f)
            
            nx.set_node_attributes(self.topology_graph, node_positions, 'pos')
            self.dibujar_topologia(self.topology_graph)
            self.actualizar_estado(f"Disposición cargada desde {os.path.basename(file_path)}")

    def limpiar_tabla(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
    def actualizar_estado(self, message):
        self.status_label.configure(text=message)

    def manejar_doble_clic(self, event):
        """Maneja el evento de doble clic en la tabla."""
        ip = self.obtener_ip_seleccionada()
        if ip:
            self.iniciar_escaneo_puertos(ip)

    def mostrar_menu_contextual(self, event):
        """Muestra el menú contextual en la posición del cursor."""
        # Identifica la fila bajo el cursor
        item_id = self.tree.identify_row(event.y)
        if item_id:
            # Selecciona la fila sobre la que se hizo clic
            self.tree.selection_set(item_id)
            # Muestra el menú
            self.context_menu.post(event.x_root, event.y_root)

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
        self.search_label.configure(text=self.lang.obtener("search_label"))
        self.search_entry.configure(placeholder_text=self.lang.obtener("search_placeholder"))
        
        self.tree.heading("Estado", text=self.lang.obtener("col_estado"))
        self.tree.heading("IP", text=self.lang.obtener("col_ip"))
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
