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
import csv
from tkinter import filedialog
import os
import webbrowser
import tkinter as tk

# Importamos las funciones que creamos en nuestro backend
from scanner_backend import scan_network, get_default_network_range, scan_ports
from languages import LANGUAGES

class LanguageManager:
    def __init__(self, initial_language="Español"):
        self.languages = LANGUAGES
        self.language = initial_language

    def get(self, key):
        return self.languages.get(self.language, {}).get(key, key)

    def set_language(self, language):
        if language in self.languages:
            self.language = language

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configuración de la ventana principal ---
        self.lang = LanguageManager() # Gestor de idiomas
        self.title(self.lang.get("window_title"))
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.language_var = ctk.StringVar(value="Español")
        self._create_menus()

        # --- Layout de la ventana (Grid) ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1) # La tabla ahora está en la fila 1

        # --- Frame superior para los controles ---
        self.top_frame = ctk.CTkFrame(self, height=50)
        self.top_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.top_frame.grid_columnconfigure([1, 5], weight=1) # Columnas de entrada de texto se expanden

        self.label_ip = ctk.CTkLabel(self.top_frame, text=self.lang.get("ip_range_label"))
        self.label_ip.grid(row=0, column=0, padx=10, pady=10)

        self.entry_ip = ctk.CTkEntry(self.top_frame, placeholder_text=self.lang.get("ip_range_placeholder"))
        self.entry_ip.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.scan_button = ctk.CTkButton(self.top_frame, text=self.lang.get("scan_button"), command=self.start_scan_thread)
        self.scan_button.grid(row=0, column=2, padx=(10, 5), pady=10)

        self.cancel_button = ctk.CTkButton(self.top_frame, text=self.lang.get("cancel_button"), command=self.cancel_scan, state="disabled")
        self.cancel_button.grid(row=0, column=3, padx=(0, 10), pady=10)

        # --- Caja de búsqueda (en la misma fila) ---
        self.search_label = ctk.CTkLabel(self.top_frame, text=self.lang.get("search_label"))
        self.search_label.grid(row=0, column=4, padx=(20, 10), pady=10)

        self.search_entry = ctk.CTkEntry(self.top_frame, placeholder_text=self.lang.get("search_placeholder"))
        self.search_entry.grid(row=0, column=5, padx=10, pady=10, sticky="ew")
        self.search_entry.bind("<KeyRelease>", self.filter_results)

        # --- Frame central para la tabla de resultados ---
        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.table_frame.grid_columnconfigure(0, weight=1)
        self.table_frame.grid_rowconfigure(0, weight=1)

        # --- Estilo y creación de la Tabla (TreeView) ---
        self.setup_table_style()
        columns = ("IP", "Hostname", "MAC", "Fabricante")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        
        # Configurar encabezados y comando de ordenamiento
        for col in columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col, False))
            self.tree.column(col, width=200 if col == "Hostname" else 200 if col == "Fabricante" else 160 if col == "MAC" else 140, anchor="w" if col in ("Hostname", "Fabricante") else "center")

        self.tree.grid(row=0, column=0, sticky="nsew")
        
        scrollbar = ctk.CTkScrollbar(self.table_frame, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # --- Menú contextual (clic derecho) ---
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label=self.lang.get("ctx_ping"), command=self.ping_device)
        self.context_menu.add_command(label=self.lang.get("ctx_rdp"), command=self.rdp_device)
        self.context_menu.add_command(label=self.lang.get("ctx_http"), command=self.http_device)

        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.handle_double_click)

        # --- Frame inferior para la barra de progreso y estado ---
        self.bottom_frame = ctk.CTkFrame(self, height=40)
        self.bottom_frame.grid(row=2, column=0, padx=10, pady=(5, 10), sticky="ew")
        self.bottom_frame.grid_columnconfigure(0, weight=1) # Status label
        self.bottom_frame.grid_columnconfigure(1, weight=1) # Progress bar

        self.status_label = ctk.CTkLabel(self.bottom_frame, text=self.lang.get("status_ready"))
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.progress_bar = ctk.CTkProgressBar(self.bottom_frame, orientation="horizontal", mode="determinate", height=20, progress_color="#2CC985")
        self.progress_bar.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.progress_bar.set(0) # Iniciar en 0

        self.export_button = ctk.CTkButton(self.bottom_frame, text=self.lang.get("export_button"), command=self.export_to_csv)
        self.export_button.grid(row=0, column=2, padx=10, pady=10)

        # --- Variables para la lógica de la app ---
        self.all_scan_results = [] # Almacena todos los resultados sin filtrar
        self.sort_column_name = "IP"
        self.sort_reverse = False
        self.cancel_scan_event = threading.Event()

        # --- Llenar el campo de IP con la red detectada ---
        self.populate_default_ip()

        # Maximizar la ventana después de que todos los widgets se hayan inicializado
        self.after(10, lambda: self.state('zoomed'))

    def _create_menus(self):
        """Crea (o recrea) toda la barra de menú."""
        # Si ya existe un menú, lo destruimos primero.
        if hasattr(self, 'menubar') and self.menubar:
            self.menubar.destroy()

        self.menubar = tk.Menu(self)
        self.config(menu=self.menubar)

        # Menú Archivo
        file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label=self.lang.get("file_menu"), menu=file_menu)
        file_menu.add_command(label=self.lang.get("file_menu_exit"), command=self.quit)

        # Menú Configuración
        config_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label=self.lang.get("config_menu"), menu=config_menu)
        language_menu = tk.Menu(config_menu, tearoff=0)
        config_menu.add_cascade(label=self.lang.get("config_menu_lang"), menu=language_menu)
        for lang_name in self.lang.languages.keys():
            language_menu.add_radiobutton(label=lang_name, variable=self.language_var, value=lang_name, command=self.update_language)

        # Menú Ayuda
        help_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label=self.lang.get("help_menu"), menu=help_menu)
        help_menu.add_command(label=self.lang.get("help_menu_about"), command=self.show_about_dialog)

    def setup_table_style(self):
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
        style.map('Treeview', background=[('selected', '!focus', '#3470b6'), ('selected', 'focus', '#3470b6')],
                  foreground=[('selected', 'white')])

        # 3. Configurar el resaltado al pasar el ratón (hover)
        style.map('Treeview.Heading', background=[('active', '#cce5ff')])

    def populate_default_ip(self):
        default_range = get_default_network_range()
        if default_range:
            self.entry_ip.insert(0, default_range)

    def start_scan_thread(self):
        self.scan_button.configure(state="disabled", text=self.lang.get("scan_button_scanning"))
        self.cancel_button.configure(state="normal")
        self.status_label.configure(text=self.lang.get("status_scanning"))
        self.progress_bar.set(0)
        self.all_scan_results = []
        self.clear_table()
        self.cancel_scan_event.clear() # Reiniciamos el evento de cancelación
        
        scan_thread = threading.Thread(target=self.perform_scan, args=(self.cancel_scan_event,))
        scan_thread.daemon = True
        scan_thread.start()

    def perform_scan(self, cancel_event):
        ip_range = self.entry_ip.get()
        if not ip_range:
            self.after(0, self.update_status, self.lang.get("status_error_no_range"))
            self.after(0, self.reset_ui)
            return

        try:
            # Pasamos la función de actualización de progreso a nuestro backend
            # y el evento de cancelación.
            scan_network(ip_range,
                         progress_callback=self.update_progress,
                         result_callback=self.add_device_to_table,
                         update_callback=self.update_device_in_table,
                         cancel_event=cancel_event)

            # Cuando scan_network termina, actualizamos el estado según si fue cancelado o no.
            if cancel_event.is_set():
                self.after(0, self.update_status, self.lang.get("status_scan_cancelled"))
            else:
                self.after(0, self.update_status, self.lang.get("status_scan_completed").format(len(self.all_scan_results)))
        except Exception as e:
            self.after(0, self.update_status, self.lang.get("status_error_scan").format(e))
        finally:
            self.after(0, self.reset_ui)

    def update_progress(self, value):
        """Función de callback que se ejecuta desde el hilo de escaneo."""
        self.progress_bar.set(value)

    def add_device_to_table(self, device):
        """Añade un dispositivo a la lista y actualiza la tabla (thread-safe)."""
        self.after(0, self._add_device_thread_safe, device)

    def _add_device_thread_safe(self, device):
        """Esta función se ejecuta en el hilo principal de la GUI."""
        self.all_scan_results.append(device)
        # Usamos la IP como iid porque la MAC puede ser "N/A" en escaneos WAN
        self.tree.insert("", "end", iid=device["ip"], values=(device["ip"], device["hostname"], device["mac"], device["manufacturer"]))
        self.filter_results() # Re-filtra y re-ordena con el nuevo dispositivo

    def update_device_in_table(self, device_update):
        """Actualiza un dispositivo existente en la tabla (thread-safe)."""
        self.after(0, self._update_device_thread_safe, device_update)

    def _update_device_thread_safe(self, device_update):
        """Actualiza la celda del hostname en el hilo principal de la GUI."""
        # Buscar el dispositivo en la lista completa por IP
        for i, device in enumerate(self.all_scan_results):
            if device["ip"] == device_update["ip"]:
                if "hostname" in device_update:
                    self.all_scan_results[i]["hostname"] = device_update["hostname"]
                    # Actualizar la celda en la tabla usando el ID (IP)
                    self.tree.set(device["ip"], column="Hostname", value=device_update["hostname"])
                if "manufacturer" in device_update:
                    self.all_scan_results[i]["manufacturer"] = device_update["manufacturer"]
                    self.tree.set(device["ip"], column="Fabricante", value=device_update["manufacturer"])
                break
        self.filter_results() # Re-filtra y re-ordena con el nuevo dispositivo

    def filter_results(self, event=None):
        """Filtra los resultados de la tabla basándose en el campo de búsqueda."""
        search_term = self.search_entry.get().lower()
        self.clear_table()

        filtered_results = []
        if not search_term:
            filtered_results = self.all_scan_results
        else:
            for device in self.all_scan_results:
                # Comprobar si el término de búsqueda está en alguno de los campos
                if any(search_term in str(value).lower() for value in device.values()):
                    filtered_results.append(device)
        
        # Volvemos a insertar solo los resultados filtrados
        for device in filtered_results:
            self.tree.insert("", "end", iid=device["ip"], values=(device["ip"], device["hostname"], device["mac"], device["manufacturer"]))
        
        # Volver a aplicar el ordenamiento actual después de filtrar
        if self.sort_column_name:
            self.sort_column(self.sort_column_name, keep_direction=True)

    def sort_column(self, col, keep_direction=False):
        """Ordena la tabla por la columna seleccionada."""
        # Obtener los datos de la tabla como una lista de tuplas
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]

        # Determinar la dirección del ordenamiento
        if not keep_direction:
            if self.sort_column_name == col:
                self.sort_reverse = not self.sort_reverse
            else:
                self.sort_reverse = False
            self.sort_column_name = col
        
        # Lógica de ordenamiento especial para IPs
        key_func = lambda item: ipaddress.ip_address(item[0]) if col == "IP" else str(item[0]).lower()
        data.sort(key=key_func, reverse=self.sort_reverse)

        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
    def update_status(self, message):
        self.status_label.configure(text=message)

    def handle_double_click(self, event):
        """Maneja el evento de doble clic en la tabla."""
        ip = self.get_selected_ip()
        if ip:
            self.start_port_scan(ip)

    def show_context_menu(self, event):
        """Muestra el menú contextual en la posición del cursor."""
        # Identifica la fila bajo el cursor
        item_id = self.tree.identify_row(event.y)
        if item_id:
            # Selecciona la fila sobre la que se hizo clic
            self.tree.selection_set(item_id)
            # Muestra el menú
            self.context_menu.post(event.x_root, event.y_root)

    def get_selected_ip(self):
        """Obtiene la dirección IP de la fila seleccionada en la tabla."""
        selected_item = self.tree.selection()
        if selected_item:
            return self.tree.item(selected_item[0])['values'][0]
        return None

    def ping_device(self):
        ip = self.get_selected_ip()
        if ip:
            # 'start cmd /k' abre una nueva terminal en Windows y ejecuta el comando, manteniéndola abierta.
            os.system(f'start cmd /k ping {ip} -t')

    def rdp_device(self):
        ip = self.get_selected_ip()
        if ip:
            os.system(f'mstsc /v:{ip}')

    def http_device(self):
        ip = self.get_selected_ip()
        if ip:
            webbrowser.open(f'http://{ip}')

    def cancel_scan(self):
        """Activa el evento de cancelación para detener el hilo de escaneo."""
        self.status_label.configure(text=self.lang.get("status_cancelling"))
        self.cancel_scan_event.set()
        self.cancel_button.configure(state="disabled")

    def export_to_csv(self):
        """Exporta los resultados actuales de la tabla a un archivo CSV."""
        # Primero, verificar si hay algo que exportar
        if not self.tree.get_children():
            self.update_status(self.lang.get("export_status_no_results"))
            return

        # Abrir el diálogo para guardar archivo
        try:
            file_path = filedialog.asksaveasfilename( # type: ignore
                defaultextension=".csv",
                filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
                title=self.lang.get("export_dialog_title")
            )
        except Exception as e:
            self.update_status(f"Dialog error: {e}")
            return

        if not file_path:
            self.update_status(self.lang.get("export_status_cancelled"))
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow((self.lang.get("col_ip"), self.lang.get("col_hostname"), self.lang.get("col_mac"), self.lang.get("col_manufacturer")))
                for child_id in self.tree.get_children():
                    writer.writerow(self.tree.item(child_id)['values'])
            self.update_status(self.lang.get("export_status_success").format(os.path.basename(file_path)))
        except Exception as e:
            self.update_status(f"Export error: {e}")

    def start_port_scan(self, ip):
        """Inicia el escaneo de puertos en un hilo y muestra una ventana de progreso."""
        # Crear una nueva ventana Toplevel para el progreso
        port_scan_window = ctk.CTkToplevel(self)
        port_scan_window.title(self.lang.get("portscan_window_title").format(ip))
        port_scan_window.geometry("400x150")
        port_scan_window.transient(self) # Mantener la ventana por encima de la principal
        port_scan_window.grab_set() # Bloquear interacción con la ventana principal

        label = ctk.CTkLabel(port_scan_window, text=self.lang.get("portscan_window_label").format(ip))
        label.pack(pady=20)

        progress_bar = ctk.CTkProgressBar(port_scan_window, width=350)
        progress_bar.pack(pady=10)
        progress_bar.set(0)

        def update_port_progress(value):
            progress_bar.set(value)

        def run_scan():
            # Lista de puertos comunes a escanear
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            open_ports = scan_ports(ip, common_ports, progress_callback=update_port_progress)
            
            # Cuando termina, le pedimos al hilo principal que cierre la ventana de progreso
            # y muestre los resultados. Esto evita la condición de carrera.
            def finish_port_scan():
                port_scan_window.destroy()
                self.show_port_scan_results(ip, open_ports)
            self.after(0, finish_port_scan)

        # Ejecutar el escaneo en un hilo
        threading.Thread(target=run_scan, daemon=True).start()

    def show_port_scan_results(self, ip, open_ports):
        """Muestra los resultados del escaneo de puertos en una nueva ventana."""
        results_window = ctk.CTkToplevel(self)
        results_window.title(self.lang.get("portscan_results_title").format(ip))
        results_window.geometry("300x400")
        results_window.transient(self)
        results_window.grab_set()

        label = ctk.CTkLabel(results_window, text=self.lang.get("portscan_results_label").format(ip))
        label.pack(pady=10)

        textbox = ctk.CTkTextbox(results_window, width=280, height=320)
        textbox.pack(pady=10, padx=10, fill="both", expand=True)
        
        if open_ports:
            textbox.insert("0.0", "\n".join(map(str, open_ports)))
        else:
            textbox.insert("0.0", self.lang.get("portscan_results_no_ports"))
        
        textbox.configure(state="disabled") # Hacer el texto de solo lectura

    def reset_ui(self):
        """Restaura la UI a su estado inicial después de un escaneo."""
        self.scan_button.configure(state="normal", text=self.lang.get("scan_button"))
        self.cancel_button.configure(state="disabled")

    def show_about_dialog(self):
        """Muestra la ventana 'Acerca de' con información del programa."""
        about_window = ctk.CTkToplevel(self)
        about_window.title(self.lang.get("about_title"))
        about_window.geometry("550x400")
        about_window.transient(self) # Mantener por encima de la ventana principal
        about_window.grab_set()      # Bloquear interacción con la ventana principal
        about_window.resizable(False, False)

        about_window.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(about_window, text="Redescubre", font=ctk.CTkFont(size=28, weight="bold")) # El nombre no se traduce
        title_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        version_label = ctk.CTkLabel(about_window, text=self.lang.get("about_version"), font=ctk.CTkFont(size=12))
        version_label.grid(row=1, column=0, padx=20, pady=0, sticky="n")

        description_label = ctk.CTkLabel(about_window, text=self.lang.get("about_description"), justify="center")
        description_label.grid(row=2, column=0, padx=20, pady=20)

        author_label = ctk.CTkLabel(about_window, text=self.lang.get("about_author"), font=ctk.CTkFont(size=12, weight="bold"))
        author_label.grid(row=3, column=0, padx=20, pady=10)

        license_label = ctk.CTkLabel(about_window, text=self.lang.get("about_license"))
        license_label.grid(row=4, column=0, padx=20, pady=5)

        close_button = ctk.CTkButton(about_window, text=self.lang.get("close_button"), command=about_window.destroy)
        close_button.grid(row=5, column=0, padx=20, pady=(20, 20))

    def update_language(self):
        """Actualiza el idioma de toda la GUI."""
        new_language = self.language_var.get()
        self.lang.set_language(new_language)

        # --- Actualizar todos los widgets de la ventana principal ---
        self.title(self.lang.get("window_title"))
        
        # 1. Recrear toda la barra de menú
        self._create_menus()
        
        # 2. Actualizar el resto de la UI
        self.label_ip.configure(text=self.lang.get("ip_range_label"))
        self.entry_ip.configure(placeholder_text=self.lang.get("ip_range_placeholder"))
        self.scan_button.configure(text=self.lang.get("scan_button"))
        self.cancel_button.configure(text=self.lang.get("cancel_button"))
        self.search_label.configure(text=self.lang.get("search_label"))
        self.search_entry.configure(placeholder_text=self.lang.get("search_placeholder"))
        
        self.tree.heading("IP", text=self.lang.get("col_ip"))
        self.tree.heading("Hostname", text=self.lang.get("col_hostname"))
        self.tree.heading("MAC", text=self.lang.get("col_mac"))
        self.tree.heading("Fabricante", text=self.lang.get("col_manufacturer"))

        # 3. Actualizar el menú contextual (clic derecho)
        self.context_menu.entryconfig(0, label=self.lang.get("ctx_ping"))
        self.context_menu.entryconfig(1, label=self.lang.get("ctx_rdp"))
        self.context_menu.entryconfig(2, label=self.lang.get("ctx_http"))

        self.status_label.configure(text=self.lang.get("status_ready"))
        self.export_button.configure(text=self.lang.get("export_button"))

if __name__ == "__main__":
    app = App()
    app.mainloop()
