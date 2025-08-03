import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
from datetime import datetime
import uuid
import random
import inspect
import io
import re

# Import the entire models package.
from models import (
    datastream_models,
    xccdf_models,
    cpe_dictionary_models,
    oval # Import our unified oval module
)

from models import oval_helper

class XccdfEditorApp:

##--  [ Initialization and Core UI ]---
    def __init__(self, root):
        self.root = root
        self.root.title("SPECTRE")
        self.root.geometry("1000x700")
        
        # --- Initialize all instance variables ---
        self.datastream_collection = None
        self.prefix = None  
        self.current_oval_defs = None
        self.item_map = {}
        self.cpe_item_map = {}
        self.oval_definition_map = {}
        self.oval_criteria_map = {}
        self.oval_tests_map = {}
        self.oval_objects_map = {}
        self.oval_states_map = {}
        self.oval_variables_map = {}
        self.right_clicked_item_data = None
        self.platforms_tree = None
        self.logical_test_editor_frame = None
        self.fact_refs_tree = None
        self.selected_platform_obj = None
        self.oval_factory = oval_helper.OVAL_Entity_Factory()
        
        # --- create the UI ---
        self.create_widgets()

    def create_widgets(self):
        # --- Create Menubar ---
        self.menu = tk.Menu(self.root)
        self.root.config(menu=self.menu)

        # --- File Menu ---
        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Save Datastream As...", command=self.save_file, state=tk.DISABLED)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)

        # --- Create Menu ---
        create_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Create", menu=create_menu)
        create_menu.add_command(label="New Datastream", command=self.new_file)
        create_menu.add_separator()
        create_menu.add_command(label="New XCCDF Component", command=self.new_xccdf_component, state=tk.DISABLED)
        create_menu.add_command(label="New CPE Dictionary Component", command=self.new_cpe_dictionary, state=tk.DISABLED)
        create_menu.add_command(label="New OVAL Check Component", command=lambda: self.new_oval_component("checks"), state=tk.DISABLED)
        create_menu.add_command(label="New CPE OVAL Component", command=lambda: self.new_oval_component("dictionaries"), state=tk.DISABLED)
  
        # --- Import Menu ---
        import_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Import", menu=import_menu)
        import_menu.add_command(label="CPE Dictionary...", command=self.import_cpe_dictionary, state=tk.DISABLED)
        import_menu.add_command(label="OVAL Check Component...", command=lambda: self._import_oval_file("OVAL Check", "checks"), state=tk.DISABLED)
        import_menu.add_command(label="CPE OVAL Component...", command=lambda: self._import_oval_file("CPE OVAL", "dictionaries"), state=tk.DISABLED)

        # --- Main layout ---
        paned_window = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Left side: Treeview ---
        tree_frame = ttk.Frame(paned_window)
        self.tree = ttk.Treeview(tree_frame)
        self.tree.pack(fill=tk.BOTH, expand=True)
        paned_window.add(tree_frame, weight=1)

        # --- Right side: Detail Frame ---
        self.detail_frame = ttk.Frame(paned_window, padding=10)
        paned_window.add(self.detail_frame, weight=3)

        # --- Bind events ---
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        # --- Initialize context menu and welcome message ---
        self.create_context_menu()
        self.show_welcome_message()        
                        
##--  [ Top-Level Menu Commands (File/Import) ]---
    def new_file(self):
        prefix = simpledialog.askstring("New Datastream", "Enter a unique source prefix (no underscores):", parent=self.root)
        
        if not prefix or '_' in prefix:
            messagebox.showerror("Invalid Prefix", "The prefix cannot be empty or contain underscores.")
            return
            
        self.prefix = prefix
        
        collection_id = f"scap_{self.prefix}_collection_from_SPECTRE.xml"
        datastream_id = f"scap_{self.prefix}_datastream_from_SPECTRE.xml"

        data_stream = datastream_models.data_stream(
            id=datastream_id,
            scap_version="1.3",
            use_case="OTHER",
            timestamp=datetime.now()
        )
        self.datastream_collection = datastream_models.data_stream_collection(
            id=collection_id,
            schematron_version="1.3",
            data_stream=[data_stream]
        )
        
        # --- Create components and get their IDs
        cpe_comp_id, cpe_cref_id = self.new_cpe_dictionary()
        xccdf_comp_id, xccdf_cref_id = self.new_xccdf_component()
        oval_check_comp_id, oval_check_cref_id = self.new_oval_component("checks")
        cpe_oval_comp_id, cpe_oval_cref_id = self.new_oval_component("dictionaries")
        
        ds = self.datastream_collection.get_data_stream()[0]

        # --- Manually create the single, linked component-ref for checklists ---
        if xccdf_comp_id and oval_check_comp_id and xccdf_cref_id: 
            if ds.get_checklists() is None: ds.set_checklists(datastream_models.refListType())
            check_ref_id = f"{self.prefix.replace('.', '-')}-collection-oval.xml"
            checklist_comp_ref = datastream_models.component_ref(id=xccdf_cref_id, href=f"#{xccdf_comp_id}")
            checklist_catalog_uri = datastream_models.uri(name=check_ref_id, uri_member=f"#{oval_check_cref_id}")
            checklist_comp_ref.set_catalog(datastream_models.catalog(uri=[checklist_catalog_uri]))
            ds.get_checklists().add_component_ref(checklist_comp_ref)
            
        # --- Manually create the single, linked component-ref for dictionaries
        if cpe_comp_id and cpe_oval_comp_id:
            ds = self.datastream_collection.get_data_stream()[0]
            if ds.get_dictionaries() is None:
                ds.set_dictionaries(datastream_models.refListType())

            ref_id = f"{self.prefix.replace('.', '-')}-collection-cpe-oval.xml"
            # --- The component-ref points to the CPE dictionary component
            comp_ref = datastream_models.component_ref(id=cpe_cref_id, href=f"#{cpe_comp_id}")
            # --- The catalog within it points to the CPE OVAL component
            catalog_uri = datastream_models.uri(name=ref_id, uri_member=f"#{cpe_oval_cref_id}")
            comp_ref.set_catalog(datastream_models.catalog(uri=[catalog_uri]))            
            ds.get_dictionaries().add_component_ref(comp_ref)

        # --- Populate the <checks> list with simple refs to all OVAL components.
        if ds.get_checks() is None:
            ds.set_checks(datastream_models.refListType())

        # --- Create and add the simple ref for the OVAL Check component
        if oval_check_comp_id:
            oval_check_ref_id = f"scap_{self.prefix}_cref_SPECTRE-oval-check.xml"
            oval_check_ref = self._create_component_ref(
                oval_check_ref_id, f"#{oval_check_comp_id}", create_catalog=False
            )
            ds.get_checks().add_component_ref(oval_check_ref)
        
        # --- Create and add the simple ref for the CPE OVAL component
        if cpe_oval_comp_id:
            cpe_oval_check_ref_id = f"scap_{self.prefix}_cref_SPECTRE-cpe-oval-check.xml"
            cpe_oval_check_ref = self._create_component_ref(
                cpe_oval_check_ref_id, f"#{cpe_oval_comp_id}", create_catalog=False
            )
            ds.get_checks().add_component_ref(cpe_oval_check_ref)

        self.populate_treeview() # Refresh the tree once all components are created and linked
        self.file_menu.entryconfig("Save Datastream As...", state=tk.NORMAL)

    def save_file(self):
        if not self.datastream_collection:
            messagebox.showwarning("No Data", "There is nothing to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
            title="Save Datastream As..."
        )
        if not file_path:
            return

        try:
            # 2. Export to an in-memory buffer to allow for post-processing.
            xml_buffer = io.StringIO()

            # 3. Define all namespaces and the main schemaLocation for the root element.
            root_schema_location = (
                'http://scap.nist.gov/schema/scap/source/1.2 http://scap.nist.gov/schema/scap/1.2/scap-source-data-stream_1.2.xsd '
                'http://checklists.nist.gov/xccdf/1.2 http://csrc.nist.gov/publications/nistir/7275/SP800-70-2/xccdf-1.2.xsd '
                'http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.3.xsd'
            )
            ns_definitions = (
                'xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2" '
                'xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" '
                'xmlns:cpe-dict="http://cpe.mitre.org/dictionary/2.0" '
                'xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" '
                'xmlns:html="http://www.w3.org/1999/xhtml" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" '
                'xmlns:ocil="http://scap.nist.gov/schema/ocil/2.0" '
                'xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" '
                'xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" '
                'xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" '
                'xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" '
                'xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" '
                'xmlns:sol-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#solaris" '
                'xmlns:xlink="http://www.w3.org/1999/xlink" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                'xmlns:cat="urn:oasis:names:tc:entity:xmlns:xml:catalog" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                #f'xsi:schemaLocation="{root_schema_location}"'
            )

            # 4. Call export with the correct, separated name and prefix arguments.
            self.datastream_collection.export(
                xml_buffer, 0,
                pretty_print=True,
                name_='data-stream-collection',
                namespaceprefix_='ds:',
                namespacedef_=ns_definitions
            )
            xml_content = xml_buffer.getvalue()
            
            # 6. Post-Processing Step B: Inject OVAL's own schemaLocation.
            oval_schema_location = oval.OVAL_SCHEMA_LOCATION
            
            # Find the first <oval-def:oval_definitions> tag and insert the attribute.
            correct_opening_tag = f'<oval-def:oval_definitions xsi:schemaLocation="{oval_schema_location}">'
            correct_closing_tag = '</oval-def:oval_definitions>'

            # 7. Write the final, corrected string to the file.
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write(xml_content)
            messagebox.showinfo("Success", f"File saved successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file: {e}")

            
    def _import_oval_file(self, component_type_str, ref_list_name):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return

        oval_path = filedialog.askopenfilename(
            title=f"Import {component_type_str} File",
            filetypes=(("XML files", "*.xml"), ("All files", "*.*"))
        )
        if not oval_path:
            return

        try:
            parsed_oval_defs = oval.parse(oval_path, silence=True)
            
            comp_id = f"comp_oval_{uuid.uuid4()}"
            oval_component = datastream_models.component(
                id=comp_id,
                timestamp=datetime.now(),
                oval_definitions=parsed_oval_defs
            )
            
            self.datastream_collection.add_component(oval_component)
            comp_ref = self._create_component_ref(f"cref_oval_{uuid.uuid4()}", f"#{comp_id}")
            ds = self.datastream_collection.get_data_stream()[0]
            
            ref_list_obj = getattr(ds, f"get_{ref_list_name}")()
            if ref_list_obj is None:
                ref_list_obj = datastream_models.refListType()
                getattr(ds, f"set_{ref_list_name}")(ref_list_obj)
            
            ref_list_obj.add_component_ref(comp_ref)

            self.populate_treeview()
            messagebox.showinfo("Success", f"{component_type_str} component added.")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import OVAL file:\n{e}")

    def import_cpe_dictionary(self):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return

        # --- Add this check to prevent importing a second dictionary
        if self.get_cpe_dictionary() is not None:
            messagebox.showwarning("Exists", "A CPE Dictionary component already exists in this datastream.")
            return

        cpe_path = filedialog.askopenfilename(
            title="Import CPE Dictionary File",
            filetypes=(("XML files", "*.xml"), ("All files", "*.*"))
        )
        if not cpe_path:
            return

        try:
            parsed_cpe_list = cpe_dictionary_models.parse(cpe_path, silence=True)
            
            comp_id = f"comp_cpe_{uuid.uuid4()}"
            cpe_component = datastream_models.component(
                id=comp_id,
                timestamp=datetime.now(),
                cpe_list=parsed_cpe_list
            )
            
            self.datastream_collection.add_component(cpe_component)
            comp_ref = self._create_component_ref(f"cref_cpe_{uuid.uuid4()}", f"#{comp_id}")
            ds = self.datastream_collection.get_data_stream()[0]
            if ds.get_dictionaries() is None:
                ds.set_dictionaries(datastream_models.refListType())
            ds.get_dictionaries().add_component_ref(comp_ref)

            self.populate_treeview()
            messagebox.showinfo("Success", "CPE Dictionary component added.")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import CPE dictionary:\n{e}")

    def import_oval_component(self):
        self._import_oval_file("OVAL Check", "checks")
    
    def import_cpe_oval(self):
        self._import_oval_file("CPE OVAL", "dictionaries")

##--  [ Core Component Creators ]---
    def new_xccdf_component(self):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return
        if self.get_benchmark() is not None:
            messagebox.showwarning("Exists", "An XCCDF Benchmark component already exists in this datastream.")
            return
        
        benchmark = xccdf_models.Benchmark(id=f"xccdf_benchmark_{uuid.uuid4()}")
        benchmark.set_title([xccdf_models.textWithSubType(valueOf_='New Security Benchmark')])
        benchmark.status = [xccdf_models.status(valueOf_='incomplete', date=datetime.now().strftime('%Y-%m-%d'))]
        benchmark.description = [xccdf_models.htmlTextWithSubType(valueOf_='A new benchmark description.')]
        benchmark.version = xccdf_models.versionType(valueOf_='1.0.0')
        benchmark.metadata = [xccdf_models.metadataType()]
        new_group = xccdf_models.groupType(id="G-1", title=[xccdf_models.textWithSubType(valueOf_='Default Group')])
        new_group.description = [xccdf_models.htmlTextWithSubType(valueOf_='')]
        new_rule = xccdf_models.ruleType(id="R-1", severity="unknown", title=[xccdf_models.textWithSubType(valueOf_='Default Rule')])
        new_rule.description = [xccdf_models.htmlTextWithSubType(valueOf_='')]
        new_group.Rule.append(new_rule)
        benchmark.Group.append(new_group)
        
        comp_id = f"scap_{self.prefix}_comp_SPECTRE-xccdf.xml"
        cref_id = f"scap_{self.prefix}_cref_SPECTRE-xccdf.xml"
        xccdf_component = datastream_models.component(
            id=comp_id,
            timestamp=datetime.now(),
            Benchmark=benchmark
        )
        self.datastream_collection.add_component(xccdf_component)
        
        return comp_id, cref_id

    def new_cpe_dictionary(self):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return None # Return None on failure
        
        if self.get_cpe_dictionary() is not None:
            messagebox.showwarning("Exists", "A CPE Dictionary component already exists in this datastream.")
            return None # Return None on failure
        
        new_cpe_list = cpe_dictionary_models.ListType()
        comp_id = f"scap_{self.prefix}_comp_SPECTRE-cpe-dictionary.xml"
        cref_id = f"scap_{self.prefix}_cref_SPECTRE-cpe-dictionary.xml"
        cpe_component = datastream_models.component(
            id=comp_id,
            timestamp=datetime.now(),
            cpe_list=new_cpe_list
        )
        self.datastream_collection.add_component(cpe_component)
        return comp_id, cref_id # Return the new component's ID

    def new_oval_component(self, ref_list_name):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return None

        new_oval_defs = oval.oval_definitions()
        
        # --- Use conditional logic to generate the correct component ID
        if ref_list_name == "dictionaries":
            comp_id = f"scap_{self.prefix}_comp_SPECTRE-cpe-oval.xml"
            cref_id = f"scap_{self.prefix}_cref_SPECTRE-cpe-oval.xml"
        else: # Assumes "checks"
            comp_id = f"scap_{self.prefix}_cref_SPECTRE-oval.xml"
            cref_id = f"scap_{self.prefix}_cref_SPECTRE-oval.xml"


        oval_component = datastream_models.component(
            id=comp_id,
            timestamp=datetime.now(),
            oval_definitions=new_oval_defs
        )
        self.datastream_collection.add_component(oval_component)
        
        return comp_id, cref_id # Always return the component ID

##--  [ Main UI Handlers and Population ]---
    def populate_treeview(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.item_map.clear()
        if not self.datastream_collection:
            return
        
        dsc_id = self.tree.insert("", "end", text=f"Datastream Collection ({self.datastream_collection.get_id()})", open=True)
        self.item_map[dsc_id] = self.datastream_collection

        for ds in self.datastream_collection.get_data_stream():
            ds_id = self.tree.insert(dsc_id, "end", text=f"DataStream ({ds.get_id()})", open=True)
            self.item_map[ds_id] = ds
        
        comp_node_id = self.tree.insert(dsc_id, "end", text="Components", open=True)
        for comp in self.datastream_collection.get_component():
            comp_text = f"Component ({comp.get_id()})"
            if comp.Benchmark:
                comp_text = f"XCCDF Component ({comp.get_id()})"
            elif comp.cpe_list:
                comp_text = f"CPE Dictionary Component ({comp.get_id()})"
            elif comp.oval_definitions:
                # Simply check if "cpe-oval" is in the component's ID string
                if "cpe-oval" in comp.get_id():
                    comp_text = f"CPE OVAL Component ({comp.get_id()})"
                else:
                    comp_text = f"OVAL Check Component ({comp.get_id()})"

            c_id = self.tree.insert(comp_node_id, "end", text=comp_text, open=True)
            self.item_map[c_id] = comp
            
            if comp.Benchmark:
                benchmark_obj = comp.Benchmark
                title_text = benchmark_obj.title[0].get_valueOf_() if benchmark_obj.title else ""
                b_id = self.tree.insert(c_id, "end", text=f"Benchmark: {title_text}", open=True)
                self.item_map[b_id] = benchmark_obj
                
                if benchmark_obj.Group:
                    for group in benchmark_obj.Group:
                        self._add_group_to_tree(b_id, group)
                
                profiles_node_id = self.tree.insert(b_id, "end", text="Profiles", open=False)
                self.item_map[profiles_node_id] = "PROFILES_STATIC_NODE"
                if benchmark_obj.Profile:
                    for profile in benchmark_obj.Profile:
                        profile_title = profile.title[0].get_valueOf_() if profile.title else profile.get_id()
                        p_node_id = self.tree.insert(profiles_node_id, "end", text=profile_title)
                        self.item_map[p_node_id] = profile

    def on_tree_select(self, event):
        selected_id = self.tree.focus()
        if not selected_id:
            return
        item_data = self.item_map.get(selected_id)
        self.display_details(item_data)
        
    def display_details(self, item):
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        if not item: return

        if isinstance(item, str) and item == "PROFILES_STATIC_NODE":
            self.display_profile_list_manager()
            
        elif isinstance(item, datastream_models.data_stream_collection):
            self.create_detail_entry(self.detail_frame, "ID", item, "id")
            self.create_detail_entry(self.detail_frame, "Schematron Version", item, "schematron_version")

        elif isinstance(item, datastream_models.component):
            if item.cpe_list is not None:
                self.display_cpe_dictionary_manager(item.cpe_list)
            elif item.oval_definitions is not None:
                self.display_oval_manager(item.oval_definitions)
            else:
                self.create_detail_entry(self.detail_frame, "ID", item, "id")

        elif isinstance(item, datastream_models.data_stream):
            self.create_detail_entry(self.detail_frame, "ID", item, "id")

            # --- SCAP Version Drop-down ---
            scap_frame = ttk.Frame(self.detail_frame)
            scap_frame.pack(fill=tk.X, pady=5)
            ttk.Label(scap_frame, text="SCAP Version", width=15).pack(side=tk.LEFT)
            scap_version_options = ['1.0', '1.1', '1.2', '1.3']
            scap_version_var = tk.StringVar(self.root, value=item.get_scap_version())
            scap_combo = ttk.Combobox(scap_frame, textvariable=scap_version_var, values=scap_version_options, state="readonly")
            scap_combo.pack(fill=tk.X, expand=True)
            scap_combo.bind("<<ComboboxSelected>>", lambda event: item.set_scap_version(scap_version_var.get()))

            # --- Use Case Drop-down ---
            use_case_frame = ttk.Frame(self.detail_frame)
            use_case_frame.pack(fill=tk.X, pady=5)
            ttk.Label(use_case_frame, text="Use Case", width=15).pack(side=tk.LEFT)
            use_case_options = ['CONFIGURATION', 'VULNERABILITY', 'INVENTORY', 'OTHER']
            use_case_var = tk.StringVar(self.root, value=item.get_use_case())
            use_case_combo = ttk.Combobox(use_case_frame, textvariable=use_case_var, values=use_case_options, state="readonly")
            use_case_combo.pack(fill=tk.X, expand=True)
            use_case_combo.bind("<<ComboboxSelected>>", lambda event: item.set_use_case(use_case_var.get()))
        elif isinstance(item, xccdf_models.Benchmark):
            notebook = ttk.Notebook(self.detail_frame)
            notebook.pack(fill=tk.BOTH, expand=True, pady=5)
            tab_general = ttk.Frame(notebook, padding=10)
            tab_platforms = ttk.Frame(notebook, padding=10)
            notebook.add(tab_general, text="General")
            notebook.add(tab_platforms, text="Platforms")
            self.create_detail_entry(tab_general, "Benchmark ID", item, "id")
            self.create_text_editor(tab_general, "Title", item, "title")
            if item.version is None: item.version = xccdf_models.versionType(valueOf_='')
            self.create_detail_entry(tab_general, "Version", item.version, "valueOf_")
            frame = ttk.Frame(tab_general)
            frame.pack(fill=tk.X, pady=5)
            label = ttk.Label(frame, text="Status", width=15)
            label.pack(side=tk.LEFT, anchor='n')
            status_options = ['accepted', 'deprecated', 'draft', 'incomplete', 'interim']
            status_var = tk.StringVar(self.root)
            if item.status:
                status_var.set(item.status[0].get_valueOf_() or 'incomplete')
            status_combo = ttk.Combobox(frame, textvariable=status_var, values=status_options, state="readonly")
            status_combo.pack(fill=tk.X, expand=True)
            def update_status(event):
                if not item.status: item.status.append(xccdf_models.statusType())
                item.status[0].set_valueOf_(status_var.get())
            status_combo.bind("<<ComboboxSelected>>", update_status)
            ttk.Label(tab_general, text="Status Date", width=15).pack(anchor='w', pady=(5, 0))
            date_var = tk.StringVar(self.root)
            if item.status:
                date_obj = item.status[0].get_date()
                if date_obj: date_var.set(date_obj.strftime('%Y-%m-%d'))
            def update_date(*args):
                date_str = date_var.get()
                if not date_str: return
                try:
                    new_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                    if not item.status: item.status.append(xccdf_models.statusType())
                    item.status[0].set_date(new_date)
                except ValueError:
                    print(f"Invalid date format: {date_str}. Please use YYYY-MM-DD.")
            date_var.trace_add("write", update_date)
            date_entry = ttk.Entry(tab_general, textvariable=date_var)
            date_entry.pack(fill=tk.X, expand=True)
            self.create_text_editor(tab_general, "Description", item, "description", height=5)
            meta_frame = ttk.LabelFrame(tab_general, text="Metadata", padding=5)
            meta_frame.pack(fill=tk.BOTH, expand=True, pady=10)
            def create_metadata_entry(parent, field_name, dc_tag):
                ttk.Label(parent, text=f"{field_name}:").pack(anchor='w')
                var = tk.StringVar()
                entry = ttk.Entry(parent, textvariable=var)
                entry.pack(fill=tk.X, expand=True, pady=2)
                return var, entry
            creator_var, _ = create_metadata_entry(meta_frame, "Creator", "creator")
            publisher_var, _ = create_metadata_entry(meta_frame, "Publisher", "publisher")
            contrib_var, _ = create_metadata_entry(meta_frame, "Contributor", "contributor")
            source_var, _ = create_metadata_entry(meta_frame, "Source", "source")
            def update_metadata_field(dc_tag, new_value):
                if item.metadata is None or not item.metadata: item.metadata = [xccdf_models.metadataType()]
                meta_content_list = item.metadata[0].get_anytypeobjs_()
                if meta_content_list is None:
                    meta_content_list = []
                    item.metadata[0].set_anytypeobjs_(meta_content_list)
                dc_uri = "http://purl.org/dc/elements/1.1/"
                tag_to_find = f"{{{dc_uri}}}{dc_tag}"
                found = False
                for i, xml_str in enumerate(meta_content_list):
                    try:
                        elem = etree_.fromstring(xml_str)
                        if elem.tag == tag_to_find:
                            elem.text = new_value
                            meta_content_list[i] = etree_.tostring(elem).decode('utf-8')
                            found = True
                            break
                    except etree_.XMLSyntaxError: continue
                if not found and new_value:
                    new_elem_str = f'<dc:{dc_tag} xmlns:dc="{dc_uri}">{new_value}</dc:{dc_tag}>'
                    meta_content_list.append(new_elem_str)
            if item.metadata and item.metadata[0].get_anytypeobjs_():
                for xml_str in item.metadata[0].get_anytypeobjs_():
                    try:
                        elem = etree_.fromstring(xml_str)
                        if "creator" in elem.tag: creator_var.set(elem.text)
                        if "publisher" in elem.tag: publisher_var.set(elem.text)
                        if "contributor" in elem.tag: contrib_var.set(elem.text)
                        if "source" in elem.tag: source_var.set(elem.text)
                    except etree_.XMLSyntaxError: continue
            creator_var.trace_add("write", lambda *args: update_metadata_field("creator", creator_var.get()))
            publisher_var.trace_add("write", lambda *args: update_metadata_field("publisher", publisher_var.get()))
            contrib_var.trace_add("write", lambda *args: update_metadata_field("contributor", contrib_var.get()))
            source_var.trace_add("write", lambda *args: update_metadata_field("source", source_var.get()))
            platform_frame = ttk.LabelFrame(tab_platforms, text="Platform Definitions", padding=5)
            platform_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
            self.platforms_tree = ttk.Treeview(platform_frame, columns=("id",), show="headings", height=4)
            self.platforms_tree.heading("id", text="Platform ID")
            self.platforms_tree.pack(fill=tk.BOTH, expand=True)
            self.populate_platforms_tree()
            self.platforms_tree.bind("<<TreeviewSelect>>", self.on_platform_select)
            button_frame = ttk.Frame(platform_frame)
            button_frame.pack(fill=tk.X, pady=5)
            ttk.Button(button_frame, text="Add", command=self.add_platform).pack(side=tk.LEFT, padx=2)
            ttk.Button(button_frame, text="Edit", command=self.edit_platform).pack(side=tk.LEFT, padx=2)
            ttk.Button(button_frame, text="Remove", command=self.remove_platform).pack(side=tk.LEFT, padx=2)
            self.logical_test_editor_frame = ttk.Frame(tab_platforms)
            self.logical_test_editor_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            self.create_benchmark_platform_manager(tab_platforms, item)
        
        elif isinstance(item, (xccdf_models.groupType, xccdf_models.ruleType)):
            move_frame = ttk.Frame(self.detail_frame)
            move_frame.pack(fill=tk.X, pady=(0, 5))
            ttk.Button(move_frame, text="Move...", command=self.show_move_dialog).pack(side=tk.LEFT)
            if isinstance(item, xccdf_models.groupType):
                self.create_detail_entry(self.detail_frame, "Group ID", item, "id")
                self.create_text_editor(self.detail_frame, "Group Title", item, "title")
                self.create_text_editor(self.detail_frame, "Description", item, "description", height=5)
                self.create_item_platform_manager(self.detail_frame, item)
            else:
                notebook = ttk.Notebook(self.detail_frame)
                notebook.pack(fill=tk.BOTH, expand=True, pady=5)
                tab_general = ttk.Frame(notebook, padding=10)
                tab_checks = ttk.Frame(notebook, padding=10)
                tab_remediation = ttk.Frame(notebook, padding=10)
                notebook.add(tab_general, text="General")
                notebook.add(tab_checks, text="Checks")
                notebook.add(tab_remediation, text="Remediation")
                self.create_detail_entry(tab_general, "Rule ID", item, "id")
                self.create_text_editor(tab_general, "Title", item, "title")
                frame = ttk.Frame(tab_general)
                frame.pack(fill=tk.X, pady=5)
                label = ttk.Label(frame, text="Severity", width=15)
                label.pack(side=tk.LEFT, anchor='n')
                severity_options = ['unknown', 'low', 'medium', 'high', 'info']
                severity_var = tk.StringVar(self.root, value=(item.get_severity() or 'unknown'))
                severity_combo = ttk.Combobox(frame, textvariable=severity_var, values=severity_options, state="readonly")
                severity_combo.pack(fill=tk.X, expand=True)
                severity_combo.bind("<<ComboboxSelected>>", lambda e: item.set_severity(severity_var.get()))
                self.create_detail_entry(tab_general, "Weight", item, "weight")
                self.create_text_editor(tab_general, "Description", item, "description", height=5)
                if item.version is None: item.version = xccdf_models.versionType(valueOf_='')
                self.create_detail_entry(tab_general, "Version", item.version, "valueOf_")
                if not item.check: item.check = [xccdf_models.checkType(system='http://oval.mitre.org/XMLSchema/oval-definitions-5')]
                check = item.check[0]
                self.create_detail_entry(tab_checks, "System", check, "system")
                if not check.check_content_ref: check.check_content_ref = [xccdf_models.checkContentRefType()]
                self.create_detail_entry(tab_checks, "Check Content Ref (href)", check.check_content_ref[0], "href")
                if not item.fixtext: item.set_fixtext([xccdf_models.fixTextType(valueOf_='')])
                self.create_text_editor(tab_remediation, "Fix Text", item.fixtext[0], "valueOf_", height=6)
                if not item.fix: item.set_fix([xccdf_models.fixType()])
                fix_obj = item.fix[0]
                fixtext_obj = item.fixtext[0]
                fix_id_var = tk.StringVar(value=fix_obj.get_id())
                fix_ref_var = tk.StringVar(value=fixtext_obj.get_fixref())
                def update_fix_fields(*args):
                    new_id = fix_id_var.get()
                    fix_obj.set_id(new_id)
                    fixtext_obj.set_fixref(new_id)
                    fix_ref_var.set(new_id)
                fix_id_var.trace_add("write", update_fix_fields)
                id_frame = ttk.Frame(tab_remediation)
                id_frame.pack(fill=tk.X, pady=5)
                ttk.Label(id_frame, text="Fix ID", width=15).pack(side=tk.LEFT)
                ttk.Entry(id_frame, textvariable=fix_id_var).pack(fill=tk.X, expand=True)
                ref_frame = ttk.Frame(tab_remediation)
                ref_frame.pack(fill=tk.X, pady=5)
                ttk.Label(ref_frame, text="Fix Reference", width=15).pack(side=tk.LEFT)
                ttk.Entry(ref_frame, textvariable=fix_ref_var, state="readonly").pack(fill=tk.X, expand=True)
                self.create_item_platform_manager(self.detail_frame, item)
        
        elif isinstance(item, xccdf_models.profileType):
            self.create_detail_entry(self.detail_frame, "Profile ID", item, "id")
            self.create_text_editor(self.detail_frame, "Title", item, "title")
            self.create_text_editor(self.detail_frame, "Description", item, "description", height=4)
            self.create_profile_selection_editor(item)
 
    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Add Group", command=self.add_group)
        self.context_menu.add_command(label="Add Rule", command=self.add_rule)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete", command=self.delete_item)

    def show_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id: return
        self.tree.selection_set(item_id)
        self.right_clicked_item_data = self.item_map.get(item_id)
        
        self.context_menu.entryconfig("Add Group", state=tk.DISABLED)
        self.context_menu.entryconfig("Add Rule", state=tk.DISABLED)
        self.context_menu.entryconfig("Delete", state=tk.DISABLED)

        if isinstance(self.right_clicked_item_data, xccdf_models.Benchmark):
            self.context_menu.entryconfig("Add Group", state=tk.NORMAL)
        elif isinstance(self.right_clicked_item_data, xccdf_models.groupType):
            self.context_menu.entryconfig("Add Group", state=tk.NORMAL)
            self.context_menu.entryconfig("Add Rule", state=tk.NORMAL)
            self.context_menu.entryconfig("Delete", state=tk.NORMAL)
        elif isinstance(self.right_clicked_item_data, xccdf_models.ruleType):
            self.context_menu.entryconfig("Delete", state=tk.NORMAL)
        elif isinstance(self.right_clicked_item_data, datastream_models.component):
            self.context_menu.entryconfig("Delete", state=tk.NORMAL)
        self.context_menu.post(event.x_root, event.y_root)

    def add_group(self):
        if not isinstance(self.right_clicked_item_data, (xccdf_models.Benchmark, xccdf_models.groupType)): return
        new_id = f"G-{uuid.uuid4()}"
        new_group = xccdf_models.groupType(id=new_id)
        new_group.set_title([xccdf_models.textWithSubType(valueOf_='New Group')])
        new_group.description = [xccdf_models.htmlTextWithSubType(valueOf_='')]
        self.right_clicked_item_data.Group.append(new_group)
        self.populate_treeview()

    def add_rule(self):
        if not isinstance(self.right_clicked_item_data, xccdf_models.groupType): return
        new_id = f"R-{uuid.uuid4()}"
        new_rule = xccdf_models.ruleType(id=new_id, severity="unknown")
        new_rule.set_title([xccdf_models.textWithSubType(valueOf_='New Rule')])
        new_rule.description = [xccdf_models.htmlTextWithSubType(valueOf_='')]
        if self.right_clicked_item_data.Rule is None:
            self.right_clicked_item_data.Rule = []
        self.right_clicked_item_data.Rule.append(new_rule)
        self.populate_treeview()

    def delete_item(self):
        item_to_delete = self.right_clicked_item_data
        if not item_to_delete: return

        if isinstance(item_to_delete, (xccdf_models.groupType, xccdf_models.ruleType)):
            item_type = "Group" if isinstance(item_to_delete, xccdf_models.groupType) else "Rule"
            item_id = item_to_delete.get_id()
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete this {item_type} ({item_id})?"):
                parent = self.find_parent(self.datastream_collection, item_to_delete)
                if parent:
                    if item_type == "Group":
                        parent.Group.remove(item_to_delete)
                    else:
                        parent.Rule.remove(item_to_delete)
                    self.populate_treeview()
                    self.show_welcome_message()
                else:
                    messagebox.showerror("Error", "Could not find the parent of the item to delete.")
        
        elif isinstance(item_to_delete, datastream_models.component):
            item_id = item_to_delete.get_id()
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete this Component ({item_id})?"):
                self.datastream_collection.get_component().remove(item_to_delete)
                for ds in self.datastream_collection.get_data_stream():
                    for ref_list_name in ['checklists', 'checks', 'dictionaries']:
                        ref_list_obj = getattr(ds, f"get_{ref_list_name}")()
                        if ref_list_obj:
                            refs = ref_list_obj.get_component_ref()
                            refs_to_keep = [r for r in refs if r.get_href() != f"#{item_id}"]
                            ref_list_obj.set_component_ref(refs_to_keep)
                self.populate_treeview()
                self.show_welcome_message()

##--  [  XCCDF-Specific UI & Helpers ]---
    def create_benchmark_platform_manager(self, parent_frame, item_data):
        manager_frame = ttk.LabelFrame(parent_frame, text="Applicable Platforms (Benchmark-Level)", padding=5)
        manager_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        ref_tree = ttk.Treeview(manager_frame, columns=("idref",), show="headings", height=3)
        ref_tree.heading("idref", text="Platform ID Reference")
        ref_tree.pack(fill=tk.BOTH, expand=True)
        def populate_platform_references_list():
            for i in ref_tree.get_children(): ref_tree.delete(i)
            if item_data.platform:
                for p_ref in item_data.platform:
                    ref_tree.insert("", "end", values=(p_ref.get_idref(),))
        def add_platform_ref():
            new_idref = simpledialog.askstring("Add Platform Reference", "Enter new platform reference (ID or CPE):", parent=self.root)
            if not new_idref: return
            if item_data.platform and any(p.get_idref() == new_idref for p in item_data.platform):
                messagebox.showwarning("Duplicate", "That platform reference already exists.")
                return
            if item_data.platform is None:
                item_data.platform = []
            item_data.platform.append(xccdf_models.overrideableCPE2idrefType(idref=new_idref))
            populate_platform_references_list()
        def edit_platform_ref():
            selected = ref_tree.focus()
            if not selected: return
            current_idref = ref_tree.item(selected)['values'][0]
            new_idref = simpledialog.askstring("Edit Platform Reference", "Enter new platform reference:", initialvalue=current_idref, parent=self.root)
            if new_idref and new_idref != current_idref:
                for p_ref in item_data.platform:
                    if p_ref.get_idref() == current_idref:
                        p_ref.set_idref(new_idref)
                        break
                populate_platform_references_list()
        def remove_platform_ref():
            selected = ref_tree.focus()
            if not selected: return
            idref_to_remove = ref_tree.item(selected)['values'][0]
            if item_data.platform:
                item_data.platform = [p for p in item_data.platform if p.get_idref() != idref_to_remove]
            populate_platform_references_list()
        button_frame = ttk.Frame(manager_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Add...", command=add_platform_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Edit...", command=edit_platform_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Remove", command=remove_platform_ref).pack(side=tk.LEFT, padx=2)
        populate_platform_references_list()

    def display_profile_list_manager(self):
        manager_frame = ttk.LabelFrame(self.detail_frame, text="Manage Profiles", padding=5)
        manager_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        profile_tree = ttk.Treeview(manager_frame, columns=("id", "title"), show="headings", height=5)
        profile_tree.heading("id", text="Profile ID")
        profile_tree.heading("title", text="Title")
        profile_tree.pack(fill=tk.BOTH, expand=True)
        
        benchmark_obj = self.get_benchmark()

        def populate_profile_list():
            for i in profile_tree.get_children(): profile_tree.delete(i)
            if benchmark_obj and benchmark_obj.Profile:
                for p in benchmark_obj.Profile:
                    title = p.title[0].get_valueOf_() if p.title else ""
                    profile_tree.insert("", "end", values=(p.get_id(), title))
        
        def add_profile():
            new_id = simpledialog.askstring("Add Profile", "Enter new profile ID:", parent=self.root)
            if not new_id: return
            if any(p.get_id() == new_id for p in benchmark_obj.Profile):
                messagebox.showwarning("Duplicate ID", "A profile with that ID already exists.")
                return
            
            new_profile = xccdf_models.profileType(id=new_id)
            new_profile.set_title([xccdf_models.textWithSubType(valueOf_="New Profile")])
            if benchmark_obj.Profile is None:
                benchmark_obj.Profile = []
            benchmark_obj.Profile.append(new_profile)
            self.populate_treeview()
            populate_profile_list()
            
        def remove_profile():
            selected = profile_tree.focus()
            if not selected: return
            id_to_remove = profile_tree.item(selected)['values'][0]
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to remove profile '{id_to_remove}'?"):
                benchmark_obj.Profile = [p for p in benchmark_obj.Profile if p.get_id() != id_to_remove]
                self.populate_treeview()
                populate_profile_list()

        button_frame = ttk.Frame(manager_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Add Profile...", command=add_profile).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Remove Selected", command=remove_profile).pack(side=tk.LEFT, padx=2)

        populate_profile_list()

    def _add_group_to_tree(self, parent_node, group):
        title_text = group.title[0].get_valueOf_() if group.title else ""
        group_id_str = group.id or "Group"
        node_id = self.tree.insert(parent_node, "end", text=f"Group: {title_text} ({group_id_str})", open=True)
        self.item_map[node_id] = group
        if group.Group:
            for subgroup in group.Group:
                self._add_group_to_tree(node_id, subgroup)
        if group.Rule:
            for rule in group.Rule:
                self._add_rule_to_tree(node_id, rule)

    def _add_rule_to_tree(self, parent_node, rule):
        title_text = rule.title[0].get_valueOf_() if rule.title else ""
        node_id = self.tree.insert(parent_node, "end", text=f"Rule: {title_text} ({rule.id})")
        self.item_map[node_id] = rule

    def populate_fact_refs_tree(self):
        if not self.fact_refs_tree or not self.selected_platform_obj: return
        for i in self.fact_refs_tree.get_children(): self.fact_refs_tree.delete(i)
        logical_test = self.selected_platform_obj.logical_test
        if logical_test and logical_test.fact_ref:
            for fact in logical_test.fact_ref:
                self.fact_refs_tree.insert("", "end", values=(fact.get_name(),))

    def show_move_dialog(self):
        selected_id = self.tree.focus()
        if not selected_id: return
        item_to_move = self.item_map.get(selected_id)
        if not isinstance(item_to_move, (xccdf_models.groupType, xccdf_models.ruleType)): return

        dialog = tk.Toplevel(self.root)
        dialog.title("Move Item")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        
        ttk.Label(dialog, text=f"Select a new parent for '{item_to_move.get_id()}'").pack(pady=10)
        
        listbox_frame = ttk.Frame(dialog)
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        listbox = tk.Listbox(listbox_frame, selectmode=tk.SINGLE)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        listbox.config(yscrollcommand=scrollbar.set)
        
        def get_descendants(item):
            descendants = {item}
            if isinstance(item, xccdf_models.groupType) and item.Group:
                for child_group in item.Group:
                    descendants.update(get_descendants(child_group))
            return descendants

        items_to_exclude = get_descendants(item_to_move)
        
        possible_parents = []
        def collect_parents_recursive(parent_candidate):
            if parent_candidate not in items_to_exclude:
                possible_parents.append(parent_candidate)
            
            if hasattr(parent_candidate, 'Group') and parent_candidate.Group:
                for subgroup in parent_candidate.Group:
                    collect_parents_recursive(subgroup)
        
        collect_parents_recursive(self.get_benchmark())

        for parent in possible_parents:
            if isinstance(parent, xccdf_models.Benchmark):
                title = parent.title[0].get_valueOf_() if parent.title else ""
                listbox.insert(tk.END, f"Benchmark: {title}")
            else:
                title = parent.title[0].get_valueOf_() if parent.title else ""
                listbox.insert(tk.END, f"  Group: {parent.get_id()} ({title})")
        
        def on_ok():
            selected_indices = listbox.curselection()
            if not selected_indices:
                dialog.destroy()
                return
            
            new_parent_obj = possible_parents[selected_indices[0]]
            old_parent_obj = self.find_parent(self.datastream_collection, item_to_move)

            if new_parent_obj is old_parent_obj:
                dialog.destroy()
                return

            if isinstance(item_to_move, xccdf_models.ruleType) and isinstance(new_parent_obj, xccdf_models.Benchmark):
                messagebox.showerror("Invalid Move", "Rules cannot be moved directly under a Benchmark.")
                dialog.destroy()
                return

            if isinstance(item_to_move, xccdf_models.groupType):
                old_parent_obj.Group.remove(item_to_move)
            else:
                old_parent_obj.Rule.remove(item_to_move)
            
            if isinstance(item_to_move, xccdf_models.groupType):
                if new_parent_obj.Group is None: new_parent_obj.Group = []
                new_parent_obj.Group.append(item_to_move)
            else:
                if new_parent_obj.Rule is None: new_parent_obj.Rule = []
                new_parent_obj.Rule.append(item_to_move)

            self.populate_treeview()
            dialog.destroy()

        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT)

    def create_text_editor(self, parent_frame, label_text, data_obj, attr_name, height=1):
        ttk.Label(parent_frame, text=label_text, width=15).pack(anchor='w', pady=(5, 0))
        text_class = xccdf_models.htmlTextWithSubType
        if attr_name in ['title', 'rationale', 'fixtext']:
            text_class = xccdf_models.textWithSubType if attr_name == 'title' else xccdf_models.htmlTextWithSubType
        text_widget = tk.Text(parent_frame, height=height, wrap="word")
        text_widget.pack(fill=tk.X, expand=True)
        text_obj_list = getattr(data_obj, attr_name, [])
        if text_obj_list:
            text_widget.insert("1.0", text_obj_list[0].get_valueOf_() or "")
        def update_text_content(event):
            current_list = getattr(data_obj, attr_name, [])
            if not current_list:
                new_text_obj = text_class()
                setattr(data_obj, attr_name, [new_text_obj])
                current_list = [new_text_obj]
            current_list[0].set_valueOf_(text_widget.get("1.0", "end-1c"))
            if attr_name == 'title':
                self.populate_treeview()
        text_widget.bind("<KeyRelease>", update_text_content)

    def create_profile_selection_editor(self, profile_obj):
        editor_frame = ttk.LabelFrame(self.detail_frame, text="Profile Selections", padding=5)
        editor_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        pw = ttk.PanedWindow(editor_frame, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True)
        available_frame = ttk.Frame(pw, padding=2)
        button_frame = ttk.Frame(pw, padding=5)
        selected_frame = ttk.Frame(pw, padding=2)
        pw.add(available_frame, weight=2)
        pw.add(button_frame, weight=0)
        pw.add(selected_frame, weight=2)
        ttk.Label(available_frame, text="Available Items").pack()
        available_tree = ttk.Treeview(available_frame)
        available_tree.pack(fill=tk.BOTH, expand=True)
        ttk.Label(selected_frame, text="Profile Selections").pack()
        selected_tree = ttk.Treeview(selected_frame, columns=("status",), show="tree headings")
        selected_tree.heading("status", text="Status")
        selected_tree.column("status", width=80, anchor='center')
        selected_tree.pack(fill=tk.BOTH, expand=True)
        
        benchmark_obj = self.get_benchmark()

        def get_all_item_ids(groups):
            ids = {}
            def recurse(items):
                for item in items:
                    if isinstance(item, (xccdf_models.groupType, xccdf_models.ruleType)):
                        ids[item.get_id()] = item
                        if isinstance(item, xccdf_models.groupType) and item.Group:
                            recurse(item.Group)
                        if isinstance(item, xccdf_models.groupType) and item.Rule:
                            recurse(item.Rule)
            recurse(groups)
            return ids
        all_benchmark_items = get_all_item_ids(benchmark_obj.Group)
        
        def populate_trees():
            for i in available_tree.get_children(): available_tree.delete(i)
            for i in selected_tree.get_children(): selected_tree.delete(i)
            selected_idrefs = {s.get_idref() for s in profile_obj.select}
            def populate_available_recursively(parent_node, items):
                for item in items:
                    if item.get_id() not in selected_idrefs:
                        title = item.title[0].get_valueOf_() if item.title else ""
                        node_id = available_tree.insert(parent_node, "end", text=f"{item.get_id()}: {title}", open=False, values=[item.get_id()])
                        if isinstance(item, xccdf_models.groupType) and item.Group:
                            populate_available_recursively(node_id, item.Group)
                        if isinstance(item, xccdf_models.groupType) and item.Rule:
                             populate_available_recursively(node_id, item.Rule)
            populate_available_recursively("", benchmark_obj.Group)
            for selection in profile_obj.select:
                idref = selection.get_idref()
                status_str = "[+] Selected" if selection.get_selected() else "[-] Unselected"
                item_obj = all_benchmark_items.get(idref)
                title = item_obj.title[0].get_valueOf_() if item_obj and item_obj.title else ""
                selected_tree.insert("", "end", text=f"{idref}: {title}", values=(status_str,))
        
        def move_item(is_selected_bool):
            selected_id = available_tree.focus()
            if not selected_id: return
            idref = available_tree.item(selected_id)['values'][0]
            if profile_obj.select is None: profile_obj.select = []
            profile_obj.select.append(xccdf_models.profileSelectType(idref=idref, selected=is_selected_bool))
            populate_trees()
        
        def remove_selection():
            selected_in_profile = selected_tree.focus()
            if not selected_in_profile: return
            full_text = selected_tree.item(selected_in_profile)['text']
            idref_to_remove = full_text.split(':')[0]
            if profile_obj.select:
                profile_obj.select = [s for s in profile_obj.select if s.get_idref() != idref_to_remove]
            populate_trees()
        
        ttk.Button(button_frame, text="Select >>", command=lambda: move_item(True)).pack(pady=5)
        ttk.Button(button_frame, text="Unselect >>", command=lambda: move_item(False)).pack(pady=5)
        ttk.Button(button_frame, text="<< Remove", command=remove_selection).pack(pady=20)
        
        populate_trees()

    def get_benchmark(self):
        if self.datastream_collection:
            try:
                for comp in self.datastream_collection.get_component():
                    if comp.Benchmark:
                        return comp.Benchmark
            except (IndexError, AttributeError):
                return None
        return None

    def create_item_platform_manager(self, parent_frame, item_data):
        manager_frame = ttk.LabelFrame(parent_frame, text="Applicable Platforms", padding=5)
        manager_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        benchmark_obj = self.get_benchmark()
        platform_ids = set()
        if benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
            for p in benchmark_obj.platform_specification.platform:
                if p.logical_test and p.logical_test.fact_ref:
                    cpe_name = p.logical_test.fact_ref[0].get_name()
                    if cpe_name:
                        platform_ids.add(cpe_name)
        if benchmark_obj.platform:
             for p_ref in benchmark_obj.platform:
                 platform_ids.add(p_ref.get_idref())
        available_platforms = sorted(list(platform_ids))
        
        add_frame = ttk.Frame(manager_frame)
        add_frame.pack(fill=tk.X, pady=2)
        platform_combo = ttk.Combobox(add_frame, values=available_platforms, state="readonly")
        platform_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        list_frame = ttk.Frame(manager_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        platform_listbox = tk.Listbox(list_frame, height=4)
        platform_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        def populate_platform_references_list():
            platform_listbox.delete(0, tk.END)
            if item_data.platform:
                for p_ref in item_data.platform:
                    platform_listbox.insert(tk.END, p_ref.get_idref())
        def add_platform_ref():
            selected_id = platform_combo.get()
            if not selected_id: return
            if item_data.platform and any(p.get_idref() == selected_id for p in item_data.platform):
                return
            if item_data.platform is None:
                item_data.platform = []
            item_data.platform.append(xccdf_models.overrideableCPE2idrefType(idref=selected_id))
            populate_platform_references_list()
        def remove_platform_ref():
            selected_indices = platform_listbox.curselection()
            if not selected_indices: return
            selected_idref = platform_listbox.get(selected_indices[0])
            if item_data.platform:
                item_data.platform = [p for p in item_data.platform if p.get_idref() != selected_idref]
            populate_platform_references_list()
        ttk.Button(add_frame, text="Add", command=add_platform_ref).pack(side=tk.LEFT, padx=5)
        ttk.Button(list_frame, text="Remove", command=remove_platform_ref).pack(side=tk.LEFT, padx=5, anchor='n')
        populate_platform_references_list()

    def on_platform_select(self, event):
        selected_item = self.platforms_tree.focus()
        if not selected_item:
            self.selected_platform_obj = None
            return
        platform_id = self.platforms_tree.item(selected_item)['values'][0]
        benchmark_obj = self.get_benchmark()
        if benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
            for p in benchmark_obj.platform_specification.platform:
                if p.get_id() == platform_id:
                    self.selected_platform_obj = p
                    self.display_logical_test_details()
                    return 

    def display_logical_test_details(self):
        for widget in self.logical_test_editor_frame.winfo_children():
            widget.destroy()
        if not self.selected_platform_obj:
            return
        editor_frame = ttk.LabelFrame(self.logical_test_editor_frame, text=f"Logical Test for '{self.selected_platform_obj.get_id()}'", padding=5)
        editor_frame.pack(fill=tk.BOTH, expand=True)
        if self.selected_platform_obj.logical_test is None:
             self.selected_platform_obj.logical_test = xccdf_models.LogicalTestType(operator='AND', negate=False)
        logical_test = self.selected_platform_obj.logical_test
        top_frame = ttk.Frame(editor_frame)
        top_frame.pack(fill=tk.X, pady=2)
        ttk.Label(top_frame, text="Operator:").pack(side=tk.LEFT)
        op_var = tk.StringVar(value=logical_test.get_operator())
        op_combo = ttk.Combobox(top_frame, textvariable=op_var, values=["AND", "OR"], width=5)
        op_combo.pack(side=tk.LEFT, padx=5)
        def set_operator(event):
            logical_test.set_operator(op_var.get())
        op_combo.bind("<<ComboboxSelected>>", set_operator)
        negate_var = tk.BooleanVar(value=logical_test.get_negate())
        negate_check = ttk.Checkbutton(top_frame, text="Negate", variable=negate_var, command=lambda: logical_test.set_negate(negate_var.get()))
        negate_check.pack(side=tk.LEFT, padx=10)
        self.fact_refs_tree = ttk.Treeview(editor_frame, columns=("cpe",), show="headings", height=3)
        self.fact_refs_tree.heading("cpe", text="CPE Name (fact-ref)")
        self.fact_refs_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.populate_fact_refs_tree()
        fact_button_frame = ttk.Frame(editor_frame)
        fact_button_frame.pack(fill=tk.X)
        ttk.Button(fact_button_frame, text="Add CPE", command=self.add_fact_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(fact_button_frame, text="Edit CPE", command=self.edit_fact_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(fact_button_frame, text="Remove CPE", command=self.remove_fact_ref).pack(side=tk.LEFT, padx=2)

    def populate_platforms_tree(self):
        if not self.platforms_tree: return
        for i in self.platforms_tree.get_children(): self.platforms_tree.delete(i)
        benchmark_obj = self.get_benchmark()
        if benchmark_obj and benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
            for platform in benchmark_obj.platform_specification.platform:
                self.platforms_tree.insert("", "end", values=(platform.get_id(),))

    def add_platform(self):
        benchmark_obj = self.get_benchmark()
        if not benchmark_obj: return
        new_id = simpledialog.askstring("Add Platform", "Enter new platform ID:", parent=self.root)
        if new_id:
            if benchmark_obj.platform_specification is None:
                benchmark_obj.platform_specification = xccdf_models.platformSpecificationType()
            if benchmark_obj.platform_specification.platform is None:
                 benchmark_obj.platform_specification.platform = []
            new_platform = xccdf_models.PlatformType(id=new_id)
            benchmark_obj.platform_specification.platform.append(new_platform)
            self.populate_platforms_tree()

    def edit_platform(self):
        selected_item = self.platforms_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a platform to edit.")
            return
        current_id = self.platforms_tree.item(selected_item)['values'][0]
        new_id = simpledialog.askstring("Edit Platform", "Edit platform ID:", initialvalue=current_id, parent=self.root)
        if new_id and new_id != current_id:
            benchmark_obj = self.get_benchmark()
            if benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
                for platform in benchmark_obj.platform_specification.platform:
                    if platform.get_id() == current_id:
                        platform.set_id(new_id)
                        break
            self.populate_platforms_tree()

    def remove_platform(self):
        selected_item = self.platforms_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a platform to remove.")
            return
        id_to_remove = self.platforms_tree.item(selected_item)['values'][0]
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to remove platform '{id_to_remove}'?"):
            benchmark_obj = self.get_benchmark()
            if benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
                benchmark_obj.platform_specification.platform = [p for p in benchmark_obj.platform_specification.platform if p.get_id() != id_to_remove]
            self.populate_platforms_tree()

    def add_fact_ref(self):
        if not self.selected_platform_obj: return
        new_cpe = simpledialog.askstring("Add CPE", "Enter new CPE name:", parent=self.root)
        if new_cpe:
            logical_test = self.selected_platform_obj.logical_test
            if logical_test.fact_ref is None:
                logical_test.fact_ref = []
            logical_test.fact_ref.append(xccdf_models.CPEFactRefType(name=new_cpe))
            self.populate_fact_refs_tree()

    def edit_fact_ref(self):
        if not self.fact_refs_tree or not self.selected_platform_obj: return
        selected_item = self.fact_refs_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a CPE to edit.")
            return
        current_cpe = self.fact_refs_tree.item(selected_item)['values'][0]
        new_cpe = simpledialog.askstring("Edit CPE", "Edit CPE name:", initialvalue=current_cpe, parent=self.root)
        if new_cpe and new_cpe != current_cpe:
            logical_test = self.selected_platform_obj.logical_test
            if logical_test and logical_test.fact_ref:
                for fact in logical_test.fact_ref:
                    if fact.get_name() == current_cpe:
                        fact.set_name(new_cpe)
                        break
            self.populate_fact_refs_tree()
            
    def remove_fact_ref(self):
        if not self.fact_refs_tree or not self.selected_platform_obj: return
        selected_item = self.fact_refs_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a CPE to remove.")
            return
        cpe_to_remove = self.fact_refs_tree.item(selected_item)['values'][0]
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to remove CPE '{cpe_to_remove}'?"):
            logical_test = self.selected_platform_obj.logical_test
            if logical_test and logical_test.fact_ref:
                logical_test.fact_ref = [f for f in logical_test.fact_ref if f.get_name() != cpe_to_remove]
            self.populate_fact_refs_tree()
 
##--  [  CPE Manager UI & Commands ]---
    def display_cpe_dictionary_manager(self, cpe_list_obj):
        """Creates the UI for managing CPE items within a CPE Dictionary."""
        self.cpe_item_map = {}
        manager_frame = ttk.LabelFrame(self.detail_frame, text="Manage CPE Items", padding=5)
        manager_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # --- Treeview to display CPE items ---
        tree_frame = ttk.Frame(manager_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.cpe_items_tree = ttk.Treeview(tree_frame, columns=("name", "title", "def_id", "check"), show="headings")
        self.cpe_items_tree.heading("name", text="Name (CPE URI)")
        self.cpe_items_tree.heading("title", text="Title")
        self.cpe_items_tree.heading("def_id", text="OVAL Definition ID")
        self.cpe_items_tree.heading("check", text="Check Href")
        self.cpe_items_tree.column("def_id", width=250) # Set a default width
        self.cpe_items_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.cpe_items_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.cpe_items_tree.config(yscrollcommand=scrollbar.set)

        self.populate_cpe_tree(cpe_list_obj)

        # --- Buttons for Add/Edit/Remove ---
        button_frame = ttk.Frame(manager_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Add Item...", command=lambda: self.add_cpe_item(cpe_list_obj)).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Edit Item...", command=lambda: self.edit_cpe_item(cpe_list_obj)).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Remove Selected", command=lambda: self.remove_cpe_item(cpe_list_obj)).pack(side=tk.LEFT, padx=2)

    def populate_cpe_tree(self, cpe_list_obj):
        """Clears and repopulates the CPE items treeview."""
        for i in self.cpe_items_tree.get_children():
            self.cpe_items_tree.delete(i)
        self.cpe_item_map.clear()
        
        if cpe_list_obj and cpe_list_obj.get_cpe_item():
            for cpe_item in cpe_list_obj.get_cpe_item():
                name = cpe_item.get_name()
                title = cpe_item.get_title()[0].get_valueOf_() if cpe_item.get_title() else ""
                
                # --- Extract both the href and the OVAL Definition ID (the content)
                check_href = ""
                oval_def_id = ""
                if cpe_item.get_check():
                    check_href = cpe_item.get_check()[0].get_href()
                    oval_def_id = cpe_item.get_check()[0].get_valueOf_()
                
                # --- Add the new oval_def_id to the values tuple
                item_id = self.cpe_items_tree.insert("", "end", values=(name, title, oval_def_id, check_href))
                self.cpe_item_map[item_id] = cpe_item

    def _show_cpe_item_dialog(self, item_to_edit=None):
        """Shows a dialog to add or edit a CPE item. Returns a dict of values or None."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Edit CPE Item" if item_to_edit else "Add CPE Item")
        dialog.geometry("600x250")

        results = {}

        # --- Fields ---
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Name (CPE URI):").grid(row=0, column=0, sticky="w", pady=2)
        name_var = tk.StringVar(value=item_to_edit.get_name() if item_to_edit else "")
        ttk.Entry(main_frame, textvariable=name_var, width=60).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(main_frame, text="Title:").grid(row=1, column=0, sticky="w", pady=2)
        title_var = tk.StringVar(value=item_to_edit.get_title()[0].get_valueOf_() if item_to_edit and item_to_edit.get_title() else "")
        ttk.Entry(main_frame, textvariable=title_var).grid(row=1, column=1, sticky="ew", pady=2)
        
        # 1. OVAL Component Selector
        oval_components = self.get_oval_components()
        ttk.Label(main_frame, text="Check Component:").grid(row=2, column=0, sticky="w", pady=2)
        component_var = tk.StringVar()
        component_combo = ttk.Combobox(main_frame, textvariable=component_var, values=sorted(oval_components.keys()), state="readonly")
        component_combo.grid(row=2, column=1, sticky="ew", pady=2)

        # 2. OVAL Definition Selector
        ttk.Label(main_frame, text="Check Definition ID:").grid(row=3, column=0, sticky="w", pady=2)
        definition_var = tk.StringVar()
        definition_combo = ttk.Combobox(main_frame, textvariable=definition_var, state="readonly")
        definition_combo.grid(row=3, column=1, sticky="ew", pady=2)

        def on_component_select(event):
            """When a component is selected, populate the definitions dropdown."""
            selected_comp_id = component_var.get()
            component_obj = oval_components.get(selected_comp_id)
            if component_obj:
                oval_defs = component_obj.oval_definitions
                def_ids = []
                if oval_defs.get_definitions():
                    for definition in oval_defs.get_definitions().get_definition():
                        def_ids.append(definition.get_id())
                definition_combo['values'] = sorted(def_ids)
                if def_ids:
                    definition_var.set(def_ids[0])
            else:
                definition_combo['values'] = []
                definition_var.set("")
        
        component_combo.bind("<<ComboboxSelected>>", on_component_select)

        # --- Pre-fill values if editing
        if item_to_edit and item_to_edit.get_check():
            check_obj = item_to_edit.get_check()[0]
            component_var.set(check_obj.get_href().lstrip('#'))
            on_component_select(None) # Trigger the event to populate definitions
            definition_var.set(check_obj.get_valueOf_())

        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            if not name_var.get():
                messagebox.showwarning("Input Error", "Name (CPE URI) cannot be empty.", parent=dialog)
                return
            
            results['name'] = name_var.get()
            results['title'] = title_var.get()
            # --- Save both the component ID and the definition ID
            results['check_component_id'] = component_var.get()
            results['check_definition_id'] = definition_var.get()
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=10)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'name' in results else None

    def add_cpe_item(self, cpe_list_obj):
        """Handles adding a new CPE item."""
        # --- dialog gets both component and definition IDs
        data = self._show_cpe_item_dialog()
        if data:
            new_item = cpe_dictionary_models.ItemType(name=data['name'])
            new_item.add_title(cpe_dictionary_models.TextType(valueOf_=data['title']))

            # --- Use data keys to build the check element
            if data.get('check_component_id') and data.get('check_definition_id'):
                # --- Get the correct name for the href attribute from the catalog
                href_name = self.get_cpe_oval_catalog_name()

                check = cpe_dictionary_models.CheckType(
                    system="http://oval.mitre.org/XMLSchema/oval-definitions-5",
                    href=href_name,
                    valueOf_=data['check_definition_id']
                )
                new_item.add_check(check)
            
            cpe_list_obj.add_cpe_item(new_item)
            self.populate_cpe_tree(cpe_list_obj)

    def edit_cpe_item(self, cpe_list_obj):
        """Handles editing an existing CPE item."""
        selected_id = self.cpe_items_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a CPE item to edit.")
            return
        
        item_to_edit = self.cpe_item_map[selected_id]
        data = self._show_cpe_item_dialog(item_to_edit)

        if data:
            item_to_edit.set_name(data['name'])
            
            if item_to_edit.get_title():
                item_to_edit.get_title()[0].set_valueOf_(data['title'])
            else:
                item_to_edit.add_title(cpe_dictionary_models.TextType(valueOf_=data['title']))

            if data.get('check_component_id') and data.get('check_definition_id'):
                href_name = self.get_cpe_oval_catalog_name()
                check_obj = item_to_edit.get_check()[0] if item_to_edit.get_check() else None
                if not check_obj:
                    check_obj = cpe_dictionary_models.CheckType(system="http://oval.mitre.org/XMLSchema/oval-definitions-5")
                    item_to_edit.add_check(check_obj)
                
                check_obj.set_href(href_name)
                check_obj.set_valueOf_(data['check_definition_id'])
            else:
                # --- Clear the check if the fields were emptied in the dialog
                item_to_edit.set_check([]) 
            
            self.populate_cpe_tree(cpe_list_obj)

    def remove_cpe_item(self, cpe_list_obj):
        """Handles removing a selected CPE item."""
        selected_id = self.cpe_items_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a CPE item to remove.")
            return
        
        item_to_remove = self.cpe_item_map[selected_id]
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the CPE item '{item_to_remove.get_name()}'?"):
            cpe_list_obj.get_cpe_item().remove(item_to_remove)
            self.populate_cpe_tree(cpe_list_obj)

    def _create_component_ref(self, ref_id, component_id_href, create_catalog=True):
        """Creates a component-ref object, with an optional catalog."""
        comp_ref = datastream_models.component_ref(id=ref_id, href=component_id_href)
        if create_catalog:
            catalog_uri = datastream_models.uri(name=ref_id, uri=component_id_href)
            comp_ref.set_catalog(datastream_models.catalog(uri=[catalog_uri]))
        return comp_ref

    def get_cpe_oval_catalog_name(self):
        """Finds the 'name' attribute from the catalog URI within the dictionary's component-ref."""
        if not self.datastream_collection:
            return None
        try:
            ds = self.datastream_collection.get_data_stream()[0]
            if ds.get_dictionaries() and ds.get_dictionaries().get_component_ref():
                comp_ref = ds.get_dictionaries().get_component_ref()[0]
                if comp_ref.get_catalog() and comp_ref.get_catalog().get_uri():
                    return comp_ref.get_catalog().get_uri()[0].get_name()
        except (IndexError, AttributeError):
            return None
        return None


##--  [  OVAL Manager UI & Commands ]---
    def display_oval_manager(self, oval_defs_obj):
        """Creates the tabbed UI for managing OVAL components."""
        self.current_oval_defs = oval_defs_obj 
        self.oval_definition_map = {}
        self.oval_criteria_map = {}
        self.oval_tests_map = {}
        self.oval_objects_map = {}
        self.oval_states_map = {}
        
        generator = oval_defs_obj.get_generator()
        if generator is None:
            sv = oval.SchemaVersionType(valueOf_="5.11")
            generator = oval.GeneratorType(product_name="SPECTRE", product_version="1.0", schema_version=[sv], timestamp=datetime.now())
            oval_defs_obj.set_generator(generator)
        else:
            generator.set_product_name("SPECTRE")
                
                
        notebook = ttk.Notebook(self.detail_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10, padx=5)

        # --- Create the General Tab (and add it first) ---
        gen_frame = ttk.Frame(notebook, padding=10)
        notebook.add(gen_frame, text="General")

        # --- Product Name (read-only)
        ttk.Label(gen_frame, text="Product Name:").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Label(gen_frame, text=generator.get_product_name()).grid(row=0, column=1, sticky="w", pady=3)

        # --- Product Version (editable)
        ttk.Label(gen_frame, text="Product Version:").grid(row=1, column=0, sticky="w", pady=3)
        version_var = tk.StringVar(value=generator.get_product_version())
        ttk.Entry(gen_frame, textvariable=version_var).grid(row=1, column=1, sticky="ew", pady=3)

        # --- Schema Version (editable)
        schema_version_str = generator.get_schema_version()[0].get_valueOf_() if generator.get_schema_version() else "5.11"
        ttk.Label(gen_frame, text="Schema Version:").grid(row=2, column=0, sticky="w", pady=3)
        schema_version_var = tk.StringVar(value=schema_version_str)
        ttk.Entry(gen_frame, textvariable=schema_version_var).grid(row=2, column=1, sticky="ew", pady=3)
        
        gen_frame.columnconfigure(1, weight=1)
        
        # --- Trace changes to the editable fields and call the update helper
        version_var.trace_add("write", lambda *args: self._update_oval_generator(generator, version_var, schema_version_var, *args))
        schema_version_var.trace_add("write", lambda *args: self._update_oval_generator(generator, version_var, schema_version_var, *args))

        # --- Create the Definitions Tab ---
        def_frame = ttk.Frame(notebook)
        notebook.add(def_frame, text="Definitions")
        
        paned_window = ttk.PanedWindow(def_frame, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        defs_list_frame = ttk.Frame(paned_window, padding=5)
        self.oval_defs_tree = ttk.Treeview(defs_list_frame, columns=("id", "version", "class", "title"), show="headings")
        self.oval_defs_tree.heading("id", text="ID")
        self.oval_defs_tree.heading("version", text="Version")
        self.oval_defs_tree.heading("class", text="Class")
        self.oval_defs_tree.heading("title", text="Title")
        self.oval_defs_tree.column("id", width=250)
        self.oval_defs_tree.column("version", width=50)
        self.oval_defs_tree.column("class", width=100)
        self.oval_defs_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.populate_oval_definitions_tree(oval_defs_obj)

        button_frame = ttk.Frame(defs_list_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Add Definition...", command=lambda: self.add_oval_definition(oval_defs_obj)).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Edit Definition...", command=lambda: self.edit_oval_definition(oval_defs_obj)).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Remove Selected", command=lambda: self.remove_oval_definition(oval_defs_obj)).pack(side=tk.LEFT, padx=2)
        paned_window.add(defs_list_frame)

        criteria_editor_frame = ttk.LabelFrame(paned_window, text="Criteria Editor", padding=5)
        self.oval_criteria_tree = ttk.Treeview(criteria_editor_frame)
        self.oval_criteria_tree.pack(fill=tk.BOTH, expand=True, pady=5)

        crit_button_frame = ttk.Frame(criteria_editor_frame)
        crit_button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(crit_button_frame, text="Add Criteria...", command=self.add_oval_criteria).pack(side=tk.LEFT, padx=2)
        ttk.Button(crit_button_frame, text="Add Criterion...", command=self.add_oval_criterion).pack(side=tk.LEFT, padx=2)
        ttk.Button(crit_button_frame, text="Add Extended Def...", command=self.add_oval_extended_definition).pack(side=tk.LEFT, padx=2)
        ttk.Button(crit_button_frame, text="Edit Selected...", command=self.edit_oval_criteria_item).pack(side=tk.LEFT, padx=2)
        ttk.Button(crit_button_frame, text="Remove Selected", command=self.remove_oval_criteria_item).pack(side=tk.LEFT, padx=2)
        paned_window.add(criteria_editor_frame)

        self.oval_defs_tree.bind("<<TreeviewSelect>>", self.on_oval_definition_select)

        # --- Tests Tab ---
        tests_frame = ttk.Frame(notebook)
        notebook.add(tests_frame, text="Tests")
        self.oval_tests_tree = ttk.Treeview(tests_frame, columns=("id", "type", "comment"), show="headings")
        self.oval_tests_tree.heading("id", text="ID"); self.oval_tests_tree.heading("type", text="Test Type"); self.oval_tests_tree.heading("comment", text="Comment")
        self.oval_tests_tree.column("id", width=250); self.oval_tests_tree.column("type", width=150)
        self.oval_tests_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.populate_oval_tests_tree(oval_defs_obj)
        test_button_frame = ttk.Frame(tests_frame)
        test_button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(test_button_frame, text="Add Test...", command=lambda: self.add_oval_entity(oval_defs_obj, 'test')).pack(side=tk.LEFT, padx=2)
        ttk.Button(test_button_frame, text="Edit Selected...", command=lambda: self.edit_oval_entity(oval_defs_obj, 'test')).pack(side=tk.LEFT, padx=2)
        ttk.Button(test_button_frame, text="Remove Selected", command=lambda: self.remove_oval_entity(oval_defs_obj, 'test')).pack(side=tk.LEFT, padx=2)
        
        # --- Objects Tab ---
        objects_frame = ttk.Frame(notebook)
        notebook.add(objects_frame, text="Objects")
        self.oval_objects_tree = ttk.Treeview(objects_frame, columns=("id", "type", "comment"), show="headings")
        self.oval_objects_tree.heading("id", text="ID"); self.oval_objects_tree.heading("type", text="Object Type"); self.oval_objects_tree.heading("comment", text="Comment")
        self.oval_objects_tree.column("id", width=250); self.oval_objects_tree.column("type", width=150)
        self.oval_objects_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.populate_oval_objects_tree(oval_defs_obj)
        obj_button_frame = ttk.Frame(objects_frame)
        obj_button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(obj_button_frame, text="Add Object...", command=lambda: self.add_oval_entity(oval_defs_obj, 'object')).pack(side=tk.LEFT, padx=2)
        ttk.Button(obj_button_frame, text="Edit Selected...", command=lambda: self.edit_oval_entity(oval_defs_obj, 'object')).pack(side=tk.LEFT, padx=2)
        ttk.Button(obj_button_frame, text="Remove Selected", command=lambda: self.remove_oval_entity(oval_defs_obj, 'object')).pack(side=tk.LEFT, padx=2)

        # --- States Tab ---
        states_frame = ttk.Frame(notebook)
        notebook.add(states_frame, text="States")
        self.oval_states_tree = ttk.Treeview(states_frame, columns=("id", "type", "comment"), show="headings")
        self.oval_states_tree.heading("id", text="ID")
        self.oval_states_tree.heading("type", text="State Type")
        self.oval_states_tree.heading("comment", text="Comment")
        self.oval_states_tree.column("id", width=250)
        self.oval_states_tree.column("type", width=150)
        self.oval_states_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.populate_oval_states_tree(oval_defs_obj)

        st_button_frame = ttk.Frame(states_frame)
        st_button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(st_button_frame, text="Add State...", command=lambda: self.add_oval_entity(oval_defs_obj, 'state')).pack(side=tk.LEFT, padx=2)
        ttk.Button(st_button_frame, text="Edit Selected...", command=lambda: self.edit_oval_entity(oval_defs_obj, 'state')).pack(side=tk.LEFT, padx=2)
        ttk.Button(st_button_frame, text="Remove Selected", command=lambda: self.remove_oval_entity(oval_defs_obj, 'state')).pack(side=tk.LEFT, padx=2)

        # --- Variables Tab ---
        variables_frame = ttk.Frame(notebook)
        notebook.add(variables_frame, text="Variables")
        
        self.oval_variables_tree = ttk.Treeview(variables_frame, columns=("id", "type", "comment"), show="headings")
        self.oval_variables_tree.heading("id", text="ID")
        self.oval_variables_tree.heading("type", text="Variable Type")
        self.oval_variables_tree.heading("comment", text="Comment")
        self.oval_variables_tree.column("id", width=250)
        self.oval_variables_tree.column("type", width=150)
        self.oval_variables_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.populate_oval_variables_tree(oval_defs_obj) # We will create this method next

        var_button_frame = ttk.Frame(variables_frame)
        var_button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(var_button_frame, text="Add Variable...", command=lambda: self.add_oval_entity(oval_defs_obj, 'variable')).pack(side=tk.LEFT, padx=2)
        ttk.Button(var_button_frame, text="Edit Selected...", command=lambda: self.edit_oval_entity(oval_defs_obj, 'variable')).pack(side=tk.LEFT, padx=2)
        ttk.Button(var_button_frame, text="Remove Selected", command=lambda: self.remove_oval_entity(oval_defs_obj, 'variable')).pack(side=tk.LEFT, padx=2)
        
    def _update_oval_generator(self, generator_obj, version_var, schema_version_var, *args):
        """Callback to update the generator object when an entry is changed."""
        generator_obj.set_product_version(version_var.get())
        
        # --- Schema version is a list, so we update the first element
        if generator_obj.get_schema_version():
            generator_obj.get_schema_version()[0].set_valueOf_(schema_version_var.get())
        else: # Or create it if it doesn't exist
            sv = oval.SchemaVersionType(valueOf_=schema_version_var.get())
            generator_obj.set_schema_version([sv])

        # --- Update the timestamp automatically
        generator_obj.set_timestamp(datetime.now())
       
##--  [  OVAL Definitions ]---
    def populate_oval_definitions_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL definitions treeview."""
        for i in self.oval_defs_tree.get_children():
            self.oval_defs_tree.delete(i)
        self.oval_definition_map.clear()
        
        definitions_container = oval_defs_obj.get_definitions()
        if definitions_container and definitions_container.get_definition():
            for definition in definitions_container.get_definition():
                meta = definition.get_metadata()
                title = meta.get_title() if meta and meta.get_title() else ""
                
                item_id = self.oval_defs_tree.insert("", "end", values=(
                    definition.get_id(),
                    definition.get_version(),
                    definition.get_class(),
                    title
                ))
                self.oval_definition_map[item_id] = definition

    def _show_oval_definition_dialog(self, definition_to_edit=None):
        """Shows a dialog to add or edit an OVAL definition."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Edit OVAL Definition" if definition_to_edit else "Add OVAL Definition")
        dialog.geometry("550x250")

        results = {}
        
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="ID:").grid(row=0, column=0, sticky="w", pady=2)
        initial_id = f"oval:{self.prefix}:def:{random.randint(1000, 9999)}" if not definition_to_edit else definition_to_edit.get_id()
        id_var = tk.StringVar(value=initial_id)
        ttk.Entry(main_frame, textvariable=id_var).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(main_frame, text="Version:").grid(row=1, column=0, sticky="w", pady=2)
        version_var = tk.StringVar(value="1" if not definition_to_edit else str(definition_to_edit.get_version()))
        ttk.Entry(main_frame, textvariable=version_var).grid(row=1, column=1, sticky="ew", pady=2)

        ttk.Label(main_frame, text="Class:").grid(row=2, column=0, sticky="w", pady=2)
        class_options = ['compliance', 'inventory', 'miscellaneous', 'patch', 'vulnerability']
        class_var = tk.StringVar(value=definition_to_edit.get_class() if definition_to_edit else "compliance")
        ttk.Combobox(main_frame, textvariable=class_var, values=class_options, state="readonly").grid(row=2, column=1, sticky="ew", pady=2)
        
        meta = definition_to_edit.get_metadata() if definition_to_edit else None
        
        ttk.Label(main_frame, text="Title:").grid(row=3, column=0, sticky="w", pady=2)
        title_var = tk.StringVar(value=meta.get_title() if meta and meta.get_title() else "")
        ttk.Entry(main_frame, textvariable=title_var).grid(row=3, column=1, sticky="ew", pady=2)
        
        ttk.Label(main_frame, text="Description:").grid(row=4, column=0, sticky="nw", pady=2)
        desc_text = tk.Text(main_frame, height=4, width=40)
        desc_text.grid(row=4, column=1, sticky="ew", pady=2)
        if meta and meta.get_description():
            desc_text.insert("1.0", meta.get_description())

        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            results['id'] = id_var.get()
            results['version'] = version_var.get()
            results['class'] = class_var.get()
            results['title'] = title_var.get()
            results['description'] = desc_text.get("1.0", "end-1c")
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=10)
        button_frame.pack(fill=tk.X)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'id' in results else None

    def add_oval_definition(self, oval_defs_obj):
        """Handles adding a new OVAL definition."""
        data = self._show_oval_definition_dialog()
        if data:
            if not oval_defs_obj.get_definitions():
                oval_defs_obj.set_definitions(oval.DefinitionsType())
            
            new_def = oval.DefinitionType(
                id=data['id'],
                version=data['version'],
                class_=data['class'],
                metadata=oval.MetadataType(
                    title=data['title'],
                    description=data['description']
                ),
                criteria=oval.CriteriaType()
            )
            oval_defs_obj.get_definitions().add_definition(new_def)
            self.populate_oval_definitions_tree(oval_defs_obj)
    
    def edit_oval_definition(self, oval_defs_obj):
        """Handles editing an existing OVAL definition."""
        selected_id = self.oval_defs_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a definition to edit.")
            return
        
        def_to_edit = self.oval_definition_map[selected_id]
        data = self._show_oval_definition_dialog(def_to_edit)
        
        if data:
            def_to_edit.set_id(data['id'])
            def_to_edit.set_version(data['version'])
            def_to_edit.set_class(data['class'])
            
            meta = def_to_edit.get_metadata()
            if not meta:
                meta = oval.MetadataType()
                def_to_edit.set_metadata(meta)
            
            meta.set_title(data['title'])
            meta.set_description(data['description'])
            
            self.populate_oval_definitions_tree(oval_defs_obj)

    def remove_oval_definition(self, oval_defs_obj):
        """Handles removing a selected OVAL definition."""
        selected_id = self.oval_defs_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a definition to remove.")
            return

        def_to_remove = self.oval_definition_map[selected_id]
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the definition '{def_to_remove.get_id()}'?"):
            oval_defs_obj.get_definitions().get_definition().remove(def_to_remove)
            self.populate_oval_definitions_tree(oval_defs_obj)

    def on_oval_definition_select(self, event):
        """Callback for when a definition is selected in the OVAL manager."""
        for i in self.oval_criteria_tree.get_children():
            self.oval_criteria_tree.delete(i)
        self.oval_criteria_map.clear()
        
        selected_id = self.oval_defs_tree.focus()
        if not selected_id:
            return
            
        definition_obj = self.oval_definition_map.get(selected_id)
        if definition_obj and definition_obj.get_criteria():
            self._populate_oval_criteria_tree("", definition_obj.get_criteria())

    def get_oval_test_ids(self):
        """Returns a list of all OVAL test IDs."""
        if not self.datastream_collection or not self.oval_tests_map:
            return []
        return [test.get_id() for test in self.oval_tests_map.values()]
      
##--  [  OVAL Criteria ]---
    def _populate_oval_criteria_tree(self, parent_id, criteria_node):
        """Recursively populates the criteria treeview."""
        if criteria_node is None:
            return

        node_text = ""
        node_obj = None
        
        # --- Add (Negated) to the display text if the negate attribute is true
        negate_text = " (Negated)" if criteria_node.get_negate() else ""

        if isinstance(criteria_node, oval.CriteriaType):
            node_text = f"Criteria (Operator: {criteria_node.get_operator()}){negate_text}"
            node_obj = criteria_node
            
            new_parent_id = self.oval_criteria_tree.insert(parent_id, "end", text=node_text, open=True)
            self.oval_criteria_map[new_parent_id] = node_obj
            
            for child_criteria in criteria_node.get_criteria():
                self._populate_oval_criteria_tree(new_parent_id, child_criteria)
            for child_criterion in criteria_node.get_criterion():
                self._populate_oval_criteria_tree(new_parent_id, child_criterion)
            # --- Add loop for extend_definition
            for child_ext_def in criteria_node.get_extend_definition():
                self._populate_oval_criteria_tree(new_parent_id, child_ext_def)

        elif isinstance(criteria_node, oval.CriterionType):
            node_text = f"Criterion (Test Ref: {criteria_node.get_test_ref()}){negate_text}"
            node_obj = criteria_node
            new_node_id = self.oval_criteria_tree.insert(parent_id, "end", text=node_text)
            self.oval_criteria_map[new_node_id] = node_obj

        elif isinstance(criteria_node, oval.ExtendDefinitionType):
            node_text = f"Extend Definition (Def Ref: {criteria_node.get_definition_ref()}){negate_text}"
            node_obj = criteria_node
            new_node_id = self.oval_criteria_tree.insert(parent_id, "end", text=node_text)
            self.oval_criteria_map[new_node_id] = node_obj

    def _show_criteria_node_dialog(self, node_to_edit=None, node_type=None):
        """Shows a dialog to add/edit a criteria, criterion, or extend_definition. Returns a dict or None."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)

        is_criteria = (node_type == 'criteria') or isinstance(node_to_edit, oval.CriteriaType)
        is_criterion = (node_type == 'criterion') or isinstance(node_to_edit, oval.CriterionType)
        is_extend_def = (node_type == 'extend_definition') or isinstance(node_to_edit, oval.ExtendDefinitionType)

        title = "Edit " if node_to_edit else "Add "
        if is_criteria: title += "Criteria"
        elif is_criterion: title += "Criterion"
        else: title += "Extended Definition"
        dialog.title(title)
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        row = 0
        if is_criteria:
            ttk.Label(main_frame, text="Operator:").grid(row=row, column=0, sticky="w", pady=5)
            op_options = ['AND', 'OR', 'XOR', 'ONE']
            op_var = tk.StringVar(value=node_to_edit.get_operator() if node_to_edit else "AND")
            ttk.Combobox(main_frame, textvariable=op_var, values=op_options, state="readonly").grid(row=row, column=1, sticky="ew", pady=5)
            results['var'] = op_var
            row += 1
        elif is_criterion:
            ttk.Label(main_frame, text="Test Reference ID:").grid(row=row, column=0, sticky="w", pady=5)
            ref_frame = ttk.Frame(main_frame)
            ref_frame.grid(row=row, column=1, sticky="ew")
            ref_var = tk.StringVar(value=node_to_edit.get_test_ref() if node_to_edit else "")
            test_ids = self.get_oval_test_ids()
            test_combo = ttk.Combobox(ref_frame, textvariable=ref_var, values=test_ids)
            test_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
            results['var'] = ref_var
            
            # --- Helper function to handle creating a new test
            def _create_new_test():
                new_test = self.add_oval_entity(self.current_oval_defs, 'test')
                if new_test:
                    # --- Refresh the dropdown list
                    test_combo['values'] = self.get_oval_test_ids()
                    # --- Select the newly created test's ID
                    ref_var.set(new_test.get_id())

            # --- The new button
            ttk.Button(ref_frame, text="New Test...", command=_create_new_test).pack(side=tk.LEFT, padx=(5,0))
            row += 1
        elif is_extend_def:
            ttk.Label(main_frame, text="Definition Ref ID:").grid(row=row, column=0, sticky="w", pady=5)
            ref_var = tk.StringVar(value=node_to_edit.get_definition_ref() if node_to_edit else "")
            def_ids = self.get_oval_definition_ids(specific_oval_defs=self.current_oval_defs)
            ttk.Combobox(main_frame, textvariable=ref_var, values=def_ids).grid(row=row, column=1, sticky="ew", pady=5)
            results['var'] = ref_var
            row += 1

        # --- Add Negate checkbox for all types
        negate_var = tk.BooleanVar(value=node_to_edit.get_negate() if node_to_edit else False)
        ttk.Checkbutton(main_frame, text="Negate Result", variable=negate_var).grid(row=row, column=1, sticky="w", pady=5)

        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            results['negate'] = negate_var.get()
            if is_criteria:
                results['operator'] = results['var'].get()
            elif is_criterion:
                if not results['var'].get():
                    messagebox.showwarning("Input Error", "Test Reference ID cannot be empty.", parent=dialog)
                    return
                results['test_ref'] = results['var'].get()
            elif is_extend_def:
                if not results['var'].get():
                    messagebox.showwarning("Input Error", "Definition Reference ID cannot be empty.", parent=dialog)
                    return
                results['definition_ref'] = results['var'].get()
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=10)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

        self._center_dialog(dialog)
        dialog.wait_window()
        return results if len(results) > 1 else None

    def add_oval_criteria(self):
        """Adds a new nested <criteria> element."""
        selected_id = self.oval_criteria_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a parent <criteria> node to add to.")
            return
            
        parent_obj = self.oval_criteria_map.get(selected_id)
        if not isinstance(parent_obj, oval.CriteriaType):
            messagebox.showwarning("Invalid Parent", "You can only add new elements to a 'Criteria' node.")
            return

        data = self._show_criteria_node_dialog(node_type='criteria')
        if data:
            new_criteria = oval.CriteriaType(
                operator=data['operator'],
                negate=data['negate']
            )
            parent_obj.add_criteria(new_criteria)
            self.on_oval_definition_select(None)

    def add_oval_criterion(self):
        """Adds a new <criterion> element."""
        selected_id = self.oval_criteria_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a parent <criteria> node to add to.")
            return

        parent_obj = self.oval_criteria_map.get(selected_id)
        if not isinstance(parent_obj, oval.CriteriaType):
            messagebox.showwarning("Invalid Parent", "You can only add new elements to a 'Criteria' node.")
            return

        data = self._show_criteria_node_dialog(node_type='criterion')
        if data:
           new_criterion = oval.CriterionType(
                test_ref=data['test_ref'],
                negate=data['negate']
           )
           parent_obj.add_criterion(new_criterion)
           self.on_oval_definition_select(None)

    def add_oval_extended_definition(self):
        """Adds a new <extend_definition> element."""
        selected_id = self.oval_criteria_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a parent <criteria> node to add to.")
            return

        parent_obj = self.oval_criteria_map.get(selected_id)
        if not isinstance(parent_obj, oval.CriteriaType):
            messagebox.showwarning("Invalid Parent", "You can only add new elements to a 'Criteria' node.")
            return

        data = self._show_criteria_node_dialog(node_type='extend_definition')
        if data:
            new_ext_def = oval.ExtendDefinitionType(
                definition_ref=data['definition_ref'],
                negate=data['negate']
            )
            parent_obj.add_extend_definition(new_ext_def)
            self.on_oval_definition_select(None)
            
    def edit_oval_criteria_item(self):
        """Edits the selected criteria, criterion, or extend_definition node."""
        selected_id = self.oval_criteria_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select an item to edit.")
            return
            
        node_to_edit = self.oval_criteria_map.get(selected_id)
        data = self._show_criteria_node_dialog(node_to_edit=node_to_edit)
        
        if data:
            # --- Set negate attribute for all types
            if 'negate' in data:
                node_to_edit.set_negate(data['negate'])

            # --- Set type-specific attributes
            if isinstance(node_to_edit, oval.CriteriaType) and 'operator' in data:
                node_to_edit.set_operator(data['operator'])
            elif isinstance(node_to_edit, oval.CriterionType) and 'test_ref' in data:
                node_to_edit.set_test_ref(data['test_ref'])
            elif isinstance(node_to_edit, oval.ExtendDefinitionType) and 'definition_ref' in data:
                node_to_edit.set_definition_ref(data['definition_ref'])
            
            self.on_oval_definition_select(None)

    def remove_oval_criteria_item(self):
        """Removes the selected item from the criteria tree and the data model."""
        selected_id = self.oval_criteria_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a criteria item to remove.")
            return

        parent_id = self.oval_criteria_tree.parent(selected_id)
        if not parent_id:
            messagebox.showerror("Error", "Cannot remove the root criteria element.")
            return

        parent_obj = self.oval_criteria_map.get(parent_id)
        selected_obj = self.oval_criteria_map.get(selected_id)

        if not parent_obj or not selected_obj:
            return

        if isinstance(selected_obj, oval.CriteriaType):
            parent_obj.get_criteria().remove(selected_obj)
        elif isinstance(selected_obj, oval.CriterionType):
            parent_obj.get_criterion().remove(selected_obj)
        # --- Add case for extend_definition
        elif isinstance(selected_obj, oval.ExtendDefinitionType):
            parent_obj.get_extend_definition().remove(selected_obj)
        
        self.on_oval_definition_select(None)

##--  [  OVAL Entity's ]---
    def add_oval_entity(self, oval_defs_obj, entity_type_str, selected_class=None):
        """Generic function to add any type of OVAL entity."""
        # If a class isn't provided, show the selector dialog
        if not selected_class:
            base_class_map = {'test': oval.TestType, 'object': oval.ObjectType, 'state': oval.StateType, 'variable': oval.VariableType}
            title_map = {'test': "Select Test Type", 'object': "Select Object Type", 'state': "Select State Type", 'variable': "Select Variable Type"}
            selected_class = self._select_oval_entity_type_dialog(base_class_map[entity_type_str], title_map[entity_type_str])
        
        if not selected_class:
            return None

        data = None
        # --- Call the correct dialog based on the entity type
        if entity_type_str == 'test':
            data = self._show_generic_test_details_dialog(selected_class)
        elif entity_type_str == 'object':
            selected_properties = self._select_object_properties_dialog(selected_class)
            if not selected_properties:
                return None
            data = self._show_generic_object_details_dialog(selected_class, selected_properties)
#            print(f"Selected Class: {selected_class}")
        elif entity_type_str == 'state': 
            selected_properties = self._select_object_properties_dialog(selected_class)
            if not selected_properties: return None
            data = self._show_generic_state_details_dialog(selected_class, selected_properties)
        elif entity_type_str == 'variable':
            data = self._show_generic_variable_details_dialog(selected_class)        
        else:
            messagebox.showinfo("Not Implemented", f"The UI for adding a '{entity_type_str}' is not fully implemented yet.")
            return None

        if not data:
            return None

        # --- DELEGATE CREATION TO THE FACTORY ---
        new_entity = self.oval_factory.create_entity(selected_class, data, entity_type_str)
        if not new_entity: return None
        
        # --- Add the entity to the correct container in the datastream
        container = getattr(oval_defs_obj, f"get_{entity_type_str}s")()
        if not container:
            container_class = getattr(oval, f"{entity_type_str.capitalize()}sType")
            container = container_class()
            getattr(oval_defs_obj, f"set_{entity_type_str}s")(container)
        
        getattr(container, f"add_{entity_type_str}")(new_entity)
        
        # --- Refresh the UI
        populate_tree_func = getattr(self, f"populate_oval_{entity_type_str}s_tree")
        populate_tree_func(oval_defs_obj)
        return new_entity
        
    def edit_oval_entity(self, oval_defs_obj, entity_type_str):
        """Dispatcher to edit the selected OVAL entity based on its type."""
        tree = getattr(self, f"oval_{entity_type_str}s_tree")
        entity_map = getattr(self, f"oval_{entity_type_str}s_map")
        
        selected_id = tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", f"Please select an {entity_type_str} to edit.")
            return

        entity_to_edit = entity_map[selected_id]
        entity_class = type(entity_to_edit)
        
        data = None
        if entity_type_str == 'test':
            # --- Tests use a simpler, one-step dialog
            data = self._show_generic_test_details_dialog(entity_class, entity_to_edit)
        elif (entity_type_str == 'object' or entity_type_str == 'state'):

            # --- For editing an object, we find all its possible properties to show in the dialog.
            properties_map = {}
            sig = inspect.signature(entity_class.__init__)
            for param in sig.parameters.values():
                if param.name not in ['self', 'id', 'gds_collector_', 'kwargs_'] and \
                   param.name not in oval_helper.DEPRECATED_OVAL_ENTITIES and \
                   param.name not in oval_helper.EXCLUDED_OVAL_PROPERTIES:
                
                    datatype = oval_helper.OVAL_PROPERTY_DATATYPE_MAP.get(param.name, 'string')
                    properties_map[param.name] = {'type': datatype}
            
            if entity_type_str == 'object':
                data = self._show_generic_object_details_dialog(entity_class, properties_map, entity_to_edit)
            else:
                data = self._show_generic_state_details_dialog(entity_class, properties_map, entity_to_edit)
        elif entity_type_str == 'variable':
            data = self._show_generic_variable_details_dialog(type(entity_to_edit), entity_to_edit)        
        else:
            messagebox.showinfo("Not Implemented", f"The editor for an OVAL {entity_type_str} is not implemented yet.")
            return

        if not data:
            return

        # --- Delegate the update logic to the factory ---
        self.oval_factory.update_entity(entity_to_edit, data, entity_type_str)

        # --- Refresh the UI
        populate_tree_func = getattr(self, f"populate_oval_{entity_type_str}s_tree")
        populate_tree_func(oval_defs_obj)

    def remove_oval_entity(self, oval_defs_obj, entity_type_str):
        """Generic function to remove any selected OVAL entity."""
        tree = getattr(self, f"oval_{entity_type_str}s_tree")
        entity_map = getattr(self, f"oval_{entity_type_str}s_map")

        selected_id = tree.focus()
        if not selected_id: return
        entity_to_remove = entity_map[selected_id]

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete this {entity_type_str}?\n\n{entity_to_remove.get_id()}"):
            container = getattr(oval_defs_obj, f"get_{entity_type_str}s")()
            if container:
                list_getter = getattr(container, f"get_{entity_type_str}")()
                list_getter.remove(entity_to_remove)
                populate_tree_func = getattr(self, f"populate_oval_{entity_type_str}s_tree")
                populate_tree_func(oval_defs_obj)

    def _get_available_entity_types(self, base_class_name):
        """
        Dynamically finds all OVAL entity classes by inspecting each component
        model file directly and checking the class name.
        """
        import inspect
        from models import oval_independent_models, oval_linux_models, oval_unix_models, oval_solaris_models

        # --- Determine the required suffix from the base class name (e.g., 'TestType' -> '_test')
        suffix = "_" + base_class_name.replace('Type', '').lower()
        entity_families = {}
        
        if suffix == '_variable':
            from models import oval_core_models
            module_map = {
               'Core' : oval_core_models
            }
        else:
            module_map = {
                'Independent': oval_independent_models,
                'Linux': oval_linux_models,
                'Unix': oval_unix_models,
                'Solaris': oval_solaris_models
            }

        for family_name, module in module_map.items():
            family_entities = {}
            for name, obj in inspect.getmembers(module):
                # --- The new, more reliable check: just look at the name of the class
                if inspect.isclass(obj) and name.endswith(suffix):
                    if name in oval_helper.DEPRECATED_OVAL_ENTITIES:
                        continue
                    friendly_name = name.replace('_', ' ').capitalize()
                    family_entities[friendly_name] = obj
            
            if family_entities:
                entity_families[family_name] = family_entities
                
        return entity_families

    def _select_oval_entity_type_dialog(self, base_class, title):
        """Shows a dialog to select any type of OVAL entity."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title(title)

        entity_families = self._get_available_entity_types(base_class.__name__)
        if not entity_families:
            messagebox.showerror("Error", f"No OVAL {base_class.__name__} types found in models.", parent=self.root)
            return None

        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Family Dropdown
        ttk.Label(main_frame, text="Select Family:").pack(pady=(5,0))
        family_var = tk.StringVar()
        family_combo = ttk.Combobox(main_frame, textvariable=family_var, values=sorted(entity_families.keys()), state="readonly")
        family_combo.pack(fill=tk.X, padx=5, pady=(0,10))

        # --- Item Dropdown
        ttk.Label(main_frame, text="Select Item Type:").pack(pady=(5,0))
        test_var = tk.StringVar()
        test_combo = ttk.Combobox(main_frame, textvariable=test_var, state="readonly")
        test_combo.pack(fill=tk.X, padx=5, pady=(0,10))

        def on_family_select(event):
            selected_family = family_var.get()
            # --- Get the test names for the selected family
            test_names = sorted(entity_families.get(selected_family, {}).keys())
            test_combo['values'] = test_names
            if test_names:
                test_var.set(test_names[0])

        family_combo.bind("<<ComboboxSelected>>", on_family_select)
        family_var.set(sorted(entity_families.keys())[0])
        on_family_select(None)

        selected_class = None
        def on_ok():
            nonlocal selected_class
            family = family_var.get()
            test_name = test_var.get()
            if family and test_name:
                # --- Look up the name in the nested dictionary to get the class object
                selected_class = entity_families[family][test_name]
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=10)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

        self._center_dialog(dialog)
        dialog.wait_window()
        return selected_class # This now correctly returns the class object

##--  [  OVAL Tests ]---
    def populate_oval_tests_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL tests treeview."""
        for i in self.oval_tests_tree.get_children():
            self.oval_tests_tree.delete(i)
        self.oval_tests_map.clear()
        
        tests_container = oval_defs_obj.get_tests()
        if tests_container and tests_container.get_test():
            for test in tests_container.get_test():
                test_type_name = test.__class__.__name__ # e.g., "FileTest"
                item_id = self.oval_tests_tree.insert("", "end", values=(
                    test.get_id(),
                    test_type_name,
                    test.get_comment()
                ))
                self.oval_tests_map[item_id] = test

    def _show_generic_test_details_dialog(self, test_class, test_to_edit=None):
        """Shows a generic dialog to add or edit the details of any OVAL test."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        is_edit = test_to_edit is not None
        dialog.title(f"{'Edit' if is_edit else 'Add'} OVAL {test_class.__name__}")

        # 1. Deduce the expected object and state class names from the test's name
        base_name = test_class.__name__.replace('_test', '')
        expected_obj_name = f"{base_name}_object"
        expected_state_name = f"{base_name}_state"
        
        # 2. Get the actual class objects from the oval module
        expected_obj_class = getattr(oval, expected_obj_name, None)
        expected_state_class = getattr(oval, expected_state_name, None)
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- ID ---
        initial_id = test_to_edit.get_id() if is_edit else f"oval:{self.prefix}:tst:{random.randint(1000, 9999)}"
        id_var = tk.StringVar(value=initial_id)
        ttk.Label(main_frame, text="ID:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=id_var).grid(row=0, column=1, sticky="ew", pady=2)
        
        # --- Comment ---
        ttk.Label(main_frame, text="Comment:").grid(row=1, column=0, sticky="w", pady=2)
        comment_var = tk.StringVar(value=test_to_edit.get_comment() if is_edit else f"Default {test_class.__name__}")
        ttk.Entry(main_frame, textvariable=comment_var, width=50).grid(row=1, column=1, sticky="ew", pady=2)

        # --- Version ---
        ttk.Label(main_frame, text="Version:").grid(row=2, column=0, sticky="w", pady=2)
        version_var = tk.StringVar(value=test_to_edit.get_version() if is_edit else "1")
        ttk.Entry(main_frame, textvariable=version_var).grid(row=2, column=1, sticky="ew", pady=2)
        
        # --- Check Enumeration ---
        check_options = ["all", "at least one", "none exist", "none satisfy", "only one"]
        ttk.Label(main_frame, text="Check:").grid(row=3, column=0, sticky="w", pady=2)
        check_var = tk.StringVar(value=test_to_edit.get_check() if is_edit else "all")
        ttk.Combobox(main_frame, textvariable=check_var, values=check_options, state="readonly").grid(row=3, column=1, sticky="ew", pady=2)
        
        # --- Check Existence Enumeration ---
        check_existence_options = ["all_exist", "any_exist", "at_least_one_exists", "none_exist", "only_one_exists"]
        ttk.Label(main_frame, text="Check Existence:").grid(row=4, column=0, sticky="w", pady=2)
        check_existence_var = tk.StringVar(value=test_to_edit.get_check_existence() if is_edit else "at_least_one_exists")
        ttk.Combobox(main_frame, textvariable=check_existence_var, values=check_existence_options, state="readonly").grid(row=4, column=1, sticky="ew", pady=2)

        # --- Object Reference with "New" button ---
        ttk.Label(main_frame, text="Object Ref ID:").grid(row=5, column=0, sticky="w", pady=2)
        obj_ref_frame = ttk.Frame(main_frame)
        obj_ref_frame.grid(row=5, column=1, sticky="ew")
        
        obj_ref_val = test_to_edit.get_object().get_object_ref() if is_edit and test_to_edit.get_object() else ""
        object_ref_var = tk.StringVar(value=obj_ref_val)
        # 3. Call the helper with the filter class to get a filtered list of IDs
        object_combo = ttk.Combobox(obj_ref_frame, textvariable=object_ref_var, values=self.get_oval_object_ids(filter_class=expected_obj_class))
        object_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def _create_new_object():
            # 4. Call add_oval_entity, passing in the correct class to skip the selector
            new_object = self.add_oval_entity(self.current_oval_defs, 'object', selected_class=expected_obj_class)
            if new_object:
                object_combo['values'] = self.get_oval_object_ids(filter_class=expected_obj_class)
                object_ref_var.set(new_object.get_id())

        ttk.Button(obj_ref_frame, text="New...", command=_create_new_object).pack(side=tk.LEFT, padx=(5,0))

        # --- State Reference with "New" button (applies the same logic) ---
        ttk.Label(main_frame, text="State Ref ID:").grid(row=6, column=0, sticky="w", pady=2)
        state_ref_frame = ttk.Frame(main_frame)
        state_ref_frame.grid(row=6, column=1, sticky="ew")

        st_ref_val = test_to_edit.get_state()[0].get_state_ref() if is_edit and test_to_edit.get_state() else ""
        state_ref_var = tk.StringVar(value=st_ref_val)
        state_combo = ttk.Combobox(state_ref_frame, textvariable=state_ref_var, values=self.get_oval_state_ids(filter_class=expected_state_class))
        state_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def _create_new_state():
            new_state = self.add_oval_entity(self.current_oval_defs, 'state', selected_class=expected_state_class)
            if new_state:
                state_combo['values'] = self.get_oval_state_ids(filter_class=expected_state_class)
                state_ref_var.set(new_state.get_id())
        
        ttk.Button(state_ref_frame, text="New...", command=_create_new_state).pack(side=tk.LEFT, padx=(5,0))
        
        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            results['id'] = id_var.get()
            results['comment'] = comment_var.get()
            results['version'] = version_var.get()
            results['check'] = check_var.get()
            results['check_existence'] = check_existence_var.get()
            results['object_ref'] = object_ref_var.get()
            results['state_ref'] = state_ref_var.get()
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'id' in results else None

    def get_oval_object_ids(self, filter_class=None):
        """Returns a list of all OVAL object IDs, optionally filtered by a specific class."""
        if not self.datastream_collection or not self.oval_objects_map:
            return []
        
        if filter_class:
            return [obj.get_id() for obj in self.oval_objects_map.values() if isinstance(obj, filter_class)]
        else:
            return [obj.get_id() for obj in self.oval_objects_map.values()]

    def get_oval_state_ids(self, filter_class=None):
        """Returns a list of all OVAL state IDs, optionally filtered by a specific class."""
        if not self.datastream_collection or not self.oval_states_map:
            return []
            
        if filter_class:
            return [state.get_id() for state in self.oval_states_map.values() if isinstance(state, filter_class)]
        else:
            return [state.get_id() for state in self.oval_states_map.values()]
                
##--  [  OVAL Objects ]---
    def populate_oval_objects_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL objects treeview."""
        for i in self.oval_objects_tree.get_children():
            self.oval_objects_tree.delete(i)
        self.oval_objects_map.clear()
        
        objects_container = oval_defs_obj.get_objects()
        if objects_container and objects_container.get_object():
            for obj in objects_container.get_object():
                obj_type_name = obj.__class__.__name__
                item_id = self.oval_objects_tree.insert("", "end", values=(
                    obj.get_id(),
                    obj_type_name,
                    obj.get_comment()
                ))
                self.oval_objects_map[item_id] = obj

    def _show_generic_object_details_dialog(self, obj_class, properties_map, obj_to_edit=None):
        """
        A smart dialog that shows common fields and dynamically adds user-selected
        properties with interactive attribute editors.
        """
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        is_edit = obj_to_edit is not None
        dialog.title(f"{'Edit' if is_edit else 'Add'} OVAL {obj_class.__name__}")
        
        results = {}
        prop_widgets = {} # To hold all UI elements for each property
        
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        row = 0
        # --- 1. Your hardcoded, always-visible properties ---
        initial_id = obj_to_edit.get_id() if is_edit else f"oval:{self.prefix}:obj:{random.randint(1000, 9999)}"
        id_var = tk.StringVar(value=initial_id)
        ttk.Label(main_frame, text="ID:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=id_var).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        comment_val = obj_to_edit.get_comment() if is_edit and hasattr(obj_to_edit, 'get_comment') else ""
        comment_var = tk.StringVar(value=comment_val)
        ttk.Label(main_frame, text="Comment:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=comment_var).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        if 'version' in [p.name for p in inspect.signature(obj_class.__init__).parameters.values()]:
            version_val = obj_to_edit.get_version() if is_edit and hasattr(obj_to_edit, 'get_version') else "1"
            version_var = tk.StringVar(value=version_val)
            ttk.Label(main_frame, text="Version:").grid(row=row, column=0, sticky="w", pady=2)
            ttk.Entry(main_frame, textvariable=version_var).grid(row=row, column=1, sticky="ew", pady=2)
            row += 1

        # --- 2. Dynamically create the interactive editors for selected properties ---
        prop_grid_frame = ttk.Frame(main_frame)
        prop_grid_frame.grid(row=row, column=0, columnspan=2, sticky="ew")
        row += 1
        col = 0
        grid_row = 0
        
        for prop_name, prop_info in sorted(properties_map.items()):
            if prop_name in ['id', 'comment', 'version']: continue

            if prop_name == 'behaviors':
                behaviors_frame = ttk.LabelFrame(main_frame, text="Behaviors", padding=5)
                behaviors_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5, ipady=5)
                row += 1

                b_widgets = {}
                b_edit_obj = obj_to_edit.get_behaviors() if is_edit and obj_to_edit.get_behaviors() else None

                # --- Helper to create a row with a checkbox that enables/disables a widget
                def create_behavior_row(parent, row_num, name, widget_class, **kwargs):
                    chk_var = tk.BooleanVar()
                    label = ttk.Label(parent, text=f"{name.replace('_', ' ').capitalize()}:")
                    var = tk.StringVar()
                    widget = widget_class(parent, textvariable=var, **kwargs)
                    widget.config(state=tk.DISABLED)

                    def toggle():
                        widget.config(state=tk.NORMAL if chk_var.get() else tk.DISABLED)
                    
                    chk = ttk.Checkbutton(parent, variable=chk_var, command=toggle)
                    chk.grid(row=row_num, column=0, sticky='w')
                    label.grid(row=row_num, column=1, sticky='w', padx=5)
                    widget.grid(row=row_num, column=2, sticky='ew', padx=5)
                    
                    # --- Pre-fill and enable if editing
                    edit_val = getattr(b_edit_obj, f"get_{name}", lambda: None)() if b_edit_obj else None
                    if edit_val:
                        var.set(edit_val)
                        chk_var.set(True)
                        toggle()
                    
                    return {'chk': chk_var, 'var': var}
 
                b_row = 0
                if obj_class is oval.rpminfo_object:
                    b_widgets['filepaths'] = create_behavior_row(behaviors_frame, b_row, 'filepaths', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                elif obj_class is oval.rpmverifypackage_object:
                    b_widgets['nodeps'] = create_behavior_row(behaviors_frame, b_row, 'nodeps', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nodigest'] = create_behavior_row(behaviors_frame, b_row, 'nodigest', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['noscripts'] = create_behavior_row(behaviors_frame, b_row, 'noscripts', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nosignature'] = create_behavior_row(behaviors_frame, b_row, 'nosignature', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                elif (obj_class is oval.rpmverifyfile_object or obj_class is oval.rpmverify_object):
                    if obj_class is oval.rpmverify_object:
                        b_widgets['nodeps'] = create_behavior_row(behaviors_frame, b_row, 'nodeps', ttk.Combobox, values=['true', 'false'], state='readonly')
                        b_row += 1
                        b_widgets['nodigest'] = create_behavior_row(behaviors_frame, b_row, 'nodigest', ttk.Combobox, values=['true', 'false'], state='readonly')
                        b_row += 1
                        b_widgets['nofiles'] = create_behavior_row(behaviors_frame, b_row, 'nofiles', ttk.Combobox, values=['true', 'false'], state='readonly')
                        b_row += 1
                        b_widgets['noscripts'] = create_behavior_row(behaviors_frame, b_row, 'noscripts', ttk.Combobox, values=['true', 'false'], state='readonly')
                        b_row += 1
                        b_widgets['nosignature'] = create_behavior_row(behaviors_frame, b_row, 'nosignature', ttk.Combobox, values=['true', 'false'], state='readonly')
                        b_row += 1
                    
                    b_widgets['nolinkto'] = create_behavior_row(behaviors_frame, b_row, 'nolinkto', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nomd5'] = create_behavior_row(behaviors_frame, b_row, 'nomd5', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nosize'] = create_behavior_row(behaviors_frame, b_row, 'nosize', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nouser'] = create_behavior_row(behaviors_frame, b_row, 'nouser', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nogroup'] = create_behavior_row(behaviors_frame, b_row, 'nogroup', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nomtime'] = create_behavior_row(behaviors_frame, b_row, 'nomtime', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nomode'] = create_behavior_row(behaviors_frame, b_row, 'nomode', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nordev'] = create_behavior_row(behaviors_frame, b_row, 'nordev', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1                
                    b_widgets['noconfigfiles'] = create_behavior_row(behaviors_frame, b_row, 'noconfigfiles', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['noghostfiles'] = create_behavior_row(behaviors_frame, b_row, 'noghostfiles', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    
                else:
                    b_widgets['max_depth'] = create_behavior_row(behaviors_frame, b_row, 'max_depth', ttk.Entry)
                    b_row += 1
                    b_widgets['recurse'] = create_behavior_row(behaviors_frame, b_row, 'recurse', ttk.Combobox, values=['directories', 'symlinks', 'symlinks and directories'], state='readonly')
                    b_row += 1
                    b_widgets['recurse_direction'] = create_behavior_row(behaviors_frame, b_row, 'recurse_direction', ttk.Combobox, values=['none', 'up', 'down'], state='readonly')
                    b_row += 1
                    b_widgets['recurse_file_system'] = create_behavior_row(behaviors_frame, b_row, 'recurse_file_system', ttk.Combobox, values=['all', 'local', 'defined'], state='readonly')
                    b_row += 1
                
                if (obj_class is oval.filehash58_object or obj_class is oval.xmlfilecontent_object):
                    b_widgets['windows_view'] = create_behavior_row(behaviors_frame, b_row, 'windows_view', ttk.Combobox, values=['32_bit', '64_bit'], state='readonly')
                    b_row += 1

                if obj_class is oval.textfilecontent54_object: 
                    b_widgets['windows_view'] = create_behavior_row(behaviors_frame, b_row, 'windows_view', ttk.Combobox, values=['32_bit', '64_bit'], state='readonly')
                    b_row += 1
                    b_widgets['ignore_case'] = create_behavior_row(behaviors_frame, b_row, 'ignore_case', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['multiline'] = create_behavior_row(behaviors_frame, b_row, 'multiline', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['singleline'] = create_behavior_row(behaviors_frame, b_row, 'singleline', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    
                behaviors_frame.columnconfigure(2, weight=1)
                prop_widgets['behaviors'] = b_widgets
                continue 

            elif prop_name == 'filter':
                filter_frame = ttk.LabelFrame(main_frame, text="Filter")
                filter_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5, ipady=5)
                row += 1

                f_widgets = {}
                # --- For now, we'll edit the first filter if it exists
                f_edit_obj = obj_to_edit.get_filter()[0] if is_edit and obj_to_edit.get_filter() else None

                # --- Action Dropdown
                ttk.Label(filter_frame, text="Action:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
                f_widgets['action'] = tk.StringVar(value=f_edit_obj.get_action() if f_edit_obj else "include")
                ttk.Combobox(filter_frame, textvariable=f_widgets['action'], values=['include', 'exclude'], state='readonly').grid(row=0, column=1, sticky="ew", padx=5, pady=2)

                # --- State ID Dropdown
                ttk.Label(filter_frame, text="State ID:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
                f_widgets['state_id'] = tk.StringVar(value=f_edit_obj.get_valueOf_() if f_edit_obj else "")
                ttk.Combobox(filter_frame, textvariable=f_widgets['state_id'], values=self.get_oval_state_ids(), state='readonly').grid(row=1, column=1, sticky="ew", padx=5, pady=2)
                
                filter_frame.columnconfigure(1, weight=1)
                prop_widgets['filter'] = f_widgets
                continue 
                
            prop_container = ttk.LabelFrame(prop_grid_frame, text=prop_name.replace('_', ' ').capitalize())
            prop_container.grid(row=grid_row, column=col, sticky="nsew", padx=2, pady=4)

            val_frame = ttk.Frame(prop_container)
            val_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
            val_obj = getattr(obj_to_edit, f"get_{prop_name}", lambda: None)() if is_edit else None
            val_var = tk.StringVar(value=val_obj.get_valueOf_() if val_obj else "")
            
             # --- Check if this property is special and create a dropdown
            if prop_name == 'hash_type':
                ttk.Label(val_frame, text="Value:").pack(side=tk.LEFT)
                hash_options = ['MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512']
                ttk.Combobox(val_frame, textvariable=val_var, values=hash_options, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
            elif prop_name == 'engine':
                ttk.Label(val_frame, text="Value:").pack(side=tk.LEFT)
                engine_options = ['access',  'db2',  'cache',  'firebird',  'firstsql',  'foxpro',  'informix',  'ingres',  'interbase',  'lightbase',  'maxdb',  'monetdb',  'mimer',  'mysql',  'oracle',  'paradox',  'pervasive',  'postgre',  'sqlbase',  'sqlite',  'sqlserver',  'sybase']
                ttk.Combobox(val_frame, textvariable=val_var, values=engine_options, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
            else:    
                ttk.Label(val_frame, text="Value:").pack(side=tk.LEFT)
                ttk.Entry(val_frame, textvariable=val_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        
            attr_frame = ttk.Frame(prop_container, padding=(0, 5))
            #attr_frame.pack(fill=tk.X, expand=True)

            show_attrs_var = tk.BooleanVar()
            
            #Toggle Logic
            chk_button = ttk.Checkbutton(prop_container, text="Show Optional Attributes", variable=show_attrs_var)              
            command = lambda frame=attr_frame, var=show_attrs_var, btn=chk_button: (
                frame.pack(fill=tk.X, expand=True, before=btn) if var.get() else frame.pack_forget()
            )
            chk_button.config(command=command)
            chk_button.pack(anchor='w', padx=5)

            predefined_datatype = prop_info.get('type')
            dt_var = tk.StringVar(value=val_obj.get_datatype() if val_obj else predefined_datatype)
            dt_options = ["string", "int", "boolean", "version", "ipv4_address", "ipv6_address", "float", "evr_string", "binary"]
            ttk.Label(attr_frame, text="Datatype:").grid(row=0, column=0, sticky='w')
            dt_combo = ttk.Combobox(attr_frame, textvariable=dt_var, values=dt_options, state="readonly", width=12)
            dt_combo.grid(row=0, column=1, sticky='ew', padx=5)
            if predefined_datatype: dt_combo.config(state=tk.DISABLED)                

            op_var = tk.StringVar(value=val_obj.get_operation() if val_obj else "")
            op_map = {
                'default': ["equals", "pattern match", "not equal", "case insensitive equals", "case insensitive not equal", "greater than", "less than", "greater than or equal", "less than or equal", "bitwise and", "bitwise or", "subset of", "superset of"],
                'string': ["equals", "not equal", "case insensitive equals", "case insensitive not equal", "pattern match"],
                'numeric': ["equals", "not equal", "greater than", "less than", "greater than or equal", "less than or equal", "bitwise and", "bitwise or"],
                'version': ["equals", "not equal", "greater than", "less than", "greater than or equal", "less than or equal"],
                'boolean': ["equals", "not equal"],
                'record': ["equals"]
            }
            op_category = 'default' # Default
            if predefined_datatype in ['int', 'float']:
                op_category = 'numeric'
            elif predefined_datatype == 'version':
                op_category = 'version'
            elif predefined_datatype in ['boolean', 'binary']:
                op_category = 'boolean'
            elif predefined_datatype == 'string':
                op_category = 'string'
            op_options = op_map[op_category]    
            ttk.Label(attr_frame, text="Operation:").grid(row=0, column=2, sticky='w', padx=10)
            op_combo = ttk.Combobox(attr_frame, textvariable=op_var, values=op_options, state="readonly", width=15)
            op_combo.grid(row=0, column=3, sticky='ew', padx=5)
            if op_var.get() not in op_options:
                op_var.set("") # Clear the selection if it's no longer valid
                
            # --- START MODIFICATION ---
            mask_var = tk.StringVar(value=val_obj.get_mask() if val_obj else "")
            ttk.Label(attr_frame, text="Mask:").grid(row=1, column=0, sticky='w', pady=(5,0))
            ttk.Combobox(attr_frame, textvariable=mask_var, values=["true", "false"], state="readonly", width=8).grid(row=1, column=1, sticky='ew', padx=5, pady=(5,0))

            var_ref_var = tk.StringVar(value=val_obj.get_var_ref() if val_obj else "")
            ttk.Label(attr_frame, text="Variable Ref:").grid(row=1, column=2, sticky='w', padx=10, pady=(5,0))
            ttk.Entry(attr_frame, textvariable=var_ref_var).grid(row=1, column=3, sticky='ew', padx=5, pady=(5,0))
            # --- END MODIFICATION ---

            attr_frame.columnconfigure(1, weight=1)
            attr_frame.columnconfigure(3, weight=1)
            
            if is_edit and val_obj and (val_obj.get_datatype() or val_obj.get_operation() or val_obj.get_mask() or val_obj.get_var_ref()):
                show_attrs_var.set(True)
                command()
                
            prop_widgets[prop_name] = {'value': val_var, 'datatype': dt_var, 'operation': op_var, 'mask': mask_var, 'var_ref': var_ref_var, 'show_attrs': show_attrs_var}

            col += 1
            if col == 2:
                col = 0
                grid_row += 1
                
        prop_grid_frame.columnconfigure(0, weight=1)
        prop_grid_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            # --- Get data from the correct variables and widget maps
            results['id'] = id_var.get()
            results['comment'] = comment_var.get()
            if version_var:
                results['version'] = version_var.get()

            for prop_name, widgets in prop_widgets.items():
                if prop_name == 'behaviors':
                    b_data = {}
                    for key, b_widget_data in widgets.items():
                        if b_widget_data['chk'].get():
                            b_data[key] = b_widget_data['var'].get()
                    results['behaviors'] = b_data
                elif prop_name == 'filter':
                    # --- Gather data from the filter widgets
                    f_data = {key: var.get() for key, var in widgets.items()}
                    results['filter'] = f_data
                else:
                    prop_data = {'value': widgets['value'].get()}                  
                    if widgets['datatype'].get(): prop_data['datatype'] = widgets['datatype'].get()
                    if widgets['operation'].get(): prop_data['operation'] = widgets['operation'].get()
                    if widgets['mask'].get(): prop_data['mask'] = widgets['mask'].get()
                    if widgets['var_ref'].get(): prop_data['var_ref'] = widgets['var_ref'].get()
                    results[prop_name] = prop_data
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if results and 'id' in results else None
        
    def _select_object_properties_dialog(self, obj_class):
        """
        Shows a dialog with checkboxes for properties and looks up their expected datatypes.
        """
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title(f"Select Properties for {obj_class.__name__}")
        dialog.minsize(width=350, height=300)

        properties_map = {}
        sig = inspect.signature(obj_class.__init__)
        for param in sig.parameters.values():
            if param.name not in ['self', 'id', 'gds_collector_', 'kwargs_', 'comment', 'version'] and \
               param.name not in oval_helper.DEPRECATED_OVAL_ENTITIES and \
               param.name not in oval_helper.EXCLUDED_OVAL_PROPERTIES:
                
                # --- Look up the datatype from our new map, defaulting to 'string'
                datatype = oval_helper.OVAL_PROPERTY_DATATYPE_MAP.get(param.name, 'string')
                properties_map[param.name] = {'type': datatype}


        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Select the properties to include:").pack(anchor="w", pady=5)
        
        check_vars = {name: tk.BooleanVar() for name in properties_map}
        for prop_name in sorted(properties_map.keys()):
            chk = ttk.Checkbutton(main_frame, text=prop_name.replace('_', ' ').capitalize(), variable=check_vars[prop_name])
            chk.pack(anchor="w", padx=10)

        selected_properties = None
        def on_ok():
            nonlocal selected_properties
            selected_properties = {name: data for name, data in properties_map.items() if check_vars[name].get()}
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return selected_properties
        
##--  [  OVAL States ]---
    def populate_oval_states_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL states treeview."""
        for i in self.oval_states_tree.get_children():
            self.oval_states_tree.delete(i)
        self.oval_states_map.clear()
        
        states_container = oval_defs_obj.get_states()
        if states_container and states_container.get_state():
            for state in states_container.get_state():
                state_type_name = state.__class__.__name__
                item_id = self.oval_states_tree.insert("", "end", values=(
                    state.get_id(),
                    state_type_name,
                    state.get_comment()
                ))
                self.oval_states_map[item_id] = state

    def _show_generic_state_details_dialog(self, state_class, properties_map, state_to_edit=None):
        """A smart dialog that builds an input form for any OVAL state."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        is_edit = state_to_edit is not None
        dialog.title(f"{'Edit' if is_edit else 'Add'} OVAL {state_class.__name__}")
        
        results = {}
        prop_widgets = {} 
        
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        row = 0
        # --- 1. Hardcoded, always-visible properties ---
        initial_id = state_to_edit.get_id() if is_edit else f"oval:{self.prefix}:ste:{random.randint(1000, 9999)}"
        id_var = tk.StringVar(value=initial_id)
        ttk.Label(main_frame, text="ID:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=id_var).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        comment_val = state_to_edit.get_comment() if is_edit and hasattr(state_to_edit, 'get_comment') else ""
        comment_var = tk.StringVar(value=comment_val)
        ttk.Label(main_frame, text="Comment:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=comment_var).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1
        
        operator_val = state_to_edit.get_operator() if is_edit and hasattr(state_to_edit, 'get_operator') else "AND"
        operator_var = tk.StringVar(value=operator_val)
        ttk.Label(main_frame, text="Operator:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Combobox(main_frame, textvariable=operator_var, values=["AND", "ONE", "OR", "XOR"], state="readonly", width=8).grid(row=row, column=1, sticky='ew', padx=5, pady=(5,0))
        row += 1

        if 'version' in [p.name for p in inspect.signature(state_class.__init__).parameters.values()]:
            version_val = state_to_edit.get_version() if is_edit and hasattr(state_to_edit, 'get_version') else "1"
            version_var = tk.StringVar(value=version_val)
            ttk.Label(main_frame, text="Version:").grid(row=row, column=0, sticky="w", pady=2)
            ttk.Entry(main_frame, textvariable=version_var).grid(row=row, column=1, sticky="ew", pady=2)
            row += 1

        # --- 2. Dynamically create the editors for selected properties ---
        prop_grid_frame = ttk.Frame(main_frame)
        prop_grid_frame.grid(row=row, column=0, columnspan=2, sticky="ew")
        row += 1
        col = 0
        grid_row = 0

        for prop_name, prop_info in sorted(properties_map.items()):
            if prop_name in ['id', 'comment', 'version', 'operator']: continue

            prop_container = ttk.LabelFrame(prop_grid_frame, text=prop_name.replace('_', ' ').capitalize())
            prop_container.grid(row=grid_row, column=col, sticky="nsew", padx=2, pady=4)
            
            val_frame = ttk.Frame(prop_container)
            val_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
            val_obj = getattr(obj_to_edit, f"get_{prop_name}", lambda: None)() if is_edit else None
            val_var = tk.StringVar(value=val_obj.get_valueOf_() if val_obj else "")
            

            # --- Check if this property is special and create a dropdown
            if prop_name == 'windows_view':
                ttk.Label(val_frame, text="Value:").pack(side=tk.LEFT)
                windows_view_options = ['32_bit', '64_bit']
                ttk.Combobox(val_frame, textvariable=val_var, values=windows_view_options, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)            
            else:
                ttk.Label(val_frame, text="Value:").pack(side=tk.LEFT)
                ttk.Entry(val_frame, textvariable=val_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            attr_frame = ttk.Frame(prop_container, padding=(0, 5))
            #attr_frame.pack(fill=tk.X, expand=True)

            show_attrs_var = tk.BooleanVar()

            #Toggle Logic
            chk_button = ttk.Checkbutton(prop_container, text="Show Optional Attributes", variable=show_attrs_var)              
            command = lambda frame=attr_frame, var=show_attrs_var, btn=chk_button: (
                frame.pack(fill=tk.X, expand=True, before=btn) if var.get() else frame.pack_forget()
            )
            chk_button.config(command=command)
            chk_button.pack(anchor='w', padx=5)
            
            predefined_datatype = prop_info.get('type')
            dt_var = tk.StringVar(value=val_obj.get_datatype() if val_obj else predefined_datatype)
            dt_options = ["string", "int", "boolean", "version", "ipv4_address", "ipv6_address", "float", "evr_string", "binary", "record"]
            ttk.Label(attr_frame, text="Datatype:").grid(row=0, column=0, sticky='w')
            dt_combo = ttk.Combobox(attr_frame, textvariable=dt_var, values=dt_options, state="readonly", width=12)
            dt_combo.grid(row=0, column=1, sticky='ew', padx=5)
            if predefined_datatype: dt_combo.config(state=tk.DISABLED)                

            op_var = tk.StringVar(value=val_obj.get_operation() if val_obj else "")
            op_map = {
                'default': ["equals", "pattern match", "not equal", "case insensitive equals", "case insensitive not equal", "greater than", "less than", "greater than or equal", "less than or equal", "bitwise and", "bitwise or", "subset of", "superset of"],
                'string': ["equals", "not equal", "case insensitive equals", "case insensitive not equal", "pattern match"],
                'numeric': ["equals", "not equal", "greater than", "less than", "greater than or equal", "less than or equal", "bitwise and", "bitwise or"],
                'version': ["equals", "not equal", "greater than", "less than", "greater than or equal", "less than or equal"],
                'boolean': ["equals", "not equal"],
                'record': ["equals"]
            }
            op_category = 'default' # Default
            if predefined_datatype in ['int', 'float']:
                op_category = 'numeric'
            elif predefined_datatype == 'version':
                op_category = 'version'
            elif predefined_datatype in ['boolean', 'binary']:
                op_category = 'boolean'
            elif predefined_datatype == 'string':
                op_category = 'string'
            op_options = op_map[op_category]    
            ttk.Label(attr_frame, text="Operation:").grid(row=0, column=2, sticky='w', padx=10)
            op_combo = ttk.Combobox(attr_frame, textvariable=op_var, values=op_options, state="readonly", width=15)
            op_combo.grid(row=0, column=3, sticky='ew', padx=5)
            if op_var.get() not in op_options:
                op_var.set("") # Clear the selection if it's no longer valid
            
            mask_var = tk.StringVar(value=val_obj.get_mask() if val_obj else "")
            ttk.Label(attr_frame, text="Mask:").grid(row=1, column=0, sticky='w', pady=(5,0))
            ttk.Combobox(attr_frame, textvariable=mask_var, values=["true", "false"], state="readonly", width=8).grid(row=1, column=1, sticky='ew', padx=5, pady=(5,0))

            var_ref_var = tk.StringVar(value=val_obj.get_var_ref() if val_obj else "")
            ttk.Label(attr_frame, text="Variable Ref:").grid(row=1, column=2, sticky='w', padx=10, pady=(5,0))
            ttk.Entry(attr_frame, textvariable=var_ref_var).grid(row=1, column=3, sticky='ew', padx=5, pady=(5,0))
                
            attr_frame.columnconfigure(1, weight=1)
            attr_frame.columnconfigure(3, weight=1)
            
            if is_edit and val_obj and (val_obj.get_datatype() or val_obj.get_operation() or val_obj.get_mask() or val_obj.get_var_ref()):
                show_attrs_var.set(True)
                command()
                
            prop_widgets[prop_name] = {'value': val_var, 'datatype': dt_var, 'operation': op_var, 'mask': mask_var, 'var_ref': var_ref_var, 'show_attrs': show_attrs_var}

            col += 1
            if col == 2:
                col = 0
                grid_row += 1
                
        prop_grid_frame.columnconfigure(0, weight=1)
        prop_grid_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(1, weight=1)
            
        def on_ok():
            # --- CORRECTED: Get data from the correct variables and widget maps
            results['id'] = id_var.get()
            results['comment'] = comment_var.get()
            results['operator'] = operator_var.get()
            if version_var:
                results['version'] = version_var.get()

            for prop_name, widgets in prop_widgets.items():
                prop_data = {'value': widgets['value'].get()}                  
                if widgets['datatype'].get(): prop_data['datatype'] = widgets['datatype'].get()
                if widgets['operation'].get(): prop_data['operation'] = widgets['operation'].get()
                if widgets['mask'].get(): prop_data['mask'] = widgets['mask'].get()
                if widgets['var_ref'].get(): prop_data['var_ref'] = widgets['var_ref'].get()
                results[prop_name] = prop_data
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if results and 'id' in results else None

##--  [  OVAL Variables ]---
    def populate_oval_variables_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL variables treeview."""
        for i in self.oval_variables_tree.get_children():
            self.oval_variables_tree.delete(i)
        self.oval_variables_map.clear()
        
        variables_container = oval_defs_obj.get_variables()
        if variables_container and variables_container.get_variable():
            for var in variables_container.get_variable():
                var_type_name = var.__class__.__name__
                item_id = self.oval_variables_tree.insert("", "end", values=(
                    var.get_id(),
                    var_type_name,
                    var.get_comment()
                ))
                self.oval_variables_map[item_id] = var

    def get_oval_variable_ids(self, filter_class=None):
        """
        Returns a list of all OVAL variable IDs, optionally filtered by a specific class.
        """
        if not self.datastream_collection or not self.oval_variables_map:
            return []
        
        # If a filter is provided, return only IDs of that specific variable type
        if filter_class:
            return [var.get_id() for var in self.oval_variables_map.values() if isinstance(var, filter_class)]
        # Otherwise, return all variable IDs
        else:
            return [var.get_id() for var in self.oval_variables_map.values()]
            
    def _show_generic_variable_details_dialog(self, var_class, var_to_edit=None):
        """A smart dialog that builds an input form for any OVAL variable."""
        from models import oval_core_models
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        is_edit = var_to_edit is not None
        dialog.title(f"{'Edit' if is_edit else 'Add'} OVAL {var_class.__name__}")
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        

        class ListEditorData:
            def __init__(self, data_list, widget):
                self.data = data_list
                self.widget = widget
                
        # Define the list editor helper function first so it's always available.
        def create_list_editor(parent, label_text, initial_data, dialog_callback, display_formatter, edit_kwarg_name, add_limit=None):
            data_list = list(initial_data)
            frame = ttk.LabelFrame(parent, text=label_text, padding=5)
            # This helper uses pack internally for its own elements
            listbox = tk.Listbox(frame, width=60)
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
 
            edit_frame = ttk.Frame(frame)
            edit_frame.pack(side=tk.LEFT, padx=5, fill=tk.Y)
            
            for item_data in data_list:
                listbox.insert(tk.END, display_formatter(item_data))

            def add_item():
                if add_limit is not None and len(data_list) >= add_limit:
                    messagebox.showinfo("Limit Reached", f"This function can only have {add_limit} component(s).", parent=dialog)
                    return
                    
                new_data = dialog_callback()
                if new_data:
                    data_list.append(new_data)
                    listbox.insert(tk.END, display_formatter(new_data))
            
            def edit_item():
                selected_index = listbox.curselection()
                if not selected_index: return
                index = selected_index[0]
                edited_data = dialog_callback(**{edit_kwarg_name: data_list[index]})
                if edited_data:
                    data_list[index] = edited_data
                    listbox.delete(index)
                    listbox.insert(index, display_formatter(edited_data))

            def remove_item():
                selected_index = listbox.curselection()
                if not selected_index: return
                index = selected_index[0]
                listbox.delete(index)
                del data_list[index]


            ttk.Button(edit_frame, text="Add...", command=add_item).pack(fill=tk.X)
            ttk.Button(edit_frame, text="Edit...", command=edit_item).pack(fill=tk.X, pady=2)
            ttk.Button(edit_frame, text="Remove", command=remove_item).pack(fill=tk.X)
            
            return frame, ListEditorData(data_list, listbox)
            
        # --- Standard Fields ---
        row = 0
        initial_id = var_to_edit.get_id() if is_edit else f"oval:{self.prefix}:var:{random.randint(1000, 9999)}"
        id_var = tk.StringVar(value=initial_id)
        ttk.Label(main_frame, text="ID:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=id_var).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        version_val = var_to_edit.get_version() if is_edit and hasattr(var_to_edit, 'get_version') else "1"
        version_var = tk.StringVar(value=version_val)
        ttk.Label(main_frame, text="Version:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=version_var).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1
        
        comment_val = var_to_edit.get_comment() if is_edit and hasattr(var_to_edit, 'get_comment') else ""
        comment_var = tk.StringVar(value=comment_val)
        ttk.Label(main_frame, text="Comment:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(main_frame, textvariable=comment_var).grid(row=row, column=1, sticky="ew", pady=2)
        row += 1

        dt_val = var_to_edit.get_datatype() if is_edit and hasattr(var_to_edit, 'get_datatype') else "string"
        dt_var = tk.StringVar(value=dt_val)
        dt_options = ["string", "int", "boolean", "version", "ipv4_address", "ipv6_address", "float", "evr_string", "binary", "fileset_revision"]
        ttk.Label(main_frame, text="Datatype:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Combobox(main_frame, textvariable=dt_var, values=dt_options, state="readonly").grid(row=row, column=1, sticky="ew", pady=2)
        row += 1
            
        # --- Value Field (specific to constant_variable) ---
        if var_class is oval.constant_variable:
            initial_values = [v.get_valueOf_() for v in var_to_edit.get_value()] if is_edit and var_to_edit.get_value() else []
            frame, editor_data = create_list_editor(
                main_frame, "Values", initial_values, self._show_value_dialog, 
                lambda d: d, 'value_to_edit'
            )
            frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)
            results['value'] = editor_data.data

        elif var_class is oval.external_variable:
            # Pre-populate lists if editing
            p_vals_data = []
            if is_edit and var_to_edit.get_possible_value():
                for pv in var_to_edit.get_possible_value():
                    p_vals_data.append({'value': pv.get_valueOf_(), 'hint': pv.get_hint()})
            
            p_rests_data = []
            if is_edit and var_to_edit.get_possible_restriction():
                for pr in var_to_edit.get_possible_restriction():
                    restrictions_list = [{'value': r.get_valueOf_(), 'operation': r.get_operation()} for r in pr.get_restriction()]
                    p_rests_data.append({'restriction': pr.get_restriction(), 'hint': pr.get_hint()})
            
            pv_frame, pv_editor_data = create_list_editor(
                main_frame, "Possible Values", p_vals_data, 
                self._show_possible_value_dialog, 
                lambda d: f"{d['value']} (Hint: {d.get('hint', 'N/A')})",
                'value_to_edit'
            )
            pv_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)
            results['possible_value'] = pv_editor_data.data

            pr_frame, pr_editor_data = create_list_editor(
                main_frame, "Possible Restrictions", p_rests_data, self._show_possible_restriction_editor, 
#                lambda d: f"{d['restriction']} (Hint: {d.get('hint', 'N/A')})", 'restriction_to_edit'
                lambda d: f"Hint: {d.get('hint', 'N/A')} ({len(d.get('restrictions', []))} restrictions)",
                'restriction_to_edit'
            )
            pr_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=5)
            results['possible_restriction'] = pr_editor_data.data

        elif var_class is oval.local_variable:
            # --- Component Frames ---
            component_type_var = tk.StringVar()
            function_type_var = tk.StringVar()

            literal_frame = ttk.Frame(main_frame)
            variable_frame = ttk.Frame(main_frame)
            object_frame = ttk.Frame(main_frame)
            function_frame = ttk.Frame(main_frame)

            # --- Radio Buttons to select component type ---
            radio_frame = ttk.LabelFrame(main_frame, text="Component Type", padding=5)
            radio_frame.grid(row=4, column=0, columnspan=2, sticky='ew', pady=5)
            ttk.Radiobutton(radio_frame, text="Literal", value="literal", variable=component_type_var).pack(side=tk.LEFT)
            ttk.Radiobutton(radio_frame, text="Variable", value="variable", variable=component_type_var).pack(side=tk.LEFT, padx=5)
            ttk.Radiobutton(radio_frame, text="Object", value="object", variable=component_type_var).pack(side=tk.LEFT, padx=5)
            ttk.Radiobutton(radio_frame, text="Function", value="function", variable=component_type_var).pack(side=tk.LEFT)

            def switch_component_view(*args):
                # Hide all frames
                literal_frame.grid_forget()
                variable_frame.grid_forget()
                object_frame.grid_forget()
                function_frame.grid_forget()
                # Show the selected frame
                if component_type_var.get() == "literal":
                    literal_frame.grid(row=5, column=0, columnspan=2, sticky='ew')
                elif component_type_var.get() == "variable":
                    variable_frame.grid(row=5, column=0, columnspan=2, sticky='ew')
                elif component_type_var.get() == "object":
                    object_frame.grid(row=5, column=0, columnspan=2, sticky='ew')
                elif component_type_var.get() == "function":
                    function_frame.grid(row=5, column=0, columnspan=2, sticky='ew', pady=5)
            
            component_type_var.trace_add("write", switch_component_view)
            
            # --- Build Literal Component UI ---
            lit_val_var = tk.StringVar()
            ttk.Label(literal_frame, text="Value:").grid(row=0, column=0, sticky='w')
            ttk.Entry(literal_frame, textvariable=lit_val_var).grid(row=0, column=1, sticky='ew')
            literal_frame.columnconfigure(1, weight=1)

            # --- Build Variable Component UI ---
            var_ref_frame = ttk.Frame(variable_frame)
            var_ref_frame.grid(row=0, column=1, sticky='ew')
            var_ref_var = tk.StringVar()
            ttk.Label(variable_frame, text="Variable Ref:").grid(row=0, column=0, sticky='w')
            var_combo = ttk.Combobox(var_ref_frame, textvariable=var_ref_var, values=self.get_oval_variable_ids())
            var_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            def _create_new_variable():
                new_var = self.add_oval_entity(self.current_oval_defs, 'variable')
                if new_var:
                    var_combo['values'] = self.get_oval_variable_ids()
                    var_ref_var.set(new_var.get_id())
            ttk.Button(var_ref_frame, text="New...", command=_create_new_variable).pack(side=tk.LEFT, padx=(5,0))
            variable_frame.columnconfigure(1, weight=1)

            # --- Build Object Component UI ---
            obj_ref_frame = ttk.Frame(object_frame)
            obj_ref_frame.grid(row=0, column=1, sticky='ew')
            obj_ref_var = tk.StringVar(); item_field_var = tk.StringVar(); rec_field_var = tk.StringVar()
            ttk.Label(object_frame, text="Object Ref:").grid(row=0, column=0, sticky='w')
            obj_combo = ttk.Combobox(obj_ref_frame, textvariable=obj_ref_var, values=self.get_oval_object_ids())
            obj_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

            def _create_new_object():
                new_obj = self.add_oval_entity(self.current_oval_defs, 'object')
                if new_obj:
                    obj_combo['values'] = self.get_oval_object_ids()
                    obj_ref_var.set(new_obj.get_id())
            ttk.Button(obj_ref_frame, text="New...", command=_create_new_object).pack(side=tk.LEFT, padx=(5,0))
            
            ttk.Label(object_frame, text="Item Field:").grid(row=1, column=0, sticky='w'); ttk.Entry(object_frame, textvariable=item_field_var).grid(row=1, column=1, sticky='ew')
            ttk.Label(object_frame, text="Record Field:").grid(row=2, column=0, sticky='w'); ttk.Entry(object_frame, textvariable=rec_field_var).grid(row=2, column=1, sticky='ew')
            object_frame.columnconfigure(1, weight=1)

            # --- Build UI for Function Component ---
            function_editor = ttk.LabelFrame(function_frame, text="Function Editor", padding=5)
            function_editor.pack(fill=tk.BOTH, expand=True)
            

            # Dropdown to select the specific function
            function_options = ["arithmetic", "begin", "concat", "end", "escape_regex", "split", "substring", "time_difference", "regex_capture", "unique", "count", "glob_to_regex"]
            ttk.Label(function_editor, text="Function Type:").pack(anchor='w')
            function_combo = ttk.Combobox(function_editor, textvariable=function_type_var, values=function_options, state='readonly')
            function_combo.pack(fill=tk.X, pady=(0, 10))

            # Placeholder for the dynamic UI that will change based on the selected function
            dynamic_function_frame = ttk.Frame(function_editor)
            dynamic_function_frame.pack(fill=tk.BOTH, expand=True)

            def switch_function_editor(*args):                
                for widget in dynamic_function_frame.winfo_children():
                    widget.destroy()
                
                selected_function = function_type_var.get()

                # This function now handles both UI creation and pre-population cleanly.

                # 1. Prepare initial data (defaults or from the edited object)
                components_data = []
                # Add defaults for the new attributes
                char_value, arith_op_value, delimiter_value, pattern_value, glob_noescape_value, substring_start_value, substring_length_value,  \
                   time_diff_format1_value, time_diff_format2_value = '', 'add', '', '', '', '', '', '', ''
              
                if is_edit:
                    func = getattr(var_to_edit, f"get_{selected_function}", lambda: None)()
                    if func:
                        if selected_function == 'arithmetic': arith_op_value = func.get_arithmetic_operation()
                        elif selected_function in ['begin', 'end']: 
                            char_value = func.get_character()

                        elif selected_function == 'split': 
                            delimiter_value = func.get_delimiter()
                      
                        elif selected_function == 'regex_capture': 
                            pattern_value = func.get_pattern()
                      
                        elif selected_function == 'glob_to_regex': 
                            glob_noescape_value = func.get_glob_noescape()
                      
                        elif selected_function == 'substring': 
                            substring_start_value = func.get_substring_start()
                            substring_length_value = func.get_substring_length()

                        elif selected_function == 'time_difference':
                            time_diff_format1_value = func.get_format_1()
                            time_diff_format2_value = func.get_format_2()
                            
                        for comp in func.get_literal_component():
                            components_data.append({'type': 'literal_component', 'value': comp.get_valueOf_()})
                        for comp in func.get_object_component():
                            components_data.append({'type': 'object_component', 'object_ref': comp.get_object_ref(), 'item_field': comp.get_item_field(), 'record_field': comp.get_record_field()})
                        for comp in func.get_variable_component():
                            components_data.append({'type': 'variable_component', 'var_ref': comp.get_var_ref()})

                
                # 2. Build the UI using the prepared data
                if selected_function == 'arithmetic':
                    op_var = tk.StringVar(value=arith_op_value)
                    op_frame = ttk.Frame(dynamic_function_frame)
                    op_frame.pack(fill=tk.X, pady=5)
                    ttk.Label(op_frame, text="Arithmetic Op:").pack(side=tk.LEFT)
                    ttk.Combobox(op_frame, textvariable=op_var, values=['add', 'multiply', 'subtract'], state='readonly').pack(side=tk.LEFT)
                    results['arithmetic_op_var'] = op_var
                
                # --- Build UI based on the selected function ---
                elif selected_function in ['begin', 'end']:
                    char_var = tk.StringVar(value=char_value)
                    char_frame = ttk.Frame(dynamic_function_frame)
                    char_frame.pack(fill=tk.X, pady=5)
                    ttk.Label(char_frame, text="Character:").pack(side=tk.LEFT)
                    ttk.Entry(char_frame, textvariable=char_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
                    results['char_var'] = char_var

                elif selected_function == 'split':
                    delimiter_var = tk.StringVar(value=delimiter_value)
                    attr_frame = ttk.Frame(dynamic_function_frame)
                    attr_frame.pack(fill=tk.X, pady=5)
                    ttk.Label(attr_frame, text="Delimiter:").pack(side=tk.LEFT)
                    ttk.Entry(attr_frame, textvariable=delimiter_var).pack(fill=tk.X, expand=True)
                    results['delimiter_var'] = delimiter_var
                
                elif selected_function == 'regex_capture':
                    pattern_var = tk.StringVar(value=pattern_value)
                    attr_frame = ttk.Frame(dynamic_function_frame)
                    attr_frame.pack(fill=tk.X, pady=5)
                    ttk.Label(attr_frame, text="Pattern:").pack(side=tk.LEFT)
                    ttk.Entry(attr_frame, textvariable=pattern_var).pack(fill=tk.X, expand=True)
                    results['pattern_var'] = pattern_var

                elif selected_function == 'glob_to_regex':
                    glob_noescape_var = tk.StringVar(value=glob_noescape_value)
                    attr_frame = ttk.Frame(dynamic_function_frame)
                    attr_frame.pack(fill=tk.X, pady=5)
                    ttk.Label(attr_frame, text="Glob Noescape:").pack(side=tk.LEFT)
                    ttk.Combobox(attr_frame, textvariable=glob_noescape_var, values=['True', ''], state='readonly').pack(fill=tk.X, expand=True)
                    results['glob_noescape_var'] = glob_noescape_var

                elif selected_function == 'substring':
                    attr_frame = ttk.Frame(dynamic_function_frame)
                    attr_frame.pack(fill=tk.X, pady=5)
                    
                    start_var = tk.StringVar(value=substring_start_value)
                    ttk.Label(attr_frame, text="Substring Start:").grid(row=0, column=0, sticky='w')
                    ttk.Entry(attr_frame, textvariable=start_var).grid(row=0, column=1, sticky='ew', padx=5)

                    length_var = tk.StringVar(value=substring_length_value)
                    ttk.Label(attr_frame, text="Substring Length:").grid(row=1, column=0, sticky='w', pady=(5,0))
                    ttk.Entry(attr_frame, textvariable=length_var).grid(row=1, column=1, sticky='ew', padx=5, pady=(5,0))
                    
                    attr_frame.columnconfigure(1, weight=1)
                    results['substring_start_var'] = start_var
                    results['substring_length_var'] = length_var

                if selected_function == 'time_difference':
                    attr_frame = ttk.Frame(dynamic_function_frame)
                    attr_frame.pack(fill=tk.X, pady=5)
                    
                    format_options = ['seconds_since_epoch', 'day_month_year', 'year_month_day', 'month_day_year', 'win_filetime']
                    
                    ttk.Label(attr_frame, text="Format 1:").grid(row=0, column=0, sticky='w')
                    format1_var = tk.StringVar(value=time_diff_format1_value)
                    ttk.Combobox(attr_frame, textvariable=format1_var, values=format_options, state='readonly').grid(row=0, column=1, sticky='ew', padx=5)

                    ttk.Label(attr_frame, text="Format 2:").grid(row=1, column=0, sticky='w', pady=(5,0))
                    format2_var = tk.StringVar(value=time_diff_format2_value)
                    ttk.Combobox(attr_frame, textvariable=format2_var, values=format_options, state='readonly').grid(row=1, column=1, sticky='ew', padx=5, pady=(5,0))
                    
                    attr_frame.columnconfigure(1, weight=1)
                    results['time_diff_format1_var'] = format1_var
                    results['time_diff_format2_var'] = format2_var
                    
                # 3. Create the list editor, which will auto-populate
                if selected_function in ["arithmetic", "concat", "escape_regex", "unique", "count"]:
                    frame, editor_data = create_list_editor(
                        dynamic_function_frame, "Components", components_data,
                        self._show_function_component_dialog,
                        lambda d: f"{d['type']}: {d.get('value') or d.get('var_ref') or d.get('object_ref')}",
                        'component_to_edit'
                    )
                    frame.pack(fill=tk.BOTH, expand=True, pady=5)
                    results['components_editor_data'] = editor_data

                elif selected_function in ["time_difference"]:
                    frame, editor_data = create_list_editor(
                        dynamic_function_frame, "Components (up to 2)", components_data,
                        self._show_function_component_dialog,
                        lambda d: f"{d['type']}: {d.get('value') or d.get('var_ref') or d.get('object_ref')}",
                        'component_to_edit',
                        add_limit=2 #Pass the limit to the helper
                    )
                    frame.pack(fill=tk.BOTH, expand=True, pady=5)
                    results['components_editor_data'] = editor_data
                    
                elif selected_function in ["begin", "end", "split", "regex_capture", "glob_to_regex", "substring"]:
                    # --- UI for a SINGLE component ---
                    frame, editor_data = create_list_editor(
                        dynamic_function_frame, "Components (up to 1)", components_data,
                        self._show_function_component_dialog,
                        lambda d: f"{d['type']}: {d.get('value') or d.get('var_ref') or d.get('object_ref')}",
                        'component_to_edit',
                        add_limit=1 #Pass the limit to the helper
                    )

                    frame.pack(fill=tk.BOTH, expand=True, pady=5)
                    results['components_editor_data'] = editor_data
                    if selected_function in ["begin", "end"]: results['character_var'] = char_var
                    elif selected_function in ["split"]: results['delimiter_var'] = delimiter_var
                    elif selected_function in ["regex_capture"]: results['pattern_var'] = pattern_var
                    elif selected_function in ["glob_to_regex"]: results['glob_noescape_var'] = glob_noescape_var
                    elif selected_function in ["substring"]: 
                        results['substring_start_var'] = start_var
                        results['substring_length_var'] = length_var

            function_type_var.trace_add("write", switch_function_editor)
            
            # Pre-select based on existing data if editing
            if is_edit:
                if var_to_edit.get_literal_component(): component_type_var.set("literal")
                elif var_to_edit.get_variable_component(): component_type_var.set("variable")
                elif var_to_edit.get_object_component(): component_type_var.set("object")
                elif any(getattr(var_to_edit, f"get_{f}", None) for f in function_options):
                    component_type_var.set("function")
                    for f in function_options:
                        if getattr(var_to_edit, f"get_{f}", None):
                            function_type_var.set(f)
                            break
            else:
                component_type_var.set("literal")

        def on_ok():
            results['id'] = id_var.get()
            results['comment'] = comment_var.get()
            results['datatype'] = dt_var.get()
            results['version'] = version_var.get()
            if var_class is oval.local_variable:
                results['component_type'] = component_type_var.get()
                if results['component_type'] == 'literal':
                    results['literal_value'] = lit_val_var.get()
                elif results['component_type'] == 'variable':
                    results['var_ref'] = var_ref_var.get()
                elif results['component_type'] == 'object':
                    results['object_ref'] = obj_ref_var.get()
                    results['item_field'] = item_field_var.get()
                    results['record_field'] = rec_field_var.get()
                elif results['component_type'] == 'function':
                    results['function_type'] = function_type_var.get()
                    
                    # Gather data from the specific function editor
                    if results['function_type'] == 'arithmetic':
                        results['arithmetic_op'] = results['arithmetic_op_var'].get()
                        del results['arithmetic_op_var']
                    elif results['function_type'] in ['begin', 'end']:
                        # This line was missing. It gets the value from the StringVar.
                        results['character'] = results['character_var'].get()
                        del results['character_var']
                    elif results['function_type'] == 'split':
                        results['delimiter'] = results['delimiter_var'].get()
                        del results['delimiter_var']
                    elif results['function_type'] == 'regex_capture':
                        results['pattern'] = results['pattern_var'].get()
                        del results['pattern_var']
                    elif results['function_type'] == 'glob_to_regex':
                        results['glob_noescape'] = results['glob_noescape_var'].get()
                        del results['glob_noescape_var']
                    elif results['function_type'] == 'substring':
                        results['substring_start'] = results['substring_start_var'].get()
                        results['substring_length'] = results['substring_length_var'].get()
                        del results['substring_start_var']                        
                        del results['substring_length_var'] 
                    elif results['function_type'] == 'time_difference':
                        results['format_1'] = results['time_diff_format1_var'].get()
                        results['format_2'] = results['time_diff_format2_var'].get()
                        del results['time_diff_format1_var']                        
                        del results['time_diff_format2_var'] 
                    if 'components_editor_data' in results:
                        results['components_data'] = results['components_editor_data'].data
                        del results['components_editor_data']
                        
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'id' in results else None

    def _show_possible_value_dialog(self, value_to_edit=None):
        """Shows a dialog to add or edit a possible_value with its attributes."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Edit Possible Value" if value_to_edit else "Add Possible Value")
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        initial_value = value_to_edit.get('value', '') if value_to_edit else ""
        initial_hint = value_to_edit.get('hint', '') if value_to_edit else ""
        initial_datatype = value_to_edit.get('datatype', 'string') if value_to_edit else "string"
        
        ttk.Label(main_frame, text="Value:").grid(row=0, column=0, sticky="w", pady=2)
        val_var = tk.StringVar(value=initial_value)
        ttk.Entry(main_frame, textvariable=val_var).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(main_frame, text="Hint:").grid(row=1, column=0, sticky="w", pady=2)
        hint_var = tk.StringVar(value=initial_hint)
        ttk.Entry(main_frame, textvariable=hint_var).grid(row=1, column=1, sticky="ew", pady=2)
        
        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            if not val_var.get():
                messagebox.showwarning("Input Error", "Value cannot be empty.", parent=dialog)
                return
            if not hint_var.get():
                messagebox.showwarning("Input Error", "Hint cannot be empty.", parent=dialog)
                return            
            results['value'] = val_var.get()
            results['hint'] = hint_var.get()
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'value' in results else None

    def _show_possible_restriction_editor(self, restriction_to_edit=None):
        """Shows a dialog to manage a possible_restriction and its list of restrictions."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Edit Possible Restriction" if restriction_to_edit else "Add Possible Restriction")
        dialog.minsize(width=400, height=300)

        results = {}
        restrictions_data = list(restriction_to_edit.get('restrictions', [])) if restriction_to_edit else []

        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Entry for the 'hint'  and operator attribute
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(top_frame, text="Hint:").grid(row=0, column=0, sticky="w", pady=2)
        hint_var = tk.StringVar(value=restriction_to_edit.get('hint', '') if restriction_to_edit else "")
        ttk.Entry(top_frame, textvariable=hint_var).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(top_frame, text="Operator:").grid(row=1, column=0, sticky="w", pady=2)
        op_var = tk.StringVar(value=restriction_to_edit.get('operator', 'AND') if restriction_to_edit else "AND")
        ttk.Combobox(top_frame, textvariable=op_var, values=['AND', 'OR', 'XOR', 'ONE'], state='readonly').grid(row=1, column=1, sticky="ew", pady=2)
        
        top_frame.columnconfigure(1, weight=1)

        # List editor for the child <restriction> elements
        list_frame = ttk.LabelFrame(main_frame, text="Restrictions", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        listbox = tk.Listbox(list_frame)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        for r_data in restrictions_data:
            listbox.insert(tk.END, f"{r_data['value']} (Operation: {r_data.get('operation', 'equals')})")

        def add_item():
            new_data = self._show_restriction_dialog()
            if new_data:
                restrictions_data.append(new_data)
                listbox.insert(tk.END, f"{new_data['value']} (Operation: {new_data.get('operation', 'equals')})")

        def edit_item():
            selected_index = listbox.curselection()
            if not selected_index: return
            index = selected_index[0]
            edited_data = self._show_restriction_dialog(restriction_to_edit=restrictions_data[index])
            if edited_data:
                restrictions_data[index] = edited_data
                listbox.delete(index)
                listbox.insert(index, f"{edited_data['value']} (Operation: {edited_data.get('operation', 'equals')})")

        def remove_item():
            selected_index = listbox.curselection()
            if not selected_index: return
            index = selected_index[0]
            listbox.delete(index)
            del restrictions_data[index]

        edit_frame = ttk.Frame(list_frame)
        edit_frame.pack(side=tk.LEFT, padx=5, fill=tk.Y)
        ttk.Button(edit_frame, text="Add...", command=add_item).pack()
        ttk.Button(edit_frame, text="Edit...", command=edit_item).pack(pady=2)
        ttk.Button(edit_frame, text="Remove", command=remove_item).pack()

        def on_ok():
            if not restrictions_data:
                messagebox.showwarning("Input Error", "At least one restriction is required.", parent=dialog)
                return
            results['hint'] = hint_var.get()
            results['operator'] = op_var.get()
            results['restrictions'] = restrictions_data
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)

        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'restrictions' in results else None
        
    def _show_restriction_dialog(self, restriction_to_edit=None):
        """Shows a dialog to add or edit a single restriction with its operation."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Edit Restriction" if restriction_to_edit else "Add Restriction")
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        initial_value = restriction_to_edit.get('value', '') if restriction_to_edit else ""
        initial_op = restriction_to_edit.get('operation', '') if restriction_to_edit else ""

        ttk.Label(main_frame, text="Value:").grid(row=0, column=0, sticky="w", pady=2)
        value_var = tk.StringVar(value=initial_value)
        ttk.Entry(main_frame, textvariable=value_var).grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(main_frame, text="Operation:").grid(row=1, column=0, sticky="w", pady=2)
        op_var = tk.StringVar(value=initial_op)
        op_options = ["", "equals", "pattern match", "not equal", "case insensitive equals", "case insensitive not equal", "greater than", "less than", "greater than or equal", "less than or equal", "bitwise and", "bitwise or", "subset of", "superset of"]
        ttk.Combobox(main_frame, textvariable=op_var, values=op_options, state="readonly").grid(row=1, column=1, sticky="ew", pady=2)
        
        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            if not value_var.get():
                messagebox.showwarning("Input Error", "Value cannot be empty.", parent=dialog)
                return
            results['value'] = value_var.get()
            results['operation'] = op_var.get()
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'value' in results else None

    def _show_value_dialog(self, value_to_edit=None):
        """Shows a simple dialog to add or edit a single value string."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Edit Value" if value_to_edit else "Add Value")
        
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Value:").pack(anchor='w')
        val_var = tk.StringVar(value=value_to_edit or "")
        ttk.Entry(main_frame, textvariable=val_var, width=50).pack(fill=tk.X, expand=True)
        
        result = None
        def on_ok():
            nonlocal result
            if not val_var.get():
                messagebox.showwarning("Input Error", "Value cannot be empty.", parent=dialog)
                return
            result = val_var.get()
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return result

    def _show_function_component_dialog(self, component_to_edit=None):
        """A dialog to add/edit one of the four component types inside a function."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Edit Function Component" if component_to_edit else "Add Function Component")
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Radio buttons to select the component type ---
        component_type_var = tk.StringVar()
        radio_frame = ttk.Frame(main_frame)
        radio_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(radio_frame, text="Literal", value="literal_component", variable=component_type_var).pack(side=tk.LEFT)
        ttk.Radiobutton(radio_frame, text="Object", value="object_component", variable=component_type_var).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="Variable", value="variable_component", variable=component_type_var).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="Function", value="function_group", variable=component_type_var).pack(side=tk.LEFT)

        # --- Frames for each component's UI ---
        literal_frame = ttk.Frame(main_frame)
        object_frame = ttk.Frame(main_frame)
        variable_frame = ttk.Frame(main_frame)
        function_frame = ttk.Frame(main_frame) # Placeholder for nested functions

        def switch_view(*args):
            literal_frame.pack_forget(); object_frame.pack_forget(); variable_frame.pack_forget(); function_frame.pack_forget()
            ctype = component_type_var.get()
            if ctype == "literal_component": literal_frame.pack(fill=tk.BOTH, expand=True)
            elif ctype == "object_component": object_frame.pack(fill=tk.BOTH, expand=True)
            elif ctype == "variable_component": variable_frame.pack(fill=tk.BOTH, expand=True)
            elif ctype == "function_group": function_frame.pack(fill=tk.BOTH, expand=True)
        
        component_type_var.trace_add("write", switch_view)

        # --- Build the UI inside each frame ---
        lit_var = tk.StringVar(); obj_ref_var = tk.StringVar(); item_field_var = tk.StringVar()
        rec_field_var = tk.StringVar(); var_ref_var = tk.StringVar()
        
        ttk.Label(literal_frame, text="Value:").grid(row=0, column=0); ttk.Entry(literal_frame, textvariable=lit_var).grid(row=0, column=1, sticky='ew')
        ttk.Label(object_frame, text="Object Ref:").grid(row=0, column=0); ttk.Combobox(object_frame, textvariable=obj_ref_var, values=self.get_oval_object_ids()).grid(row=0, column=1, sticky='ew')
        ttk.Label(object_frame, text="Item Field:").grid(row=1, column=0); ttk.Entry(object_frame, textvariable=item_field_var).grid(row=1, column=1, sticky='ew')
        ttk.Label(object_frame, text="Record Field:").grid(row=2, column=0); ttk.Entry(object_frame, textvariable=rec_field_var).grid(row=2, column=1, sticky='ew')
        ttk.Label(variable_frame, text="Variable Ref:").grid(row=0, column=0); ttk.Combobox(variable_frame, textvariable=var_ref_var, values=self.get_oval_variable_ids()).grid(row=0, column=1, sticky='ew')
#        ttk.Label(function_frame, text="Nested functions not yet supported.").pack()
        # --- UI for the nested function ---
        func_type_var = tk.StringVar()
        ttk.Label(function_frame, text="Function Type:").pack(anchor='w')
        func_options = ["arithmetic", "concat", "end", "escape_regex", "split", "substring", "time_difference", "regex_capture", "unique", "count", "glob_to_regex"]
        ttk.Combobox(function_frame, textvariable=func_type_var, values=func_options, state='readonly').pack(fill=tk.X)
        ttk.Button(function_frame, text="Define...", command=lambda: messagebox.showinfo("Info", "Nested function components are defined in the main editor.")).pack(pady=5)

        # Pre-fill if editing
        if component_to_edit:
            # This logic can be expanded to pre-fill the fields
            pass 
        else:
            component_type_var.set("literal_component")


        def on_ok():
            results['type'] = component_type_var.get()
            if results['type'] == 'literal_component': results['value'] = lit_var.get()
            elif results['type'] == 'object_component':
                results['object_ref'] = obj_ref_var.get(); results['item_field'] = item_field_var.get(); results['record_field'] = rec_field_var.get()
            elif results['type'] == 'variable_component': results['var_ref'] = var_ref_var.get()
            elif results['type'] == 'function_group':
                # For now, we only need to know the type of function to create
                results['function_type'] = func_type_var.get()
                # A more advanced version would open another editor here
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return results if 'type' in results else None

        
##--  [ General Helpers & Getters ]---
    def create_detail_entry(self, parent_frame, label_text, data_obj, attr_name):
        frame = ttk.Frame(parent_frame)
        frame.pack(fill=tk.X, pady=5)
        label = ttk.Label(frame, text=label_text, width=15)
        label.pack(side=tk.LEFT, anchor='n')
        var = tk.StringVar(self.root)
        var.set(getattr(data_obj, attr_name, ""))
        def update_data(*args):
            setattr(data_obj, attr_name, var.get())
        var.trace_add("write", update_data)
        widget = ttk.Entry(frame, textvariable=var)
        widget.pack(fill=tk.X, expand=True)
      
    def get_cpe_dictionary(self):
        if self.datastream_collection:
            try:
                for comp in self.datastream_collection.get_component():
                    if comp.cpe_list is not None:
                        return comp.cpe_list
            except (IndexError, AttributeError):
                return None
        return None

    def get_oval_definition_ids(self, specific_oval_defs=None):
        """Finds the CPE OVAL component and returns a list of all OVAL definition IDs within it."""
        ids = []
        if not self.datastream_collection:
            return ids
        
        if specific_oval_defs:
            # --- Search only within the provided OVAL definitions object
            if specific_oval_defs.get_definitions():
                for definition in specific_oval_defs.get_definitions().get_definition():
                    ids.append(definition.get_id())
        else:
            # --- Search all OVAL components in the entire datastream
            for comp in self.datastream_collection.get_component():
                if comp.oval_definitions:
                    oval_defs = comp.oval_definitions
                    if oval_defs.get_definitions():
                        for definition in oval_defs.get_definitions().get_definition():
                            ids.append(definition.get_id())
        
        return sorted(list(set(ids)))

    def get_oval_components(self):
        """Finds all OVAL components in the datastream and returns a map of their ID to the object."""
        components = {}
        if not self.datastream_collection:
            return components
        for comp in self.datastream_collection.get_component():
            if comp.oval_definitions is not None:
                components[comp.get_id()] = comp
        return components
        
    def _center_dialog(self, dialog):
        """Centers a Toplevel dialog over the main application window."""
        dialog.update_idletasks()  # Update geometry information
        
        # --- Get the main window's geometry
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_width = self.root.winfo_width()
        root_height = self.root.winfo_height()
        
        # --- Get the dialog's size
        dialog_width = dialog.winfo_width()
        dialog_height = dialog.winfo_height()
        
        # --- Calculate the new x and y coordinates
        x = root_x + (root_width // 2) - (dialog_width // 2)
        y = root_y + (root_height // 2) - (dialog_height // 2)
        
        dialog.geometry(f'+{x}+{y}')
        
    def find_parent(self, start_node, child_to_find):
        if isinstance(start_node, datastream_models.data_stream_collection):
            benchmark = self.get_benchmark()
            if benchmark:
                return self.find_parent(benchmark, child_to_find)
        elif isinstance(start_node, (xccdf_models.Benchmark, xccdf_models.groupType)):
            if hasattr(start_node, 'Group') and start_node.Group and child_to_find in start_node.Group:
                return start_node
            if hasattr(start_node, 'Rule') and start_node.Rule and child_to_find in start_node.Rule:
                return start_node
            if hasattr(start_node, 'Group') and start_node.Group:
                for subgroup in start_node.Group:
                    found_parent = self.find_parent(subgroup, child_to_find)
                    if found_parent:
                        return found_parent
        return None

    def show_welcome_message(self):
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        ttk.Label(self.detail_frame, text="Welcome!", font=("Helvetica", 16)).pack()
        ttk.Label(self.detail_frame, text="Use Create -> New Datastream to get started.", justify=tk.LEFT).pack()         
           
if __name__ == "__main__":
    root = tk.Tk()
    app = XccdfEditorApp(root)
    root.mainloop()