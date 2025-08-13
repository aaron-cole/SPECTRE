import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
from datetime import datetime
import uuid
import random
import inspect
import io
import re
import yaml
from lxml import etree

# Import the entire models package.
import scap_unified_model as models

class XccdfEditorApp:

    # A map defining the expected datatype for known OVAL properties.
    OVAL_PROPERTY_DATATYPE_MAP = {
        #Integers
        'a_time': 'int', 'chg_allow': 'int', 'chg_lst': 'int', 'chg_req': 'int', 'c_time': 'int', 'exp_date': 'int', 'exp_inact': 'int',
        'exp_warn': 'int', 'group_id': 'int', 'instance': 'int', 'last_login': 'int', 'local_port': 'int', 'loginuid': 'int', 'mod_time': 'int',
        'm_time': 'int', 'pid': 'int', 'port': 'int', 'ppid': 'int', 'priority': 'int', 'ruid': 'int', 'session_id': 'int', 'size': 'int',
        'space_left': 'int', 'space_used': 'int', 'total_space': 'int', 'ttl': 'int', 'user_id': 'int', 
        
        #Strings
        'arch': 'string', 'architecture': 'string', 'attribute_name': 'string', 'canonical_path': 'string', 'command_line': 'string',
        'connection_string': 'string', 'dependency': 'string', 'device': 'string', 'domain_name': 'string', 'exec_as_user': 'string',
        'exec_time': 'string', 'extended_name': 'string', 'filename': 'string', 'filepath': 'string', 'flag': 'string', 'fs_type': 'string',
        'gcos': 'string', 'hardware_addr': 'string', 'hash': 'string', 'high_category': 'string', 'high_sensitivity': 'string', 'home_dir': 'string',
        'hw_address': 'string', 'interface_name': 'string', 'key': 'string', 'login_shell': 'string', 'low_category': 'string', 
        'low_sensitivity': 'string', 'machine_class': 'string', 'mod_user': 'string', 'mount_options': 'string', 'mount_point': 'string',
        'name': 'string', 'no_access': 'string', 'node_name': 'string', 'os_name': 'string', 'os_release': 'string', 'os_version': 'string',
        'password': 'string', 'path': 'string', 'pattern': 'string', 'processor_type': 'string', 'program_name': 'string', 'property': 'string',
        'protocol': 'string', 'rawhigh_category': 'string', 'rawhigh_sensitivity': 'string', 'rawlow_category': 'string', 'rawlow_sensitivity': 'string',
        'revision': 'string', 'role': 'string', 'runlevel': 'string', 'scheduling_class': 'string', 'selinux_domain_label': 'string', 'server': 'string',
        'server_arguments': 'string', 'server_program': 'string', 'service_name': 'string', 'signature_keyid': 'string', 'socket_type': 'string',
        'source': 'string', 'sql': 'string', 'start_time': 'string', 'tty': 'string', 'unit': 'string', 'user': 'string', 'username': 'string', 
        'uuid': 'string', 'xpath': 'string', 
        
        
        'version': 'version',
        
        'hash_type': 'string',

        #Booleans
        'configuration_file': 'boolean', 'current_status': 'boolean', 'dependency_check_passed': 'boolean', 'digest_check_passed': 'boolean',
        'disabled': 'boolean', 'documentation_file': 'boolean', 'exec_shield': 'boolean', 'gexec': 'boolean', 'ghost_file': 'boolean', 'gread': 'boolean',
        'gwrite': 'boolean', 'has_extended_acl': 'boolean', 'is_default': 'boolean', 'is_writable': 'boolean', 'kill': 'boolean', 'license_file': 'boolean',
        'oexec': 'boolean', 'oread': 'boolean', 'owrite': 'boolean', 'pending_status': 'boolean', 'readme_file': 'boolean', 'sgid': 'boolean',
        'signature_check_passed': 'boolean', 'start': 'boolean', 'sticky': 'boolean', 'suid': 'boolean', 'uexec': 'boolean', 'uread': 'boolean',
        'uwrite': 'boolean', 'verification_script_successful': 'boolean', 'wait': 'boolean',    

    }

    # A set of complex OVAL properties that should be excluded from the simple property selector.
    EXCLUDED_OVAL_PROPERTIES = {
        'set_', 'Signature', 'deprecated', 'notes', 'operator', 'version', 'comment', 
    }

    # --- A set of OVAL entity class names that are deprecated and should not be shown in the UI.
    DEPRECATED_OVAL_ENTITIES = {
        'family_test', 'family_object', 'family_state',
        'filehash_test', 'filehash_object', 'filehash_state',
        'sql_test', 'sql_object', 'sql_state',
        #Oval >5.11.2    'sql57_test', 'sql57_object', 'sql57_state',
        'ldap_test', 'ldap_object', 'ldap_state',
        'ldap57_test', 'ldap57_object', 'ldap57_state',
        'textfilecontent_test', 'textfilecontent_object', 'textfilecontent_state',
        'environmentvariable_test', 'environmentvariable_object', 'environmentvariable_state',
        'patch_test', 'patch_object',
        'process_test', 'process_object', 'process_state',
        'sccs_test', 'sccs_object', 'sccs_state',
        'apparmorstatus_test', 'apparmorstatus_object', 'apparmorstatus_state',
    }

##--  [ Initialization and Core UI ]---
    def __init__(self, root):
        self.root = root
        self.root.title("SPECTRE")
        self.root.geometry("1000x700")
        
        # --- Initialize all instance variables ---
        self.datastream_collection = None
        self.prefix = None  
        self.current_oval_defs = None
        self.right_clicked_item_data = None
        self.platforms_tree = None
        self.logical_test_editor_frame = None
        self.fact_refs_tree = None
        self.selected_platform_obj = None
        self.is_dirty = False
        self.oval_schema_location = self._build_oval_schema_location_string()
        
        self._reset_state_maps()
        
        # --- create the UI ---
        self.create_widgets()

    def _reset_state_maps(self):
        """Helper to initialize or reset all state-tracking dictionaries."""
        self.maps = {
            'item': {}, 'cpe_item': {}, 'oval_definition': {},
            'oval_criteria': {}, 'oval_test': {}, 'oval_object': {},
            'oval_state': {}, 'oval_variable': {}
        }
        
    def _build_oval_schema_location_string(self):
        """
        Dynamically builds the full xsi:schemaLocation string for OVAL
        by inspecting the generated model for component schemas.
        """
        locations = [
            'http://oval.mitre.org/XMLSchema/oval-definitions-5 http://oval.mitre.org/XMLSchema/oval-definitions-5.11.2/oval-definitions-schema.xsd',
            'http://oval.mitre.org/XMLSchema/oval-common-5 http://oval.mitre.org/XMLSchema/oval-common-5.11.2/oval-common-schema.xsd'
        ]
        
        known_locations = {
            'independent': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent http://oval.mitre.org/XMLSchema/oval-definitions-5.11.2/components/oval-definitions-component-independent.xsd',
            'unix': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix http://oval.mitre.org/XMLSchema/oval-definitions-5.11.2/components/oval-definitions-component-unix.xsd',
            'linux': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux http://oval.mitre.org/XMLSchema/oval-definitions-5.11.2/components/oval-definitions-component-linux.xsd',
            'solaris': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#solaris http://oval.mitre.org/XMLSchema/oval-definitions-5.11.2/components/oval-definitions-component-solaris.xsd',
        }

        # Check which component types exist in the unified model
        for name, location in known_locations.items():
            if hasattr(models, f"{name}_object"): # Use the 'models' alias here
                locations.append(location)
                
        return ' '.join(locations)
        
    def create_widgets(self):
        # --- Create Menubar ---
        self.menu = tk.Menu(self.root)
        self.root.config(menu=self.menu)

        # --- File Menu (Main) ---
        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="New Datastream...", command=self.new_file)
        self.file_menu.add_command(label="Open Datastream...", command=self.open_file)
        self.file_menu.add_command(label="Close Datastream", command=self.close_file)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Save Datastream As...", command=self.save_file)
        self.file_menu.add_separator()

        # --- Create Menu (now a submenu of File) ---
        self.create_menu = tk.Menu(self.file_menu, tearoff=0)
        self.file_menu.add_cascade(label="Create Component", menu=self.create_menu)
        self.create_menu.add_command(label="New XCCDF Component", command=self.new_xccdf_component)
        self.create_menu.add_command(label="New CPE Dictionary", command=self.new_cpe_dictionary)
        self.create_menu.add_command(label="New OVAL Check Component", command=lambda: self.new_oval_component("checks"))
        self.create_menu.add_command(label="New CPE OVAL Component", command=lambda: self.new_oval_component("dictionaries"))

        # --- Exit
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        
        # --- Import Menu (its own menu) ---
        self.import_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Import", menu=self.import_menu)
        
        # --- Submenu for CPE Dictionary ---
        cpe_import_menu = tk.Menu(self.import_menu, tearoff=0)
        self.import_menu.add_cascade(label="CPE Dictionary", menu=cpe_import_menu)
        cpe_import_menu.add_command(label="From XML...", command=lambda: self.import_cpe_dictionary(file_type='xml'))
        cpe_import_menu.add_command(label="From YAML...", command=lambda: self.import_cpe_dictionary(file_type='yaml'))

        # --- Submenu for XCCDF
        self.import_menu.add_separator()
        xccdf_import_menu = tk.Menu(self.import_menu, tearoff=0)
        self.import_menu.add_cascade(label="XCCDF", menu=xccdf_import_menu)
        xccdf_import_menu.add_command(label="Profiles from File...", command=self.import_xccdf_profiles)
        xccdf_import_menu.add_command(label="Groups and Rules from File...", command=self.import_xccdf_groups_and_rules)        
        
        # --- OVAL Component Imports (can remain disabled for now) ---
        self.import_menu.add_separator()
        self.import_menu.add_command(label="OVAL Check Component...", command=lambda: self._import_oval_file("OVAL Check", "checks"), state=tk.DISABLED)
        self.import_menu.add_command(label="CPE OVAL Component...", command=lambda: self._import_oval_file("CPE OVAL", "dictionaries"), state=tk.DISABLED)


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
        
        # --- Initialize UI State ---
        self.create_context_menu()
        self.show_welcome_message()
        self._update_contextual_menus() # Call the new helper       

    def _update_contextual_menus(self):
        """Enables or disables menu items based on whether a datastream is loaded."""
        state = tk.NORMAL if self.datastream_collection else tk.DISABLED
        
        # File Menu
        self.file_menu.entryconfig("Close Datastream", state=state)
        self.file_menu.entryconfig("Save Datastream As...", state=state)
        self.file_menu.entryconfig("Create Component", state=state)
        
        self.menu.entryconfig("Import", state=state)

       
##--  [ Top-Level Menu Commands ]---
    def _mark_as_dirty(self):
        """Sets the dirty flag and updates the title bar to indicate unsaved changes."""
        if not self.is_dirty:
            self.is_dirty = True
            self.root.title(self.root.title() + " *")

    def _create_linked_component_ref(self, ds, ref_type, comp_id, comp_cref_id, cat_uri, cat_cref_id):
        """Creates and adds a component-ref with a nested catalog."""
        # Get the correct list from the datastream (e.g., checklists, dictionaries)
        list_getter = getattr(ds, f"get_{ref_type}")
        list_setter = getattr(ds, f"set_{ref_type}")
        
        ref_list = list_getter()
        if ref_list is None:
            ref_list = models.refListType()
            list_setter(ref_list)
            
        # Create the component-ref and its nested catalog/uri
        comp_ref = models.component_ref(id=comp_cref_id, href=f"#{comp_id}")
        catalog_uri = models.uri(name=cat_uri, uri=f"#{cat_cref_id}")
        comp_ref.set_catalog(models.catalog(uri=[catalog_uri]))
        
        ref_list.add_component_ref(comp_ref)
        
    def new_file(self):
        prefix = simpledialog.askstring("New Datastream", "Enter a unique source prefix (no underscores):", parent=self.root)
        if not prefix or '_' in prefix:
            messagebox.showerror("Invalid Prefix", "The prefix cannot be empty or contain underscores.")
            return
        self.prefix = prefix
        
        # --- 1. Create the main datastream collection and stream objects ---
        collection_id = f"scap_{self.prefix}_collection_from_SPECTRE.xml"
        datastream_id = f"scap_{self.prefix}_datastream_from_SPECTRE.xml"

        data_stream = models.data_stream(
            id=datastream_id,
            scap_version="1.3",
            use_case="CONFIGURATION", # Changed back to the correct default
            timestamp=datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        )
        self.datastream_collection = models.data_stream_collection(
            id=collection_id,
            schematron_version="1.3",
            data_stream=[data_stream]
        )
        ds = self.datastream_collection.get_data_stream()[0]
        
        # --- 2. Create all the base components ---
        cpe_comp_id, cpe_cref_id = self.new_cpe_dictionary()
        xccdf_comp_id, xccdf_cref_id = self.new_xccdf_component()
        oval_check_comp_id, oval_check_cref_id = self.new_oval_component("checks")
        cpe_oval_comp_id, cpe_oval_cref_id = self.new_oval_component("dictionaries")

        # --- 3. Create the linked references using the new helper ---
        self._create_linked_component_ref(
            ds, 'checklists', xccdf_comp_id, xccdf_cref_id,
            f"{self.prefix.replace('.', '-')}-collection-oval.xml", oval_check_cref_id
        )
        self._create_linked_component_ref(
            ds, 'dictionaries', cpe_comp_id, cpe_cref_id,
            f"{self.prefix.replace('.', '-')}-collection-cpe-oval.xml", cpe_oval_cref_id
        )
        
        # --- 4. Populate the <checks> list with simple references ---
        ds.set_checks(models.refListType())
        if oval_check_comp_id:
            oval_check_ref = self._create_component_ref(oval_check_cref_id, f"#{oval_check_comp_id}", create_catalog=False)
            ds.get_checks().add_component_ref(oval_check_ref)
        if cpe_oval_comp_id:
            cpe_oval_ref = self._create_component_ref(cpe_oval_cref_id, f"#{cpe_oval_comp_id}", create_catalog=False)
            ds.get_checks().add_component_ref(cpe_oval_ref)

        # --- 5. Finalize UI ---
        self.populate_treeview()
        self._update_contextual_menus()
        self.is_dirty = False
        self.root.title("SPECTRE")

    def close_file(self):
        """Closes the current datastream and resets the application state."""
        if not self.datastream_collection:
            return # Do nothing if no file is open

        if self.is_dirty:
            if not messagebox.askyesno("Unsaved Changes", "You have unsaved changes that will be lost. Do you want to close anyway?"):
                return
        
        # Reset all data and state variables
        self.datastream_collection = None
        self.prefix = None
        self.current_oval_defs = None
        self._reset_state_maps()

        # Clear the UI
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        
        # Reset the UI to its welcome state
        self.is_dirty = False # Reset flag
        self.root.title("SPECTRE") # Reset title
        self.show_welcome_message()
        self._update_contextual_menus()
 
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
            xml_buffer = io.StringIO()

            # 1. Define the schemaLocation for the ROOT element
            root_schema_location = (
                'http://scap.nist.gov/schema/scap/source/1.2 http://scap.nist.gov/schema/scap/1.2/scap-source-data-stream_1.2.xsd '
                'http://checklists.nist.gov/xccdf/1.2 http://csrc.nist.gov/publications/nistir/7275/SP800-70-2/xccdf-1.2.xsd '
                'http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.3.xsd'
            )
            
            # 2. Define ALL namespaces, including the schemaLocation
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
                'xmlns:cat="urn:oasis:names:tc:entity:xmlns:xml:catalog" '
                'xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" '
                'xmlns:cpe="http://cpe.mitre.org/language/2.0" '
                'xmlns:cpe2="http://cpe.mitre.org/language/2.0" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
##                f'xsi:schemaLocation="{root_schema_location}"'
            )

            # 3. Export to the in-memory buffer
            self.datastream_collection.export(
                xml_buffer, 0,
                pretty_print=True,
                name_='data-stream-collection',
                namespaceprefix_='ds:',
                namespacedef_=ns_definitions
            )
            xml_content = xml_buffer.getvalue()
            
            # 4. Post-Processing: Inject OVAL's own schemaLocation
            correct_opening_tag = f'<oval-def:oval_definitions xsi:schemaLocation="{self.oval_schema_location}">'
##            prefixes_to_check = list(set(models.OVAL_PREFIX_MAP.values())) + ['oval-def']
##            for prefix in prefixes_to_check:
##                incorrect_opening_tag = f'<{prefix}:oval_definitions>'
##                if incorrect_opening_tag in xml_content:
##                    xml_content = xml_content.replace(incorrect_opening_tag, correct_opening_tag, 1)
##                    break            
            correct_closing_tag = '</oval-def:oval_definitions>'

            # 5. Write the final, corrected string to the file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write(xml_content)
            messagebox.showinfo("Success", f"File saved successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file: {e}")

        self._update_contextual_menus()
        self.is_dirty = False
        self.root.title("SPECTRE")
        
    def open_file(self):
        """Opens and parses an existing SCAP datastream collection file."""
        file_path = filedialog.askopenfilename(
            title="Open SCAP Datastream Collection",
            filetypes=(("XML files", "*.xml"), ("All files", "*.*"))
        )
        if not file_path:
            return

        try:
            # --- Use our new, robust manual parser ---
            #self.datastream_collection = self._manual_parse_datastream(file_path)
            self.datastream_collection = models.parse(file_path)
            
            if self.datastream_collection.get_id():
                parts = self.datastream_collection.get_id().split('_')
                if len(parts) > 1:
                    self.prefix = parts[1]

            self.populate_treeview()
            self.file_menu.entryconfig("Save Datastream As...", state=tk.NORMAL)
            messagebox.showinfo("Success", f"Successfully opened {file_path}")

        except Exception as e:
            messagebox.showerror("Open Error", f"Failed to open or parse file:\n{e}")

        self._update_contextual_menus()
        self.is_dirty = False
        self.root.title("SPECTRE")
        
    def _manual_parse_datastream(self, file_path):
        """
        Manually parses a datastream XML file to correctly build the object tree,
        bypassing the broken generateDS parser for complex components.
        """
        from lxml import etree

        # Define the namespaces to make the XML searches easier
        ns = {
            'ds': 'http://scap.nist.gov/schema/scap/source/1.2',
            'cdf': 'http://checklists.nist.gov/xccdf/1.2',
            'cpe-dict': 'http://cpe.mitre.org/dictionary/2.0',
            'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
        }

        # Parse the file with a trusted library
        tree = etree.parse(file_path)
        root = tree.getroot()
        
        # Manually create the main collection object from the root attributes
        collection = models.data_stream_collection(
            id=root.attrib.get('id'),
            schematron_version=root.attrib.get('schematron-version')
        )

        # Manually find and build the data-stream element(s)
        for ds_node in root.findall('ds:data-stream', ns):
            # Use the model's parseString to build the simple parts of data-stream
            ds = models.parseString(etree.tostring(ds_node), silence=True)
            collection.add_data_stream(ds)

        # Manually find and build each component
        for comp_node in root.findall('ds:component', ns):
            # Create a generic component to hold the data
            component = models.component(
                id=comp_node.attrib.get('id'),
                timestamp=comp_node.attrib.get('timestamp')
            )
            
            # Now, look inside the component to find out what it really is
            benchmark_node = comp_node.find('xccdf:Benchmark', ns)
            cpe_list_node = comp_node.find('cpe-dict:cpe-list', ns)
            oval_defs_node = comp_node.find('oval-def:oval_definitions', ns)

            if benchmark_node is not None:
                # Use the XCCDF model's parser to build the Benchmark
                benchmark_obj = models.parseString(etree.tostring(benchmark_node), silence=True)
                component.set_Benchmark(benchmark_obj)
            
            elif cpe_list_node is not None:
                cpe_list_obj = models.parseString(etree.tostring(cpe_list_node), silence=True)
                component.set_cpe_list(cpe_list_obj)

            elif oval_defs_node is not None:
                # Use our unified OVAL parser to build the oval_definitions
                # This is the key that makes the OVAL import work correctly
                oval_defs_obj = models.parseString(etree.tostring(oval_defs_node), silence=True)
                component.set_oval_definitions(oval_defs_obj)

            collection.add_component(component)
        
        return collection

##--  [ Imports and such ]---
    def _add_imported_cpe_list(self, parsed_cpe_list):
        """
        A helper function that takes a parsed cpe-list object and handles
        the logic for merging, replacing, or creating a new component.
        """
        new_items = parsed_cpe_list.get_cpe_item()
        if not new_items:
            messagebox.showinfo("No Items", "The selected file does not contain any CPE items to import.")
            return

        existing_cpe_list = self.get_cpe_dictionary()

        if existing_cpe_list is not None:
            choice = messagebox.askquestion(
                "Dictionary Exists",
                "A CPE Dictionary already exists.\n\n"
                "Do you want to MERGE the new items into the existing dictionary?\n\n"
                "(Click 'No' to REPLACE the existing items.)",
                type=messagebox.YESNOCANCEL
            )
            if choice == 'yes': # MERGE
                for item in new_items:
                    if not any(e.get_name() == item.get_name() for e in existing_cpe_list.get_cpe_item()):
                        existing_cpe_list.add_cpe_item(item)
                messagebox.showinfo("Success", "CPE items merged successfully.")
            elif choice == 'no': # REPLACE
                existing_cpe_list.set_cpe_item(new_items)
                messagebox.showinfo("Success", "CPE Dictionary replaced successfully.")
            else: # CANCEL
                return
        else: # No existing dictionary, create a new one
            comp_id = f"scap_{self.prefix}_comp_IMPORTED-cpe-dictionary.xml"
            cpe_component = models.component(
                id=comp_id,
                timestamp=datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                cpe_list=parsed_cpe_list
            )
            self.datastream_collection.add_component(cpe_component)
            ds = self.datastream_collection.get_data_stream()[0]
            if ds.get_dictionaries() is None:
                ds.set_dictionaries(models.refListType())
            
            cref_id = f"scap_{self.prefix}_cref_IMPORTED-cpe-dictionary.xml"
            comp_ref = self._create_component_ref(cref_id, f"#{comp_id}")
            ds.get_dictionaries().add_component_ref(comp_ref)
            messagebox.showinfo("Success", "CPE Dictionary component imported successfully.")

        self.populate_treeview()
        self._mark_as_dirty()

    def import_cpe_dictionary(self, file_type):
        """
        Main dispatcher for importing a CPE dictionary from either XML or YAML.
        """
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return

        file_path = filedialog.askopenfilename(
            title=f"Import CPE Dictionary from {file_type.upper()}",
            filetypes=((f"{file_type.upper()} files", f"*.{file_type}"), ("All files", "*.*"))
        )
        if not file_path:
            return

        try:
            parsed_cpe_list = None
            if file_type == 'xml':
                from lxml import etree
                tree = etree.parse(file_path)
                cpe_list_node = tree.find('.//{http://cpe.mitre.org/dictionary/2.0}cpe-list')
                if cpe_list_node is None:
                    messagebox.showerror("Import Error", "Could not find a <cpe-list> element in the selected file.")
                    return
                parsed_cpe_list = models.parseString(etree.tostring(cpe_list_node), silence=True)
            
            elif file_type == 'yaml':
                import yaml
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_data = yaml.safe_load(f)
                
                parsed_cpe_list = models.ListType()
                oval_ref = yaml_data.get('oval_ref')
                oval_def_prefix = yaml_data.get('oval_def_prefix')
                
                if 'cpe_items' in yaml_data:
                    for category_key, items_dict in yaml_data['cpe_items'].items():
                        for item_key, details in items_dict.items():
                            full_cpe_name = f"cpe:/{category_key}:{item_key}"
                            new_item = models.ItemType(name=full_cpe_name)
                            new_item.add_title(models.TextType(valueOf_=details.get('title', '')))
                            if 'def' in details and 'system' in details and oval_ref and oval_def_prefix:
                                full_def_id = f"oval:{oval_def_prefix}:def:{details['def']}"
                                
                                check = models.CheckType(
                                    system=details['system'],
                                    href=oval_ref,
                                    valueOf_=full_def_id
                                )
                                new_item.add_check(check)

                            parsed_cpe_list.add_cpe_item(new_item)
                            
            if parsed_cpe_list:
                self._add_imported_cpe_list(parsed_cpe_list)

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import CPE dictionary:\n{e}")

    def _select_profiles_to_import_dialog(self, profiles):
        """Shows a dialog with a checklist of profiles to import."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Select Profiles to Import")
        dialog.minsize(width=400, height=300)

        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Select the profiles you want to import:").pack(anchor="w", pady=5)
        
        check_vars = {}
        for profile in profiles:
            profile_id = profile.get_id()
            title = profile.get_title()[0].get_valueOf_() if profile.get_title() else "No Title"
            var = tk.BooleanVar(value=True) # Default to selected
            chk = ttk.Checkbutton(main_frame, text=f"{profile_id} ({title})", variable=var)
            chk.pack(anchor="w", padx=10)
            check_vars[profile_id] = var

        selected_ids = None
        def on_ok():
            nonlocal selected_ids
            selected_ids = [pid for pid, var in check_vars.items() if var.get()]
            dialog.destroy()

        button_frame = ttk.Frame(dialog, padding=(10, 5))
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame, text="Import Selected", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return selected_ids

    def import_xccdf_profiles(self):
        """
        Opens an XCCDF file, finds all <Profile> elements using lxml, and
        imports the user's selection.
        """
        benchmark = self.get_benchmark()
        if not benchmark:
            messagebox.showwarning("No Benchmark", "Please create or open a datastream with an XCCDF component first.")
            return

        file_path = filedialog.askopenfilename(
            title="Import XCCDF Profiles From File",
            filetypes=(("XML files", "*.xml"), ("All files", "*.*"))
        )
        if not file_path:
            return

        try:
            from lxml import etree
            tree = etree.parse(file_path)
            ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.2'}
            profile_nodes = tree.findall('.//xccdf:Benchmark/xccdf:Profile', namespaces=ns)

            if not profile_nodes:
                messagebox.showinfo("No Profiles", "The selected file does not contain any XCCDF profiles.")
                return

            source_profiles = []
            for p_node in profile_nodes:
                profile_obj = models.parseString(etree.tostring(p_node), silence=True)
                if profile_obj:
                    profile_obj.set_refine_rule([])
                    if hasattr(profile_obj, 'set_refine_value'):
                         profile_obj.set_refine_value([])
                         
                # After parsing, clean the object of its old prefixes
                self._reset_xccdf_prefixes(profile_obj)
                source_profiles.append(profile_obj)

            selected_profile_ids = self._select_profiles_to_import_dialog(source_profiles)
            if not selected_profile_ids:
                return


            # 6. Merge the selected profiles into the current benchmark (this part is also correct).
            if benchmark.get_Profile() is None:
                benchmark.set_Profile([])
            
            existing_profile_ids = {p.get_id() for p in benchmark.get_Profile()}
            added_count = 0

            for profile in source_profiles:
                if profile.get_id() in selected_profile_ids:
                    if profile.get_id() not in existing_profile_ids:
                        benchmark.add_Profile(profile)
                        added_count += 1
            
            if added_count > 0:
                self._mark_as_dirty()
                messagebox.showinfo("Import Complete", f"Successfully imported {added_count} new profile(s).")
                self.populate_treeview()
                self.display_details(benchmark)
            else:
                messagebox.showinfo("No Changes", "All selected profiles already exist in the current Benchmark.")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import profiles:\n{e}")

    def _reset_xccdf_prefixes(self, element):
        """
        Recursively walks through an XCCDF element and all its children,
        resetting their namespace prefix to the application's standard 'xccdf'.
        """
        if not hasattr(element, 'ns_prefix_'):
            return # Not a model object we can modify

        # 1. Set the prefix for the current element
        element.ns_prefix_ = 'xccdf'

        # 2. Recurse into all known child elements and lists of elements
        # This list can be expanded to include any XCCDF element type.
        for child_attr in ['status', 'title', 'description', 'version', 'Group', 'Rule', 'select']:
            if hasattr(element, child_attr):
                children = getattr(element, child_attr)
                if isinstance(children, list):
                    for child in children:
                        self._reset_xccdf_prefixes(child)
                elif children is not None:
                    self._reset_xccdf_prefixes(children)

    def import_xccdf_groups_and_rules(self):
        """
        Opens an XCCDF file and orchestrates the import of selected groups
        and their entire contents (subgroups and rules).
        """
        target_benchmark = self.get_benchmark()
        if not target_benchmark:
            messagebox.showwarning("No Benchmark", "Please create or open a datastream with an XCCDF component first.")
            return

        file_path = filedialog.askopenfilename(
            title="Import XCCDF Groups From File",
            filetypes=(("XML files", "*.xml"), ("All files", "*.*"))
        )
        if not file_path:
            return

        try:
            from lxml import etree
            tree = etree.parse(file_path)
            ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.2'}

            # Find all top-level <Group> nodes
            group_nodes = tree.findall('.//xccdf:Benchmark/xccdf:Group', namespaces=ns)
            if not group_nodes:
                messagebox.showinfo("No Groups Found", "The selected file does not contain any top-level XCCDF groups.")
                return

            # Parse just the found group nodes into model objects
            source_groups = [models.parseString(etree.tostring(g_node), silence=True) for g_node in group_nodes]
            
            # Let the user select which top-level groups to import
            selected_group_ids = self._select_groups_to_import_dialog(source_groups)
            if not selected_group_ids:
                return

            # Delegate the complex merging logic to a helper
            added_count = self._import_groups_and_dependencies(
                target_benchmark=target_benchmark,
                source_groups=source_groups,
                group_ids_to_import=selected_group_ids
            )

            if added_count > 0:
                self._mark_as_dirty()
                messagebox.showinfo("Import Complete", f"Successfully imported {added_count} new item(s) (groups and rules).")
                self.populate_treeview()
                self.display_details(target_benchmark)
            else:
                messagebox.showinfo("No Changes", "All selected groups and their contents already exist in the current Benchmark.")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import groups:\n{e}")

    def _select_groups_to_import_dialog(self, groups):
        """Shows a dialog with a checklist of top-level groups to import."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title("Select Groups to Import")
        dialog.minsize(width=450, height=400)

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(main_frame, text="Select the top-level groups you want to import:").pack(anchor="w", pady=5)

        canvas = tk.Canvas(main_frame, borderwidth=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        checkbox_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=checkbox_frame, anchor="nw")

        def on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        checkbox_frame.bind("<Configure>", on_configure)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        check_vars = {}
        for group in groups:
            group_id = group.get_id()
            title = group.get_title()[0].get_valueOf_() if group.get_title() else "No Title"
            var = tk.BooleanVar(value=True)
            # Add the checkboxes to the INNER frame
            chk = ttk.Checkbutton(checkbox_frame, text=f"{group_id} ({title})", variable=var)
            chk.pack(anchor="w", padx=10, pady=2)
            check_vars[group_id] = var

        # --- Button Frame for Select/Deselect All ---
        button_frame_top = ttk.Frame(main_frame)
        button_frame_top.pack(fill=tk.X, before=canvas, pady=(0, 5)) # Place it before the canvas

        def select_all():
            for var in check_vars.values():
                var.set(True)
        
        def deselect_all():
            for var in check_vars.values():
                var.set(False)

        ttk.Button(button_frame_top, text="Select All", command=select_all).pack(side=tk.LEFT)
        ttk.Button(button_frame_top, text="Deselect All", command=deselect_all).pack(side=tk.LEFT, padx=5)

        selected_ids = None
        def on_ok():
            nonlocal selected_ids
            selected_ids = [gid for gid, var in check_vars.items() if var.get()]
            dialog.destroy()

        # --- OK/Cancel buttons at the bottom ---
        button_frame_bottom = ttk.Frame(dialog, padding=(10, 5))
        button_frame_bottom.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(button_frame_bottom, text="Import Selected", command=on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame_bottom, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
        self._center_dialog(dialog)
        dialog.wait_window()
        return selected_ids

    def _import_groups_and_dependencies(self, target_benchmark, source_groups, group_ids_to_import):
        """
        Recursively imports selected groups and all their children (subgroups and rules),
        avoiding duplicates.
        """
        # 1. Get a set of all item IDs that ALREADY EXIST in the TARGET benchmark
        existing_target_ids = set()
        def get_target_ids(items):
            for item in items:
                existing_target_ids.add(item.get_id())
                if isinstance(item, models.groupType) and item.get_Group():
                    get_target_ids(item.get_Group())
                if isinstance(item, models.groupType) and item.get_Rule():
                    get_target_ids(item.get_Rule())
        if target_benchmark.get_Group():
            get_target_ids(target_benchmark.get_Group())

        # 2. Loop through the source groups the user selected
        added_count = 0
        for group in source_groups:
            if group.get_id() in group_ids_to_import:
                # 3. Check if this top-level group already exists. If not, add it.
                if group.get_id() not in existing_target_ids:
                    if target_benchmark.get_Group() is None:
                        target_benchmark.set_Group([])
                    self._reset_xccdf_prefixes(group)
                    target_benchmark.add_Group(group)
                    added_count += 1
        
        return added_count
                   
           
##--  [ Core Component Creators ]---
    def new_cpe_dictionary(self):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return None # Return None on failure
        
        if self.get_cpe_dictionary() is not None:
            messagebox.showwarning("Exists", "A CPE Dictionary component already exists in this datastream.")
            return None # Return None on failure
        
        new_cpe_list = models.ListType()
        comp_id = f"scap_{self.prefix}_comp_SPECTRE-cpe-dictionary.xml"
        cref_id = f"scap_{self.prefix}_cref_SPECTRE-cpe-dictionary.xml"
        cpe_component = models.component(
            id=comp_id,
            timestamp=datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            cpe_list=new_cpe_list
        )
        self.datastream_collection.add_component(cpe_component)
        return comp_id, cref_id # Return the new component's ID

    def new_xccdf_component(self):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return None, None
        if self.get_benchmark() is not None:
            messagebox.showwarning("Exists", "An XCCDF Benchmark component already exists in this datastream.")
            return None, None
        
        benchmark = models.Benchmark(id=f"xccdf_benchmark_{uuid.uuid4()}", lang="en", style="SCAP_1.2", resolved="true")
        benchmark.set_title([models.textWithSubType(valueOf_='New Security Benchmark')])
        benchmark.status = [models.status(valueOf_='incomplete', date=datetime.now().strftime('%Y-%m-%d'))]
        benchmark.description = [models.htmlTextWithSubType(valueOf_='A new benchmark description.')]
        benchmark.version = models.versionType(valueOf_='1.0.0')
        benchmark.metadata = [models.metadataType()]
        new_group = models.groupType(id="G-1", title=[models.textWithSubType(valueOf_='Default Group')])
        new_group.description = [models.htmlTextWithSubType(valueOf_='')]
        new_rule = models.ruleType(id="R-1", severity="unknown", title=[models.textWithSubType(valueOf_='Default Rule')])
        new_rule.description = [models.htmlTextWithSubType(valueOf_='')]
        new_group.Rule.append(new_rule)
        benchmark.Group.append(new_group)
        
        comp_id = f"scap_{self.prefix}_comp_SPECTRE-xccdf.xml"
        cref_id = f"scap_{self.prefix}_cref_SPECTRE-xccdf.xml"
        xccdf_component = models.component(
            id=comp_id,
            timestamp=datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            Benchmark=benchmark
        )
        self.datastream_collection.add_component(xccdf_component)
        
        return comp_id, cref_id

    def new_oval_component(self, ref_list_name):
        if not self.datastream_collection:
            messagebox.showwarning("No Datastream", "Please create a new datastream first.")
            return None, None

        new_oval_defs = models.oval_definitions()
        
        # --- Use conditional logic to generate the correct component ID
        if ref_list_name == "dictionaries":
            comp_id = f"scap_{self.prefix}_comp_SPECTRE-cpe-oval.xml"
            cref_id = f"scap_{self.prefix}_cref_SPECTRE-cpe-oval.xml"
        else: # Assumes "checks"
            comp_id = f"scap_{self.prefix}_comp_SPECTRE-oval.xml"
            cref_id = f"scap_{self.prefix}_cref_SPECTRE-oval.xml"

        oval_component = models.component(
            id=comp_id,
            timestamp=datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            oval_definitions=new_oval_defs
        )
        self.datastream_collection.add_component(oval_component)
        
        return comp_id, cref_id # Always return the component ID


##--  [ Main UI Handlers and Population ]---
    def populate_treeview(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        self._reset_state_maps()
        
        if not self.datastream_collection:
            return
        
        # --- 1. Add the root nodes ---
        dsc_id = self.tree.insert("", "end", text=f"Datastream Collection ({self.datastream_collection.get_id()})", open=True)
        self.maps['item'][dsc_id] = self.datastream_collection

        for ds in self.datastream_collection.get_data_stream():
            ds_id = self.tree.insert(dsc_id, "end", text=f"DataStream ({ds.get_id()})", open=True)
            self.maps['item'][ds_id] = ds
        
        # --- 2. Add the main "Components" folder ---
        comp_node_id = self.tree.insert(dsc_id, "end", text="Components", open=True)
        
        # --- 3. Delegate the complex part to a helper ---
        for comp in self.datastream_collection.get_component():
            self._add_component_to_tree(comp_node_id, comp)

    def _add_component_to_tree(self, parent_id, component_obj):
        """Helper to add a single component and its children to the treeview."""
        # --- Determine the correct display name ---
        comp_text = f"Component ({component_obj.get_id()})"
        if component_obj.Benchmark:
            comp_text = f"XCCDF Component ({component_obj.get_id()})"
        elif component_obj.cpe_list:
            comp_text = f"CPE Dictionary Component ({component_obj.get_id()})"
        elif component_obj.oval_definitions:
            if "cpe-oval" in component_obj.get_id():
                comp_text = f"CPE OVAL Component ({component_obj.get_id()})"
            else:
                comp_text = f"OVAL Check Component ({component_obj.get_id()})"

        # --- Add the component node ---
        c_id = self.tree.insert(parent_id, "end", text=comp_text, open=True)
        self.maps['item'][c_id] = component_obj
        
        # --- If it's a benchmark, add its specific children ---
        if component_obj.Benchmark:
            benchmark_obj = component_obj.Benchmark
            title_text = benchmark_obj.title[0].get_valueOf_() if benchmark_obj.title else ""
            b_id = self.tree.insert(c_id, "end", text=f"Benchmark: {title_text}", open=True)
            self.maps['item'][b_id] = benchmark_obj
            
            if benchmark_obj.Group:
                for group in benchmark_obj.Group:
                    self._add_group_to_tree(b_id, group)
                    
    def on_tree_select(self, event):
        selected_id = self.tree.focus()
        if not selected_id:
            return
        item_data = self.maps['item'].get(selected_id)
        self.display_details(item_data)

    def _create_combobox_editor(self, parent, label_text, obj, attr, options, default_value=None):
        """Creates a labeled Combobox for editing an attribute."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(frame, text=label_text, width=15).pack(side=tk.LEFT, anchor='n')
        
        current_value = getattr(obj, f"get_{attr}", lambda: default_value)() or default_value
        var = tk.StringVar(self.root, value=current_value)
        
        combo = ttk.Combobox(frame, textvariable=var, values=options, state="readonly")
        combo.pack(fill=tk.X, expand=True)
        
        # Use a lambda to correctly capture the variables
        combo.bind("<<ComboboxSelected>>", lambda event, o=obj, a=attr, v=var: getattr(o, f"set_{a}")(v.get()))
        
    def display_details(self, item):
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        if not item: 
            self.show_welcome_message()
            return
            
        if isinstance(item, models.data_stream_collection):
            self.create_detail_entry(self.detail_frame, "ID", item, "id", read_only=True)
            self.create_detail_entry(self.detail_frame, "Schematron Version", item, "schematron_version")
            
            ttk.Separator(self.detail_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

            prefix_frame = ttk.LabelFrame(self.detail_frame, text="Update Datastream Prefix", padding=5)
            prefix_frame.pack(fill=tk.X, expand=False)
            
            ttk.Label(prefix_frame, text="New Prefix:").pack(side=tk.LEFT, padx=5)
            
            prefix_var = tk.StringVar(value=self.prefix or "")
            prefix_entry = ttk.Entry(prefix_frame, textvariable=prefix_var)
            prefix_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            
            ttk.Button(prefix_frame, text="Update All IDs", 
                       command=lambda: self._update_prefix(prefix_var.get())).pack(side=tk.LEFT, padx=5)

        elif isinstance(item, models.data_stream):
            attr_frame = ttk.Frame(self.detail_frame)
            attr_frame.pack(fill=tk.X, expand=False)
            
            self.create_detail_entry(self.detail_frame, "ID", item, "id", read_only=True)
            self._create_combobox_editor(self.detail_frame, "SCAP Version", item, "scap_version", ['1.0', '1.1', '1.2', '1.3'], "1.3")
            self._create_combobox_editor(self.detail_frame, "Use Case", item, "use_case", ['CONFIGURATION', 'VULNERABILITY', 'INVENTORY', 'OTHER'], "OTHER")

            ttk.Separator(self.detail_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
            
            refs_frame = ttk.Frame(self.detail_frame)
            refs_frame.pack(fill=tk.BOTH, expand=True)

            self._create_ref_list_viewer(refs_frame, "Dictionaries", "dictionaries")
            self._create_ref_list_viewer(refs_frame, "Checklists", "checklists")
            self._create_ref_list_viewer(refs_frame, "Checks", "checks")
            
            ttk.Button(refs_frame, text="Update References", command=self._update_datastream_references).pack(pady=10)
            
        elif isinstance(item, models.component):
            if item.cpe_list is not None:
                self.display_cpe_dictionary_manager(item.cpe_list)
            elif item.oval_definitions is not None:
                self.display_oval_manager(item.oval_definitions)
            elif item.Benchmark is not None:
                # If it's a component with a benchmark, display the benchmark editor
                self.display_details(item.Benchmark)
            else:
                # Fallback for empty or unknown components
                self.create_detail_entry(self.detail_frame, "ID", item, "id")
            
        elif isinstance(item, models.Benchmark):
            notebook = ttk.Notebook(self.detail_frame)
            notebook.pack(fill=tk.BOTH, expand=True, pady=5)
            
            tab_general = ttk.Frame(notebook, padding=10)
            tab_platforms = ttk.Frame(notebook, padding=10)
            tab_profiles = ttk.Frame(notebook, padding=10)
            
            notebook.add(tab_general, text="General")
            notebook.add(tab_platforms, text="Platforms")
            notebook.add(tab_profiles, text="Profiles")
            
            self.create_detail_entry(tab_general, "Benchmark ID", item, "id")
            self.create_text_editor(tab_general, "Title", item, "title")
            
            import_button_frame = ttk.Frame(tab_platforms)
            import_button_frame.pack(fill=tk.X, pady=(0, 10))
            ttk.Button(import_button_frame, text="Import All Platforms into CPE Dictionary", command=self._sync_platforms_to_cpe).pack(anchor='e')            
            
            if item.version is None: item.version = models.versionType(valueOf_='')
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
                if not item.status: item.status.append(models.statusType())
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
                    if not item.status: item.status.append(models.statusType())
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
                if item.metadata is None or not item.metadata: item.metadata = [models.metadataType()]
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

            # --- Platforms Tab UI
            platform_frame = ttk.LabelFrame(tab_platforms, text="Platform Definitions", padding=5)
            platform_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
            
            self.platforms_tree = ttk.Treeview(platform_frame, columns=("id",), show="headings", height=4)
            self.platforms_tree.heading("id", text="Platform ID")
            self.platforms_tree.pack(fill=tk.BOTH, expand=True)
            
            self.platforms_tree.bind("<<TreeviewSelect>>", self.on_platform_select)
            
            button_frame = ttk.Frame(platform_frame)
            button_frame.pack(fill=tk.X, pady=5)
            ttk.Button(button_frame, text="Add", command=self.add_platform).pack(side=tk.LEFT, padx=2)
            ttk.Button(button_frame, text="Edit", command=self.edit_platform).pack(side=tk.LEFT, padx=2)
            ttk.Button(button_frame, text="Remove", command=self.remove_platform).pack(side=tk.LEFT, padx=2)
            
            self.logical_test_editor_frame = ttk.Frame(tab_platforms)
            self.logical_test_editor_frame.pack(fill=tk.BOTH, expand=True, pady=5)
            self.create_benchmark_platform_manager(tab_platforms, item)
            
            self.populate_platforms_tree()
            children = self.platforms_tree.get_children()
            if children:
                first_item_id = children[0]
                self.platforms_tree.selection_set(first_item_id)
                self.platforms_tree.focus(first_item_id)
                # Manually trigger the selection event handler to load the details
                self.on_platform_select(None)
            else:
                # If there are no platforms, ensure the details panel is empty
                self.display_logical_test_details() 
            
            # Profiles
            self._create_full_profile_editor(tab_profiles, item)

        elif isinstance(item, models.groupType):
            details_frame = ttk.Frame(self.detail_frame)
            details_frame.pack(fill=tk.X, expand=False)
            
            self.create_detail_entry(details_frame, "Group ID", item, "id")
            self.create_text_editor(details_frame, "Group Title", item, "title")
            self.create_text_editor(details_frame, "Description", item, "description", height=4)
            self.create_item_platform_manager(details_frame, item)

            ttk.Separator(self.detail_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
            
            # --- Bottom section for the new shuttle editor ---
            shuttle_container = ttk.Frame(self.detail_frame)
            shuttle_container.pack(fill=tk.BOTH, expand=True)
            self._create_group_shuttle_editor(shuttle_container, item)

        elif isinstance(item, models.ruleType):
            
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
            
            if item.version is None: item.version = models.versionType(valueOf_='')
            
            self.create_detail_entry(tab_general, "Version", item.version, "valueOf_")
            
            if not item.check: item.check = [models.checkType(system='http://oval.mitre.org/XMLSchema/oval-definitions-5')]
            
            check = item.check[0]
            
            self.create_detail_entry(tab_checks, "System", check, "system")
            
            if not check.check_content_ref: check.check_content_ref = [models.checkContentRefType()]
            
            self.create_detail_entry(tab_checks, "Check Content Ref (href)", check.check_content_ref[0], "href")
            
            if not item.fixtext: item.set_fixtext([models.fixTextType(valueOf_='')])
            
            self.create_text_editor(tab_remediation, "Fix Text", item.fixtext[0], "valueOf_", height=6)
            
            if not item.fix: item.set_fix([models.fixType()])
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
              
        else:
            # If nothing else matches, show a simple message
            self.show_welcome_message()

    def _create_full_profile_editor(self, parent_frame, benchmark_obj):
        """Creates a comprehensive UI for managing all aspects of XCCDF Profiles."""
        # Main container for the entire editor
        editor_pane = ttk.PanedWindow(parent_frame, orient=tk.VERTICAL)
        editor_pane.pack(fill=tk.BOTH, expand=True)

        # --- Top Pane: A smaller box for the list of all Profiles ---
        profile_list_frame = ttk.LabelFrame(editor_pane, text="Profiles", padding=5)
        editor_pane.add(profile_list_frame, weight=1) # Smaller weight means it takes less space

        profile_tree = ttk.Treeview(profile_list_frame, columns=("id",), show="headings", height=3)
        profile_tree.heading("id", text="Profile ID")
        profile_tree.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        
        # --- Bottom Pane: The editor for the currently selected profile ---
        selection_editor_frame = ttk.Frame(editor_pane, padding=5)
        editor_pane.add(selection_editor_frame, weight=8) # Larger weight for the main editor

        # --- Details for the selected profile (ID, Title, etc.) ---
        profile_details_frame = ttk.LabelFrame(selection_editor_frame, text="Profile Details", padding=5)
        profile_details_frame.pack(fill=tk.X, expand=False, pady=(0, 10))
        
        # --- The shuttle editor will appear below the details ---
        shuttle_frame = ttk.Frame(selection_editor_frame)
        shuttle_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- LOGIC ---
        def populate_profile_list():
            profile_tree.delete(*profile_tree.get_children())
            if benchmark_obj.Profile:
                for p in benchmark_obj.Profile:
                    profile_tree.insert("", "end", values=(p.get_id(),), text=p.get_id())

        def on_profile_select(event):
            # Clear the right-hand editor
            for widget in profile_details_frame.winfo_children(): widget.destroy()
            for widget in shuttle_frame.winfo_children(): widget.destroy()
            
            selected_id = profile_tree.focus()
            if not selected_id: return
            
            profile_id = profile_tree.item(selected_id)['text']
            selected_profile = next((p for p in benchmark_obj.Profile if p.get_id() == profile_id), None)
            if not selected_profile: return
            
            # --- Build the details editor for the selected profile ---
            self.create_detail_entry(profile_details_frame, "Profile ID", selected_profile, "id")
            self.create_text_editor(profile_details_frame, "Title", selected_profile, "title")
            self.create_text_editor(profile_details_frame, "Description", selected_profile, "description", height=3)

            # --- Build the shuttle editor ---
            self._create_profile_selection_shuttle(shuttle_frame, selected_profile)

        profile_tree.bind("<<TreeviewSelect>>", on_profile_select)

        def add_profile():
            new_id = simpledialog.askstring("Add Profile", "Enter new profile ID:", parent=self.root)
            if not new_id: return
            if benchmark_obj.Profile and any(p.get_id() == new_id for p in benchmark_obj.Profile):
                messagebox.showwarning("Duplicate ID", "A profile with that ID already exists.")
                return
            
            new_profile = models.profileType(id=new_id)
            new_profile.set_title([models.textWithSubType(valueOf_="New Profile")])
            if benchmark_obj.Profile is None:
                benchmark_obj.Profile = []
                
            benchmark_obj.Profile.append(new_profile)
            self.populate_treeview()
            populate_profile_list()
            self._mark_as_dirty()
            
        def remove_profile():
            selected = profile_tree.focus()
            if not selected: return
            id_to_remove = profile_tree.item(selected)['values'][0]
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to remove profile '{id_to_remove}'?"):
                if benchmark_obj.Profile:
                    benchmark_obj.Profile = [p for p in benchmark_obj.Profile if p.get_id() != id_to_remove]
                    self.populate_treeview()
                    populate_profile_list()
                    self._mark_as_dirty()

        button_frame = ttk.Frame(profile_list_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Add Profile...", command=add_profile).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Remove Selected", command=remove_profile).pack(side=tk.LEFT, padx=2)

        populate_profile_list()

    def _create_profile_selection_shuttle(self, parent_frame, profile_obj):
        """Creates the shuttle UI for managing a profile's selections using a robust grid layout."""
        
        # --- START FINAL FIX ---
        # 1. Use a standard Frame as the main container for the grid.
        shuttle_container = ttk.Frame(parent_frame)
        shuttle_container.pack(fill=tk.BOTH, expand=True)

        # --- Configure the grid columns ---
        # Column 0 (Available) will expand.
        shuttle_container.columnconfigure(0, weight=1)
        # Column 1 (Buttons) will NOT expand.
        shuttle_container.columnconfigure(1, weight=0)
        # Column 2 (Selected) will expand.
        shuttle_container.columnconfigure(2, weight=1)
        shuttle_container.rowconfigure(0, weight=1)

        # --- 2. Create and place the frames on the grid ---
        available_frame = ttk.LabelFrame(shuttle_container, text="Available Items", padding=5)
        button_frame = ttk.Frame(shuttle_container, padding=5)
        selected_frame = ttk.LabelFrame(shuttle_container, text="Profile Selections", padding=5)

        available_frame.grid(row=0, column=0, sticky="nsew", padx=2)
        button_frame.grid(row=0, column=1, sticky="ns", pady=20)
        selected_frame.grid(row=0, column=2, sticky="nsew", padx=2)
        # --- END FINAL FIX ---

        # The rest of your code for creating the widgets inside these frames is perfect.
        
        available_tree = ttk.Treeview(available_frame)
        available_tree.pack(fill=tk.BOTH, expand=True)
        
        selected_tree = ttk.Treeview(selected_frame, columns=("status",), show="tree headings", height=10)
        selected_tree.heading("#0", text="Item")
        selected_tree.heading("status", text="Selected")
        selected_tree.column("status", width=80, anchor='center')
        selected_tree.pack(fill=tk.BOTH, expand=True)
        
        benchmark_obj = self.get_benchmark()

        def get_all_item_ids(groups):
            ids = {}
            def recurse(items):
                for item in items:
                    if isinstance(item, (models.groupType, models.ruleType)):
                        ids[item.get_id()] = item
                        if isinstance(item, models.groupType) and item.Group: recurse(item.Group)
                        if isinstance(item, models.groupType) and item.Rule: recurse(item.Rule)
            if groups: recurse(groups)
            return ids
        all_benchmark_items = get_all_item_ids(benchmark_obj.Group)
        
        def populate_trees():
            available_tree.delete(*available_tree.get_children())
            selected_tree.delete(*selected_tree.get_children())
            
            if profile_obj.select is None: profile_obj.select = []
            selected_idrefs = {s.get_idref() for s in profile_obj.select}
            
            def populate_available_recursively(parent_node, items):
                for item in items:
                    if item.get_id() not in selected_idrefs:
                        title = item.title[0].get_valueOf_() if item.title else ""
                        node_id = available_tree.insert(parent_node, "end", text=f"{item.get_id()}: {title}", open=False, values=[item.get_id()])
                        if isinstance(item, models.groupType) and item.Group: populate_available_recursively(node_id, item.Group)
                        if isinstance(item, models.groupType) and item.Rule: populate_available_recursively(node_id, item.Rule)

            if benchmark_obj.Group:
                populate_available_recursively("", benchmark_obj.Group)

            for selection in profile_obj.select:
                idref = selection.get_idref()
                status_str = "Yes" if selection.get_selected() else "No"
                item_obj = all_benchmark_items.get(idref)
                title = item_obj.title[0].get_valueOf_() if item_obj and item_obj.title else ""
                selected_tree.insert("", "end", text=f"{idref}: {title}", values=(status_str, idref))
        
        def move_item(is_selected_bool):
            selected_id = available_tree.focus()
            if not selected_id: return
            idref = available_tree.item(selected_id)['values'][0]
            
            profile_obj.select.append(models.profileSelectType(idref=idref, selected=is_selected_bool))
            populate_trees()
            self._mark_as_dirty()
        
        def remove_selection():
            selected_in_profile = selected_tree.focus()
            if not selected_in_profile: return
            idref_to_remove = selected_tree.item(selected_in_profile)['values'][1]
            
            profile_obj.select = [s for s in profile_obj.select if s.get_idref() != idref_to_remove]
            populate_trees()
            self._mark_as_dirty()
        
        ttk.Button(button_frame, text="Select >>", command=lambda: move_item(True)).pack(pady=5)
        ttk.Button(button_frame, text="Unselect >>", command=lambda: move_item(False)).pack(pady=5)
        ttk.Button(button_frame, text="<< Remove", command=remove_selection).pack(pady=20)
        
        populate_trees()
        
    def _update_prefix(self, new_prefix):
        """Validates and applies a new prefix to all relevant IDs in the datastream."""
        if not self.datastream_collection or not self.prefix or not new_prefix:
            return
            
        if '_' in new_prefix:
            messagebox.showerror("Invalid Prefix", "The prefix cannot contain underscores.")
            return

        if new_prefix == self.prefix:
            return # No change needed

        # Ask for confirmation
        if not messagebox.askyesno("Confirm Prefix Change", 
                                   f"This will change the prefix '{self.prefix}' to '{new_prefix}' for all "
                                   f"related IDs. This action cannot be undone.\n\nAre you sure you want to continue?"):
            return

        old_prefix = self.prefix
        
        # --- Update the main collection and stream IDs ---
        collection_id = self.datastream_collection.get_id().replace(f"scap_{old_prefix}_", f"scap_{new_prefix}_")
        self.datastream_collection.set_id(collection_id)
        
        ds = self.datastream_collection.get_data_stream()[0]
        ds_id = ds.get_id().replace(f"scap_{old_prefix}_", f"scap_{new_prefix}_")
        ds.set_id(ds_id)

        # --- Update all component IDs ---
        for comp in self.datastream_collection.get_component():
            comp_id = comp.get_id().replace(f"scap_{old_prefix}_", f"scap_{new_prefix}_")
            comp.set_id(comp_id)

        # --- Update all component reference IDs and URIs ---
        for ref_list_name in ['dictionaries', 'checklists', 'checks']:
            ref_list = getattr(ds, f"get_{ref_list_name}")()
            if ref_list and ref_list.get_component_ref():
                for ref in ref_list.get_component_ref():
                    ref_id = ref.get_id().replace(f"scap_{old_prefix}_", f"scap_{new_prefix}_")
                    ref.set_id(ref_id)
                    ref.set_href(ref.get_href().replace(f"scap_{old_prefix}_", f"scap_{new_prefix}_"))
                    
                    if ref.get_catalog():
                        for uri in ref.get_catalog().get_uri():
                            uri.set_name(uri.get_name().replace(old_prefix, new_prefix))
        
        # --- Finalize the update ---
        self.prefix = new_prefix
        self.populate_treeview() # Refresh the UI to show all the new IDs
        self.display_details(self.datastream_collection) # Refresh the details view
        self._mark_as_dirty()
        messagebox.showinfo("Success", "All prefixes have been updated.")

    def _create_group_shuttle_editor(self, parent_frame, group_obj):
        """Creates a shuttle editor to move groups/rules in and out of the given group."""
        # Main container for the shuttle editor
        pw = ttk.PanedWindow(parent_frame, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True, pady=10)

        # --- Left Side: Available Items ---
        available_frame = ttk.LabelFrame(pw, text="Available Benchmark Items", padding=5)
        pw.add(available_frame, weight=2)
        available_tree = ttk.Treeview(available_frame)
        available_tree.pack(fill=tk.BOTH, expand=True)

        # --- Middle: Move Buttons ---
        button_frame = ttk.Frame(pw, padding=5)
        pw.add(button_frame, weight=0)
        
        # --- Right Side: Current Group's Children ---
        selected_frame = ttk.LabelFrame(pw, text=f"Items in '{group_obj.get_id()}'", padding=5)
        pw.add(selected_frame, weight=2)
        selected_tree = ttk.Treeview(selected_frame)
        selected_tree.pack(fill=tk.BOTH, expand=True)
        
        # --- LOGIC ---
        benchmark_obj = self.get_benchmark()

        def get_all_benchmark_items(start_node):
            """Recursively gets all groups and rules."""
            items = []
            if hasattr(start_node, 'Group') and start_node.Group:
                for g in start_node.Group:
                    items.append(g)
                    items.extend(get_all_benchmark_items(g))
            if hasattr(start_node, 'Rule') and start_node.Rule:
                items.extend(start_node.Rule)
            return items

        def populate_trees():
            available_tree.delete(*available_tree.get_children())
            selected_tree.delete(*selected_tree.get_children())
            
            all_items = get_all_benchmark_items(benchmark_obj)
            current_children = (group_obj.Group or []) + (group_obj.Rule or [])
            
            # Populate Available Tree (all items not in the current group)
            for item in all_items:
                if item not in current_children and item is not group_obj:
                    title = item.title[0].get_valueOf_() if item.title else ""
                    item_type = "Group" if isinstance(item, models.groupType) else "Rule"
                    available_tree.insert("", "end", text=f"{item_type}: {item.get_id()}", values=[item.get_id()])

            # Populate Selected Tree (immediate children of the current group)
            for item in current_children:
                title = item.title[0].get_valueOf_() if item.title else ""
                item_type = "Group" if isinstance(item, models.groupType) else "Rule"
                selected_tree.insert("", "end", text=f"{item_type}: {item.get_id()}", values=[item.get_id()])

        def move_item_in():
            selected_id = available_tree.focus()
            if not selected_id: return
            item_id_to_move = available_tree.item(selected_id)['values'][0]
            
            item_to_move = next((i for i in get_all_benchmark_items(benchmark_obj) if i.get_id() == item_id_to_move), None)
            if not item_to_move: return
            
            old_parent = self.find_parent(benchmark_obj, item_to_move)
            if old_parent:
                if isinstance(item_to_move, models.groupType): old_parent.Group.remove(item_to_move)
                else: old_parent.Rule.remove(item_to_move)
            
            if isinstance(item_to_move, models.groupType):
                if group_obj.Group is None: group_obj.Group = []
                group_obj.Group.append(item_to_move)
            else:
                if group_obj.Rule is None: group_obj.Rule = []
                group_obj.Rule.append(item_to_move)

            self.populate_treeview() # Full refresh is needed
            populate_trees()
            self._mark_as_dirty()

        def move_item_out():
            selected_id = selected_tree.focus()
            if not selected_id: return
            item_id_to_move = selected_tree.item(selected_id)['values'][0]
            
            item_to_move = next((i for i in get_all_benchmark_items(group_obj) if i.get_id() == item_id_to_move), None)
            if not item_to_move: return
            
            # Remove from current group
            if isinstance(item_to_move, models.groupType): group_obj.Group.remove(item_to_move)
            else: group_obj.Rule.remove(item_to_move)

            # Add to top-level benchmark
            if isinstance(item_to_move, models.groupType):
                if benchmark_obj.Group is None: benchmark_obj.Group = []
                benchmark_obj.Group.append(item_to_move)
            else: # It's a rule, needs a parent group
                 # For simplicity, we add it to the first top-level group
                if benchmark_obj.Group:
                    benchmark_obj.Group[0].Rule.append(item_to_move)

            self.populate_treeview()
            populate_trees()
            self._mark_as_dirty()

        # Place the buttons vertically in their dedicated frame
        ttk.Button(button_frame, text="Move In >>", command=move_item_in).pack(pady=5)
        ttk.Button(button_frame, text="<< Move Out", command=move_item_out).pack(pady=20)
        
        populate_trees()
        
## Need to Make Smarter 
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
        
        self.right_clicked_item_data = self.maps['item'].get(item_id)
        
        # This is a great pattern: disable all, then enable only valid options.
        self.context_menu.entryconfig("Add Group", state=tk.DISABLED)
        self.context_menu.entryconfig("Add Rule", state=tk.DISABLED)
        self.context_menu.entryconfig("Delete", state=tk.DISABLED)

        # The logic for what to enable is well-structured.
        if isinstance(self.right_clicked_item_data, models.Benchmark):
            self.context_menu.entryconfig("Add Group", state=tk.NORMAL)
        elif isinstance(self.right_clicked_item_data, models.groupType):
            self.context_menu.entryconfig("Add Group", state=tk.NORMAL)
            self.context_menu.entryconfig("Add Rule", state=tk.NORMAL)
            self.context_menu.entryconfig("Delete", state=tk.NORMAL)
        elif isinstance(self.right_clicked_item_data, models.ruleType):
            self.context_menu.entryconfig("Delete", state=tk.NORMAL)
        elif isinstance(self.right_clicked_item_data, models.component):
            # A future improvement could be to check if the component is deletable
            self.context_menu.entryconfig("Delete", state=tk.NORMAL)
            
        self.context_menu.post(event.x_root, event.y_root)
       
    def add_group(self):
        if not isinstance(self.right_clicked_item_data, (models.Benchmark, models.groupType)): return
        new_id = f"G-{uuid.uuid4()}"
        new_group = models.groupType(id=new_id)
        new_group.set_title([models.textWithSubType(valueOf_='New Group')])
        new_group.description = [models.htmlTextWithSubType(valueOf_='')]
        self.right_clicked_item_data.Group.append(new_group)
        self.populate_treeview()
        self._mark_as_dirty()

    def add_rule(self):
        if not isinstance(self.right_clicked_item_data, models.groupType): return
        new_id = f"R-{uuid.uuid4()}"
        new_rule = models.ruleType(id=new_id, severity="unknown")
        new_rule.set_title([models.textWithSubType(valueOf_='New Rule')])
        new_rule.description = [models.htmlTextWithSubType(valueOf_='')]
        if self.right_clicked_item_data.Rule is None:
            self.right_clicked_item_data.Rule = []
        self.right_clicked_item_data.Rule.append(new_rule)
        self.populate_treeview()
        self._mark_as_dirty()

    def delete_item(self):
        item_to_delete = self.right_clicked_item_data
        if not item_to_delete: return

        if isinstance(item_to_delete, (models.groupType, models.ruleType)):
            item_type = "Group" if isinstance(item_to_delete, models.groupType) else "Rule"
            item_id = item_to_delete.get_id()
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete this {item_type} ({item_id})?"):
                benchmark = self.get_benchmark()
                if not benchmark:
                    messagebox.showerror("Error", "Could not find the Benchmark to delete from.")
                    return
                
                parent = self.find_parent(benchmark, item_to_delete)
                if parent:
                    if isinstance(item_to_delete, models.groupType):
                        parent.Group.remove(item_to_delete)
                    else: # Is a ruleType
                        parent.Rule.remove(item_to_delete)
                        
                    self.populate_treeview()
                    self.show_welcome_message()
                    self._mark_as_dirty() # Mark that a change has occurred
                else:
                    messagebox.showerror("Error", "Could not find the parent of the item to delete.")
        
        elif isinstance(item_to_delete, models.component):
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
                self._mark_as_dirty()

    def find_parent(self, start_node, child_to_find):
        if isinstance(start_node, models.data_stream_collection):
            benchmark = self.get_benchmark()
            if benchmark:
                return self.find_parent(benchmark, child_to_find)
        if isinstance(start_node, (models.Benchmark, models.groupType)):
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


##--  [  CPE Manager UI & Commands ]---
    def display_cpe_dictionary_manager(self, cpe_list_obj):
        """Creates the UI for managing CPE items within a CPE Dictionary."""
        self.maps['cpe_item'] = {}
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
        
        ttk.Separator(button_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        ttk.Button(button_frame, text="Sync All to XCCDF Platforms", command=self._sync_cpe_to_platforms).pack(side=tk.LEFT, padx=2)

    def populate_cpe_tree(self, cpe_list_obj):
        """Clears and repopulates the CPE items treeview."""
        for i in self.cpe_items_tree.get_children():
            self.cpe_items_tree.delete(i)
        
        self.maps['cpe_item'].clear()
        
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
                self.maps['cpe_item'][item_id] = cpe_item

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
        title_text = ""
        if item_to_edit and item_to_edit.get_title():
            title_text = item_to_edit.get_title()[0].get_valueOf_()        
        title_var = tk.StringVar(value=title_text)
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
                def_ids = self.get_oval_definition_ids(specific_oval_defs=component_obj.oval_definitions)
                definition_combo['values'] = def_ids
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
        data = self._show_cpe_item_dialog()
        if data:
            new_item = models.ItemType(name=data['name'])
            new_item.add_title(models.TextType(valueOf_=data['title']))

            # Use data keys to build the check element
            if data.get('check_definition_id'):
                check = models.CheckType(
                    system="http://oval.mitre.org/XMLSchema/oval-definitions-5",
                    # The href should be the OVAL Definition ID
                    href=data['check_definition_id']
                )
                new_item.add_check(check)
            
            cpe_list_obj.add_cpe_item(new_item)
            self.populate_cpe_tree(cpe_list_obj)
            self._mark_as_dirty()

    def edit_cpe_item(self, cpe_list_obj):
        """Handles editing an existing CPE item."""
        selected_id = self.cpe_items_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a CPE item to edit.")
            return
        
        item_to_edit = self.maps['cpe_item'].get(selected_id)
        if not item_to_edit:
            return

        data = self._show_cpe_item_dialog(item_to_edit)

        if data:
            item_to_edit.set_name(data['name'])
            
            if item_to_edit.get_title():
                item_to_edit.get_title()[0].set_valueOf_(data['title'])
            else:
                item_to_edit.add_title(models.TextType(valueOf_=data['title']))

            # REFINED: Simplified logic for updating the check element.
            if data.get('check_definition_id'):
                check_obj = item_to_edit.get_check()[0] if item_to_edit.get_check() else None
                # Create a new check object if one doesn't exist
                if not check_obj:
                    check_obj = models.CheckType(system="http://oval.mitre.org/XMLSchema/oval-definitions-5")
                    item_to_edit.add_check(check_obj)
                
                # Update the href with the OVAL Definition ID
                check_obj.set_href(data['check_definition_id'])
            else:
                # If the definition ID was cleared, remove the check element.
                item_to_edit.set_check([]) 
            
            self.populate_cpe_tree(cpe_list_obj)
            self._mark_as_dirty()
            
    def remove_cpe_item(self, cpe_list_obj):
        """Handles removing a selected CPE item."""
        selected_id = self.cpe_items_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a CPE item to remove.")
            return
        
        item_to_remove = self.maps['cpe_item'].get(selected_id)
        if not item_to_remove:
            return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the CPE item '{item_to_remove.get_name()}'?"):
            cpe_list_obj.get_cpe_item().remove(item_to_remove)
            self.populate_cpe_tree(cpe_list_obj)
            self._mark_as_dirty()
            
    def _create_component_ref(self, ref_id, component_id_href, create_catalog=True):
        """Creates a component-ref object, with an optional catalog."""
        comp_ref = models.component_ref(id=ref_id, href=component_id_href)
        if create_catalog:
            catalog_uri = models.uri(name=ref_id, uri_member=component_id_href)
            comp_ref.set_catalog(models.catalog(uri=[catalog_uri]))
            print(f"catalog_uri: {catalog_uri}")
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

    def _create_ref_list_viewer(self, parent, title, ref_list_name):
        """Creates a read-only listbox to display component references."""
        frame = ttk.LabelFrame(parent, text=title, padding=5)
        frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        listbox = tk.Listbox(frame, height=4)
        listbox.pack(fill=tk.BOTH, expand=True)
        
        ds = self.datastream_collection.get_data_stream()[0]
        ref_list = getattr(ds, f"get_{ref_list_name}")()
        if ref_list and ref_list.get_component_ref():
            for ref in ref_list.get_component_ref():
                listbox.insert(tk.END, f"  ID: {ref.get_id()}")
                listbox.insert(tk.END, f"  HREF: {ref.get_href()}")
                if ref.get_catalog():
                    for uri in ref.get_catalog().get_uri():
                        listbox.insert(tk.END, f"    Catalog URI: {uri.get_uri()}")
                        listbox.insert(tk.END, f"    Catalog Name: {uri.get_name()}")
        
        # Make the listbox read-only
        listbox.config(state=tk.DISABLED)

    def _update_datastream_references(self):
        """
        Scans all components and rebuilds the dictionaries, checklists, and checks
        references in the main data-stream.
        """
        if not self.datastream_collection: return
        ds = self.datastream_collection.get_data_stream()[0]

        # Clear existing references
        ds.set_dictionaries(models.refListType())
        ds.set_checklists(models.refListType())
        ds.set_checks(models.refListType())

        # Find all component IDs and create a lookup map
        xccdf_comp, cpe_dict_comp, cpe_oval_comp, oval_check_comp = None, None, None, None
        for comp in self.datastream_collection.get_component():
            if comp.Benchmark: xccdf_comp = comp
            elif comp.cpe_list: cpe_dict_comp = comp
            elif "cpe-oval" in comp.get_id(): cpe_oval_comp = comp
            else: oval_check_comp = comp

        # Rebuild dictionaries reference
        if cpe_dict_comp and cpe_oval_comp:
            comp_ref = models.component_ref(id=f"scap_{self.prefix}_cref_SPECTRE-cpe-dictionary.xml", href=f"#{cpe_dict_comp.get_id()}")
            cat_uri = models.uri(name=f"{self.prefix}-collection-cpe-oval.xml", uri=f"#{cpe_oval_comp.get_id()}")
            comp_ref.set_catalog(models.catalog(uri=[cat_uri]))
            ds.get_dictionaries().add_component_ref(comp_ref)

        # Rebuild checklists reference
        if xccdf_comp and oval_check_comp:
            comp_ref = models.component_ref(id=f"scap_{self.prefix}_cref_SPECTRE-xccdf.xml", href=f"#{xccdf_comp.get_id()}")
            cat_uri = models.uri(name=f"{self.prefix}-collection-oval.xml", uri=f"#{oval_check_comp.get_id()}")
            comp_ref.set_catalog(models.catalog(uri=[cat_uri]))
            ds.get_checklists().add_component_ref(comp_ref)
            
        # Rebuild checks references
        if oval_check_comp:
            ds.get_checks().add_component_ref(models.component_ref(id=f"scap_{self.prefix}_cref_SPECTRE-oval-check.xml", href=f"#{oval_check_comp.get_id()}"))
        if cpe_oval_comp:
            ds.get_checks().add_component_ref(models.component_ref(id=f"scap_{self.prefix}_cref_SPECTRE-cpe-oval-check.xml", href=f"#{cpe_oval_comp.get_id()}"))

        self._mark_as_dirty()
        messagebox.showinfo("Success", "Datastream references have been updated.")
        # Refresh the details view to show the changes
        self.display_details(ds)

    def _sync_cpe_to_platforms(self):
        """
        Reads all items from the CPE Dictionary and adds them to the XCCDF
        Benchmark's platforms, creating definitions for 'cpe:/a:' and
        top-level applicable platforms for 'cpe:/o:'.
        """
        benchmark = self.get_benchmark()
        cpe_list = self.get_cpe_dictionary()

        if not benchmark or not cpe_list or not cpe_list.get_cpe_item():
            messagebox.showinfo("No Data", "No CPE items found to sync.")
            return

        added_definitions = 0
        added_applicable = 0

        # Ensure parent elements exist
        if benchmark.platform_specification is None:
            benchmark.platform_specification = models.platformSpecificationType()
        if benchmark.platform_specification.platform is None:
            benchmark.platform_specification.platform = []
        if benchmark.platform is None:
            benchmark.platform = []

        # Get existing platform IDs to avoid duplicates
        existing_def_ids = {p.get_id() for p in benchmark.platform_specification.platform}
        existing_app_ids = {p.get_idref() for p in benchmark.platform}

        for item in cpe_list.get_cpe_item():
            cpe_name = item.get_name()
            
            # Add 'cpe:/a:' items as Platform Definitions
            if cpe_name.startswith("cpe:/a:") and cpe_name not in existing_def_ids:
                idref = cpe_name.replace("cpe:/a:", "")
                new_platform_def = models.PlatformType(id=idref)
                
                fact_ref = models.CPEFactRefType(name=cpe_name)
                logical_test = models.LogicalTestType(
                    operator='AND',
                    negate=False,
                    fact_ref=[fact_ref]
                )
                new_platform_def.set_logical_test(logical_test)
                
                benchmark.platform_specification.platform.append(new_platform_def)
                added_definitions += 1
            
            # Add 'cpe:/o:' items as Applicable Platforms
            elif cpe_name.startswith("cpe:/o:") and cpe_name not in existing_app_ids:
                new_platform_ref = models.overrideableCPE2idrefType(idref=cpe_name)
                benchmark.platform.append(new_platform_ref)
                added_applicable += 1

        if added_definitions > 0 or added_applicable > 0:
            self._mark_as_dirty()
            messagebox.showinfo("Sync Complete", 
                                f"Added {added_definitions} platform definitions (cpe:/a:).\n"
                                f"Added {added_applicable} applicable platforms (cpe:/o:).")

            if self.platforms_tree and self.platforms_tree.winfo_exists():
                self.populate_platforms_tree()
        else:
            messagebox.showinfo("No Changes", "All CPE platforms already exist in the XCCDF Benchmark.")
            

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
            
            item_data.platform.append(models.overrideableCPE2idrefType(idref=new_idref))
            populate_platform_references_list()
            self._mark_as_dirty()
            
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
                self._mark_as_dirty()

        def remove_platform_ref():
            selected = ref_tree.focus()
            if not selected: return
            idref_to_remove = ref_tree.item(selected)['values'][0]
            if item_data.platform:
                item_data.platform = [p for p in item_data.platform if p.get_idref() != idref_to_remove]
            populate_platform_references_list()
            self._mark_as_dirty()
            
        button_frame = ttk.Frame(manager_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Add...", command=add_platform_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Edit...", command=edit_platform_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Remove", command=remove_platform_ref).pack(side=tk.LEFT, padx=2)
        populate_platform_references_list()

    def _add_group_to_tree(self, parent_node, group):
        title_text = group.title[0].get_valueOf_() if group.title else ""
        group_id_str = group.id or "Group"
        
        node_id = self.tree.insert(parent_node, "end", text=f"Group: {title_text} ({group_id_str})", open=True)
        
        self.maps['item'][node_id] = group
        
        if group.Group:
            for subgroup in group.Group:
                self._add_group_to_tree(node_id, subgroup)
        if group.Rule:
            for rule in group.Rule:
                self._add_rule_to_tree(node_id, rule)

    def _add_rule_to_tree(self, parent_node, rule):
        title_text = rule.title[0].get_valueOf_() if rule.title else ""
        node_id = self.tree.insert(parent_node, "end", text=f"Rule: {title_text} ({rule.id})")
        self.maps['item'][node_id] = rule

    def populate_fact_refs_tree(self):
        if not self.fact_refs_tree or not self.selected_platform_obj: return
        for i in self.fact_refs_tree.get_children(): self.fact_refs_tree.delete(i)
        logical_test = self.selected_platform_obj.logical_test
        if logical_test and logical_test.fact_ref:
            for fact in logical_test.fact_ref:
                self.fact_refs_tree.insert("", "end", values=(fact.get_name(),))
       
    def create_text_editor(self, parent_frame, label_text, data_obj, attr_name, height=1):
        frame = ttk.Frame(parent_frame)
        frame.pack(fill=tk.X, pady=5)

        label = ttk.Label(frame, text=label_text, width=15)
        label.pack(side=tk.LEFT, anchor='n')

        text_widget = tk.Text(frame, height=height, wrap="word")
        text_widget.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        text_obj_list = getattr(data_obj, attr_name, [])
        if text_obj_list:
            text_obj = text_obj_list[0]
            initial_text = ""
            if hasattr(text_obj, 'get_valueOf_'):
                initial_text = text_obj.get_valueOf_() or ""
            elif isinstance(text_obj, str):
                initial_text = text_obj
            text_widget.insert("1.0", initial_text)

        def update_text_content(event):
            current_list = getattr(data_obj, attr_name, [])
            text_class = models.textWithSubType if attr_name == 'title' else models.htmlTextWithSubType
            
            if not current_list:
                new_text_obj = text_class()
                setattr(data_obj, attr_name, [new_text_obj])
                current_list = [new_text_obj]
            
            if not hasattr(current_list[0], 'set_valueOf_'):
                 current_list[0] = text_class()

            current_list[0].set_valueOf_(text_widget.get("1.0", "end-1c"))
            
            self._mark_as_dirty()
            
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
        available_tree = ttk.Treeview(available_frame, values=["id"]) # Store ID in values
        available_tree.pack(fill=tk.BOTH, expand=True)
        ttk.Label(selected_frame, text="Profile Selections").pack()
        selected_tree = ttk.Treeview(selected_frame, columns=("status",), show="tree headings")
        selected_tree.heading("status", text="Status")
        selected_tree.column("status", width=80, anchor='center')
        selected_tree.pack(fill=tk.BOTH, expand=True)
        
        benchmark_obj = self.get_benchmark()
        if not benchmark_obj: return

        def get_all_item_ids(groups):
            ids = {}
            def recurse(items):
                for item in items:
                    if isinstance(item, (models.groupType, models.ruleType)):
                        ids[item.get_id()] = item
                        if isinstance(item, models.groupType) and item.Group:
                            recurse(item.Group)
                        if isinstance(item, models.groupType) and item.Rule:
                            recurse(item.Rule)
            if groups:
                recurse(groups)
            return ids
        all_benchmark_items = get_all_item_ids(benchmark_obj.Group)
        
        def populate_trees():
            for i in available_tree.get_children(): available_tree.delete(i)
            for i in selected_tree.get_children(): selected_tree.delete(i)
            
            if profile_obj.select is None: profile_obj.select = []
            
            selected_idrefs = {s.get_idref() for s in profile_obj.select}
            
            def populate_available_recursively(parent_node, items):
                for item in items:
                    if item.get_id() not in selected_idrefs:
                        title = item.title[0].get_valueOf_() if item.title else ""
                        node_id = available_tree.insert(parent_node, "end", text=f"{item.get_id()}: {title}", open=False, values=[item.get_id()])
                        if isinstance(item, models.groupType) and item.Group:
                            populate_available_recursively(node_id, item.Group)
                        if isinstance(item, models.groupType) and item.Rule:
                            populate_available_recursively(node_id, item.Rule)

            if benchmark_obj.Group:
                populate_available_recursively("", benchmark_obj.Group)

            for selection in profile_obj.select:
                idref = selection.get_idref()
                status_str = "[+] Selected" if selection.get_selected() else "[-] Unselected"
                item_obj = all_benchmark_items.get(idref)
                title = item_obj.title[0].get_valueOf_() if item_obj and item_obj.title else ""
                selected_tree.insert("", "end", text=f"{idref}: {title}", values=(status_str, idref))
        
        def move_item(is_selected_bool):
            selected_id = available_tree.focus()
            if not selected_id: return
            idref = available_tree.item(selected_id)['values'][0]
            
            profile_obj.select.append(models.profileSelectType(idref=idref, selected=is_selected_bool))
            populate_trees()
            self._mark_as_dirty()
        
        def remove_selection():
            selected_in_profile = selected_tree.focus()
            if not selected_in_profile: return
            idref_to_remove = selected_tree.item(selected_in_profile)['values'][1]
            
            profile_obj.select = [s for s in profile_obj.select if s.get_idref() != idref_to_remove]
            populate_trees()
            self._mark_as_dirty()
        
        ttk.Button(button_frame, text="Select >>", command=lambda: move_item(True)).pack(pady=5)
        ttk.Button(button_frame, text="Unselect >>", command=lambda: move_item(False)).pack(pady=5)
        ttk.Button(button_frame, text="<< Remove", command=remove_selection).pack(pady=20)
        
        populate_trees()
        
    def get_benchmark(self):
        """
        Finds and returns the first XCCDF Benchmark component in the datastream.
        Returns None if no datastream or benchmark is found.
        """
        if self.datastream_collection and self.datastream_collection.get_component():
            for comp in self.datastream_collection.get_component():
                # The hasattr check is a bit safer than direct access
                if hasattr(comp, 'Benchmark') and comp.Benchmark is not None:
                    return comp.Benchmark
        return None

    def create_item_platform_manager(self, parent_frame, item_data):
        manager_frame = ttk.LabelFrame(parent_frame, text="Applicable Platforms", padding=5)
        manager_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        benchmark_obj = self.get_benchmark()
        if not benchmark_obj: return

        platform_ids = set()
        if hasattr(benchmark_obj, 'platform_specification') and benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
            for p in benchmark_obj.platform_specification.platform:
                if p.logical_test and p.logical_test.fact_ref:
                    # Safely get the CPE name
                    cpe_name = p.logical_test.fact_ref[0].get_name()
                    if cpe_name:
                        platform_ids.add(cpe_name)
        if hasattr(benchmark_obj, 'platform') and benchmark_obj.platform:
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
                return # Silently ignore duplicates
            if item_data.platform is None:
                item_data.platform = []
            
            item_data.platform.append(models.overrideableCPE2idrefType(idref=selected_id))
            populate_platform_references_list()
            self._mark_as_dirty() # Mark change

        def remove_platform_ref():
            selected_indices = platform_listbox.curselection()
            if not selected_indices: return
            selected_idref = platform_listbox.get(selected_indices[0])
            if item_data.platform:
                item_data.platform = [p for p in item_data.platform if p.get_idref() != selected_idref]
                populate_platform_references_list()
                self._mark_as_dirty() # Mark change

        ttk.Button(add_frame, text="Add", command=add_platform_ref).pack(side=tk.LEFT, padx=5)
        ttk.Button(list_frame, text="Remove", command=remove_platform_ref).pack(side=tk.LEFT, padx=5, anchor='n')
        
        populate_platform_references_list()
        
    def on_platform_select(self, event):
        selected_item_id = self.platforms_tree.focus()

        # Clear the current selection first
        self.selected_platform_obj = None

        if selected_item_id:
            platform_id = self.platforms_tree.item(selected_item_id)['values'][0]
            benchmark_obj = self.get_benchmark()

            if benchmark_obj and benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
                self.selected_platform_obj = next(
                    (p for p in benchmark_obj.platform_specification.platform if p.get_id() == platform_id), 
                    None
                )
        
        self.display_logical_test_details()

    def display_logical_test_details(self):
        for widget in self.logical_test_editor_frame.winfo_children():
            widget.destroy()
            
        if not self.selected_platform_obj:
            return

        editor_frame = ttk.LabelFrame(self.logical_test_editor_frame, text=f"Logical Test for '{self.selected_platform_obj.get_id()}'", padding=5)
        editor_frame.pack(fill=tk.BOTH, expand=True)
        
        # This is a great safety check to ensure the logical_test object exists.
        if self.selected_platform_obj.logical_test is None:
            self.selected_platform_obj.logical_test = models.LogicalTestType(operator='AND', negate=False)
        logical_test = self.selected_platform_obj.logical_test

        top_frame = ttk.Frame(editor_frame)
        top_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(top_frame, text="Operator:").pack(side=tk.LEFT)
        op_var = tk.StringVar(value=logical_test.get_operator())
        op_combo = ttk.Combobox(top_frame, textvariable=op_var, values=["AND", "OR"], width=5)
        op_combo.pack(side=tk.LEFT, padx=5)
        # REFINEMENT: Use a lambda for a more concise binding.
        op_combo.bind("<<ComboboxSelected>>", 
                      lambda e: (logical_test.set_operator(op_var.get()), self._mark_as_dirty()))

        negate_var = tk.BooleanVar(value=logical_test.get_negate())
        # REFINEMENT: Combine the command and the dirty marker in the lambda.
        negate_check = ttk.Checkbutton(top_frame, text="Negate", variable=negate_var, 
                                       command=lambda: (logical_test.set_negate(negate_var.get()), self._mark_as_dirty()))
        negate_check.pack(side=tk.LEFT, padx=10)
        
        # This UI setup for fact references is excellent.
        self.fact_refs_tree = ttk.Treeview(editor_frame, columns=("cpe",), show="headings", height=3)
        self.fact_refs_tree.heading("cpe", text="CPE Name (fact-ref)")
        self.fact_refs_tree.pack(fill=tk.BOTH, expand=True, pady=5)

        fact_button_frame = ttk.Frame(editor_frame)
        fact_button_frame.pack(fill=tk.X)
        ttk.Button(fact_button_frame, text="Add CPE", command=self.add_fact_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(fact_button_frame, text="Edit CPE", command=self.edit_fact_ref).pack(side=tk.LEFT, padx=2)
        ttk.Button(fact_button_frame, text="Remove CPE", command=self.remove_fact_ref).pack(side=tk.LEFT, padx=2)

        self.populate_fact_refs_tree()
        
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
        if not new_id:
            return

        if benchmark_obj.platform_specification is None:
            benchmark_obj.platform_specification = models.platformSpecificationType()
        if benchmark_obj.platform_specification.platform is None:
            benchmark_obj.platform_specification.platform = []
            
        if any(p.get_id() == new_id for p in benchmark_obj.platform_specification.platform):
            messagebox.showwarning("Duplicate ID", f"A platform with the ID '{new_id}' already exists.")
            return

        new_platform = models.PlatformType(id=new_id)
        benchmark_obj.platform_specification.platform.append(new_platform)
        
        self.populate_platforms_tree()
        self._mark_as_dirty() # Mark the change

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
                
                if any(p.get_id() == new_id for p in benchmark_obj.platform_specification.platform):
                    messagebox.showwarning("Duplicate ID", f"A platform with the ID '{new_id}' already exists.")
                    return
                
                for platform in benchmark_obj.platform_specification.platform:
                    if platform.get_id() == current_id:
                        platform.set_id(new_id)
                        break
                        
                self.populate_platforms_tree()
                self._mark_as_dirty() # Mark the change
                
    def remove_platform(self):
        selected_item = self.platforms_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a platform to remove.")
            return
            
        id_to_remove = self.platforms_tree.item(selected_item)['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to remove platform '{id_to_remove}'?"):
            benchmark_obj = self.get_benchmark()
            if benchmark_obj and benchmark_obj.platform_specification and benchmark_obj.platform_specification.platform:
                
                initial_count = len(benchmark_obj.platform_specification.platform)
                benchmark_obj.platform_specification.platform = [
                    p for p in benchmark_obj.platform_specification.platform if p.get_id() != id_to_remove
                ]
                
                # Check if a change was actually made
                if len(benchmark_obj.platform_specification.platform) < initial_count:
                    self.populate_platforms_tree()
                    self._mark_as_dirty() # Mark the change

    def add_fact_ref(self):
        """Adds a new CPE fact-ref to the selected platform's logical test."""
        if not self.fact_refs_tree or not self.selected_platform_obj: 
            return

        # Ensure the logical_test and its fact_ref list exist
        logical_test = self.selected_platform_obj.logical_test
        if logical_test is None:
            logical_test = models.LogicalTestType(operator='AND', negate=False)
            self.selected_platform_obj.logical_test = logical_test
        if logical_test.fact_ref is None:
            logical_test.fact_ref = []

        new_cpe = simpledialog.askstring("Add CPE", "Enter the new CPE name:", parent=self.root)
        if not new_cpe:
            return

        # Check for duplicates
        if any(fact.get_name() == new_cpe for fact in logical_test.fact_ref):
            messagebox.showwarning("Duplicate", f"The CPE name '{new_cpe}' already exists in this logical test.")
            return

        # Create and add the new fact reference
        new_fact = models.CPEFactRefType(name=new_cpe)
        logical_test.fact_ref.append(new_fact)
        
        self.populate_fact_refs_tree()
        self._mark_as_dirty()
        
    def edit_fact_ref(self):
        if not self.fact_refs_tree or not self.selected_platform_obj: return
        
        selected_item = self.fact_refs_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a CPE to edit.")
            return
            
        current_cpe = self.fact_refs_tree.item(selected_item)['values'][0]
        new_cpe = simpledialog.askstring("Edit CPE", "Edit CPE name:", initialvalue=current_cpe, parent=self.root)

        # Proceed only if the CPE name is new and not empty
        if new_cpe and new_cpe != current_cpe:
            logical_test = self.selected_platform_obj.logical_test
            if logical_test and logical_test.fact_ref:
                
                if any(fact.get_name() == new_cpe for fact in logical_test.fact_ref):
                    messagebox.showwarning("Duplicate", f"The CPE name '{new_cpe}' already exists in this logical test.")
                    return
                
                for fact in logical_test.fact_ref:
                    if fact.get_name() == current_cpe:
                        fact.set_name(new_cpe)
                        break
                        
                self.populate_fact_refs_tree()
                self._mark_as_dirty() # Mark the change
                
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
                
                initial_count = len(logical_test.fact_ref)
                logical_test.fact_ref = [f for f in logical_test.fact_ref if f.get_name() != cpe_to_remove]
                
                # Check if a change was actually made
                if len(logical_test.fact_ref) < initial_count:
                    self.populate_fact_refs_tree()
                    self._mark_as_dirty() # Mark the change

    def _sync_platforms_to_cpe(self):
        """
        Reads all platforms from the XCCDF Benchmark and adds any missing
        ones to the CPE Dictionary.
        """
        benchmark = self.get_benchmark()
        cpe_list = self.get_cpe_dictionary()

        if not benchmark or not cpe_list:
            messagebox.showinfo("No Data", "Benchmark and CPE Dictionary must both exist.")
            return

        platforms_to_add = set()
        if benchmark.platform_specification and benchmark.platform_specification.platform:
            for p in benchmark.platform_specification.platform:
                platforms_to_add.add(p.get_id())
        if benchmark.platform:
            for p_ref in benchmark.platform:
                platforms_to_add.add(p_ref.get_idref())

        if not platforms_to_add:
            messagebox.showinfo("No Platforms", "No platforms found in the Benchmark to import.")
            return

        if cpe_list.get_cpe_item() is None:
            cpe_list.set_cpe_item([])
            
        existing_cpe_names = {item.get_name() for item in cpe_list.get_cpe_item()}
        added_count = 0

        for name in platforms_to_add:
            if name not in existing_cpe_names:
                new_item = models.ItemType(name=name)
                # Create a simple title from the CPE name
                simple_title = name.split(':')[-1].replace('_', ' ').title()
                new_item.add_title(models.TextType(valueOf_=simple_title))
                cpe_list.add_cpe_item(new_item)
                added_count += 1
        
        if added_count > 0:
            self._mark_as_dirty()
            messagebox.showinfo("Sync Complete", f"Added {added_count} new items to the CPE Dictionary.")
            # You may want to refresh the CPE view if it's open
            self.populate_cpe_tree(cpe_list)
        else:
            messagebox.showinfo("No Changes", "All Benchmark platforms already exist in the CPE Dictionary.")
            

##--  [  OVAL Manager UI & Commands ]---
    def display_oval_manager(self, oval_defs_obj):
        """Creates the tabbed UI for managing OVAL components."""
        self.current_oval_defs = oval_defs_obj
        
        # Ensure the generator object exists
        generator = oval_defs_obj.get_generator()
        if generator is None:
            sv = models.SchemaVersionType(valueOf_="5.11")
            generator = models.GeneratorType(
                product_name="SPECTRE", product_version="1.0", 
                schema_version=[sv], timestamp=datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
            )
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

        def apply_generator_changes():
            # Correctly wrap the schema_version in its required object
            sv = models.SchemaVersionType(valueOf_=schema_version_var.get())
            
            # Set all values at once
            generator.set_product_version(version_var.get())
            generator.set_schema_version([sv])
#            generator.set_timestamp(datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f'))
            
            self._mark_as_dirty()
            messagebox.showinfo("Success", "Generator details updated.", parent=self.root)

        apply_button = ttk.Button(gen_frame, text="Apply Changes", command=apply_generator_changes)
        apply_button.grid(row=3, column=1, sticky="e", pady=10)
        
        gen_frame.columnconfigure(1, weight=1)
        
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

        self._create_oval_tab(notebook, oval_defs_obj, 'test')
        self._create_oval_tab(notebook, oval_defs_obj, 'object')
        self._create_oval_tab(notebook, oval_defs_obj, 'state')
        self._create_oval_tab(notebook, oval_defs_obj, 'variable')

    def _create_oval_tab(self, notebook, oval_defs_obj, entity_type):
        """Creates a standardized tab with a treeview and buttons for an OVAL entity."""
        entity_type_plural = f"{entity_type}s"
        entity_type_capitalized = entity_type.capitalize()

        frame = ttk.Frame(notebook)
        notebook.add(frame, text=f"{entity_type_capitalized}s")
        
        # Treeview Setup
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tree = ttk.Treeview(tree_frame, columns=("id", "type", "comment"), show="headings")
        tree.heading("id", text="ID")
        tree.heading("type", text=f"{entity_type_capitalized} Type")
        tree.heading("comment", text="Comment")
        tree.column("id", width=250)
        tree.column("type", width=150)
        
        # Attach a scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.config(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=5)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        # Store the tree in the instance using a dynamic attribute name
        setattr(self, f"oval_{entity_type_plural}_tree", tree)
        
        # Populate the tree by calling the correct populate function
        populate_func = getattr(self, f"populate_oval_{entity_type_plural}_tree")
        populate_func(oval_defs_obj)

        # Button Setup
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5, side=tk.BOTTOM)
        ttk.Button(button_frame, text=f"Add {entity_type_capitalized}...", command=lambda: self.add_oval_entity(oval_defs_obj, entity_type)).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Edit Selected...", command=lambda: self.edit_oval_entity(oval_defs_obj, entity_type)).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Remove Selected", command=lambda: self.remove_oval_entity(oval_defs_obj, entity_type)).pack(side=tk.LEFT, padx=2)
        
      
##--  [  OVAL Definitions ]---
    def populate_oval_definitions_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL definitions treeview."""
        for i in self.oval_defs_tree.get_children():
            self.oval_defs_tree.delete(i)
        
        self.maps['oval_definition'].clear()
        
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
                
                self.maps['oval_definition'][item_id] = definition

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
        title_text = ""
        if meta and meta.get_title():
            title_text = meta.get_title().get_valueOf_()
        title_var = tk.StringVar(value=title_text)
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
                oval_defs_obj.set_definitions(models.DefinitionsType())
            
            new_def = models.DefinitionType(
                id=data['id'],
                version=data['version'],
                class_=data['class'],
                metadata=models.MetadataType(
                    title=data['title'],
                    description=data['description']
                ),
                criteria=models.CriteriaType()
            )
            
            oval_defs_obj.get_definitions().add_definition(new_def)
            self.populate_oval_definitions_tree(oval_defs_obj)
            self._mark_as_dirty() # Mark the change
            
    def edit_oval_definition(self, oval_defs_obj):
        """Handles editing an existing OVAL definition."""
        selected_id = self.oval_defs_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a definition to edit.")
            return
        
        def_to_edit = self.maps['oval_definition'].get(selected_id)
        if not def_to_edit:
            return

        data = self._show_oval_definition_dialog(def_to_edit)
        
        if data:
            def_to_edit.set_id(data['id'])
            def_to_edit.set_version(data['version'])
            def_to_edit.set_class_member(data['class'])
            
            meta = def_to_edit.get_metadata()
            if not meta:
                meta = models.MetadataType()
                def_to_edit.set_metadata(meta)
            
            meta.set_title(data['title'])
            meta.set_description(data['description'])
            
            self.populate_oval_definitions_tree(oval_defs_obj)
            self._mark_as_dirty() # Mark that a change has been made
            
    def remove_oval_definition(self, oval_defs_obj):
        """Handles removing a selected OVAL definition."""
        selected_id = self.oval_defs_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a definition to remove.")
            return

        def_to_remove = self.maps['oval_definition'].get(selected_id)
        if not def_to_remove:
            return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the definition '{def_to_remove.get_id()}'?"):
            if oval_defs_obj.get_definitions() and oval_defs_obj.get_definitions().get_definition():
                oval_defs_obj.get_definitions().get_definition().remove(def_to_remove)
                self.populate_oval_definitions_tree(oval_defs_obj)
                self._mark_as_dirty() # Mark that a change has been made
                
    def on_oval_definition_select(self, event):
        """Callback for when a definition is selected in the OVAL manager."""
        for i in self.oval_criteria_tree.get_children():
            self.oval_criteria_tree.delete(i)
        
        self.maps['oval_criteria'].clear()
        
        selected_id = self.oval_defs_tree.focus()
        if not selected_id:
            return
            
        definition_obj = self.maps['oval_definition'].get(selected_id)
        if definition_obj and definition_obj.get_criteria():
            self._populate_oval_criteria_tree("", definition_obj.get_criteria())

    def get_oval_test_ids(self):
        """Returns a list of all OVAL test IDs."""
        if not self.datastream_collection or not self.maps['oval_test']:
            return []
        return [test.get_id() for test in self.maps['oval_test'].values()]

        
##--  [  OVAL Criteria ]---
    def _populate_oval_criteria_tree(self, parent_id, criteria_node):
        """Recursively populates the criteria treeview."""
        if criteria_node is None:
            return

        negate_text = " (Negated)" if criteria_node.get_negate() else ""

        if isinstance(criteria_node, models.CriteriaType):
            node_text = f"Criteria (Operator: {criteria_node.get_operator()}){negate_text}"
            
            new_parent_id = self.oval_criteria_tree.insert(parent_id, "end", text=node_text, open=True)
            
            self.maps['oval_criteria'][new_parent_id] = criteria_node
            
            for child_criteria in criteria_node.get_criteria():
                self._populate_oval_criteria_tree(new_parent_id, child_criteria)
            for child_criterion in criteria_node.get_criterion():
                self._populate_oval_criteria_tree(new_parent_id, child_criterion)
            for child_ext_def in criteria_node.get_extend_definition():
                self._populate_oval_criteria_tree(new_parent_id, child_ext_def)

        elif isinstance(criteria_node, models.CriterionType):
            node_text = f"Criterion (Test Ref: {criteria_node.get_test_ref()}){negate_text}"
            new_node_id = self.oval_criteria_tree.insert(parent_id, "end", text=node_text)
            
            self.maps['oval_criteria'][new_node_id] = criteria_node

        elif isinstance(criteria_node, models.ExtendDefinitionType):
            node_text = f"Extend Definition (Def Ref: {criteria_node.get_definition_ref()}){negate_text}"
            new_node_id = self.oval_criteria_tree.insert(parent_id, "end", text=node_text)
            
            self.maps['oval_criteria'][new_node_id] = criteria_node
            
    def _show_criteria_node_dialog(self, node_to_edit=None, node_type=None):
        """Shows a dialog to add/edit a criteria, criterion, or extend_definition. Returns a dict or None."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)

        is_criteria = (node_type == 'criteria') or isinstance(node_to_edit, models.CriteriaType)
        is_criterion = (node_type == 'criterion') or isinstance(node_to_edit, models.CriterionType)
        is_extend_def = (node_type == 'extend_definition') or isinstance(node_to_edit, models.ExtendDefinitionType)

        title = "Edit " if node_to_edit else "Add "
        if is_criteria: title += "Criteria"
        elif is_criterion: title += "Criterion"
        else: title += "Extended Definition"
        dialog.title(title)
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        row = 0
        op_var, ref_var, negate_var = None, None, None

        if is_criteria:
            ttk.Label(main_frame, text="Operator:").grid(row=row, column=0, sticky="w", pady=5)
            op_options = ['AND', 'OR', 'XOR', 'ONE']
            op_var = tk.StringVar(value=node_to_edit.get_operator() if node_to_edit else "AND")
            ttk.Combobox(main_frame, textvariable=op_var, values=op_options, state="readonly").grid(row=row, column=1, sticky="ew", pady=5)
            row += 1
        elif is_criterion:
            ttk.Label(main_frame, text="Test Reference ID:").grid(row=row, column=0, sticky="w", pady=5)
            ref_frame = ttk.Frame(main_frame)
            ref_frame.grid(row=row, column=1, sticky="ew")
            ref_var = tk.StringVar(value=node_to_edit.get_test_ref() if node_to_edit else "")
            test_ids = self.get_oval_test_ids()
            test_combo = ttk.Combobox(ref_frame, textvariable=ref_var, values=test_ids)
            test_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            def _create_new_test():
                new_test = self.add_oval_entity(self.current_oval_defs, 'test')
                if new_test:
                    test_combo['values'] = self.get_oval_test_ids()
                    ref_var.set(new_test.get_id())

            ttk.Button(ref_frame, text="New Test...", command=_create_new_test).pack(side=tk.LEFT, padx=(5,0))
            row += 1
        elif is_extend_def:
            ttk.Label(main_frame, text="Definition Ref ID:").grid(row=row, column=0, sticky="w", pady=5)
            ref_var = tk.StringVar(value=node_to_edit.get_definition_ref() if node_to_edit else "")
            def_ids = self.get_oval_definition_ids(specific_oval_defs=self.current_oval_defs)
            ttk.Combobox(main_frame, textvariable=ref_var, values=def_ids).grid(row=row, column=1, sticky="ew", pady=5)
            row += 1

        negate_var = tk.BooleanVar(value=node_to_edit.get_negate() if node_to_edit else False)
        ttk.Checkbutton(main_frame, text="Negate Result", variable=negate_var).grid(row=row, column=1, sticky="w", pady=5)

        main_frame.columnconfigure(1, weight=1)

        def on_ok():
            results['negate'] = negate_var.get()
            if is_criteria:
                results['operator'] = op_var.get()
            elif is_criterion:
                if not ref_var.get():
                    messagebox.showwarning("Input Error", "Test Reference ID cannot be empty.", parent=dialog)
                    return
                results['test_ref'] = ref_var.get()
            elif is_extend_def:
                if not ref_var.get():
                    messagebox.showwarning("Input Error", "Definition Reference ID cannot be empty.", parent=dialog)
                    return
                results['definition_ref'] = ref_var.get()
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
        self._add_criteria_child('criteria', models.CriteriaType)

    def add_oval_criterion(self):
        """Adds a new <criterion> element."""
        self._add_criteria_child('criterion', models.CriterionType)

    def add_oval_extended_definition(self):
        """Adds a new <extend_definition> element."""
        self._add_criteria_child('extend_definition', models.ExtendDefinitionType)

    def _add_criteria_child(self, node_type, child_class):
        """A generic helper to add any type of child to a criteria node."""
        selected_id = self.oval_criteria_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select a parent <criteria> node to add to.")
            return

        parent_obj = self.maps['oval_criteria'].get(selected_id)
        if not isinstance(parent_obj, models.CriteriaType):
            messagebox.showwarning("Invalid Parent", "You can only add new elements to a 'Criteria' node.")
            return

        data = self._show_criteria_node_dialog(node_type=node_type)
        if data:
            # Create an instance of the specific child class
            new_child = child_class(**data)
            
            # Use getattr to call the correct 'add' method (e.g., add_criteria, add_criterion)
            add_method_name = f"add_{node_type}"
            if hasattr(parent_obj, add_method_name):
                add_method = getattr(parent_obj, add_method_name)
                add_method(new_child)
            
            self.on_oval_definition_select(None) # Refresh the view
            self._mark_as_dirty() # Mark the change
            
    def edit_oval_criteria_item(self):
        """Edits the selected criteria, criterion, or extend_definition node."""
        selected_id = self.oval_criteria_tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", "Please select an item to edit.")
            return
            
        node_to_edit = self.maps['oval_criteria'].get(selected_id)
        if not node_to_edit:
            return

        data = self._show_criteria_node_dialog(node_to_edit=node_to_edit)
        
        if data:
            # Set negate attribute for all types
            if 'negate' in data:
                node_to_edit.set_negate(data['negate'])

            # Set type-specific attributes
            if isinstance(node_to_edit, models.CriteriaType) and 'operator' in data:
                node_to_edit.set_operator(data['operator'])
            elif isinstance(node_to_edit, models.CriterionType) and 'test_ref' in data:
                node_to_edit.set_test_ref(data['test_ref'])
            elif isinstance(node_to_edit, models.ExtendDefinitionType) and 'definition_ref' in data:
                node_to_edit.set_definition_ref(data['definition_ref'])
            
            self.on_oval_definition_select(None) # Refresh the view
            self._mark_as_dirty() # Mark the change
            
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

        parent_obj = self.maps['oval_criteria'].get(parent_id)
        selected_obj = self.maps['oval_criteria'].get(selected_id)

        if not parent_obj or not selected_obj:
            return

        if isinstance(selected_obj, models.CriteriaType):
            parent_obj.get_criteria().remove(selected_obj)
        elif isinstance(selected_obj, models.CriterionType):
            parent_obj.get_criterion().remove(selected_obj)
        elif isinstance(selected_obj, models.ExtendDefinitionType):
            parent_obj.get_extend_definition().remove(selected_obj)
        
        self.on_oval_definition_select(None) # Refresh the view
        self._mark_as_dirty() # Mark the change

      
##--  [  OVAL Entity's ]---
    def add_oval_entity(self, oval_defs_obj, entity_type_str, selected_class=None):
        """Generic function to add any type of OVAL entity."""
        if not selected_class:
            base_class_map = {
                'test': models.TestType, 'object': models.ObjectType, 
                'state': models.StateType, 'variable': models.VariableType
            }
            title_map = {
                'test': "Select Test Type", 'object': "Select Object Type", 
                'state': "Select State Type", 'variable': "Select Variable Type"
            }
            selected_class = self._select_oval_entity_type_dialog(base_class_map[entity_type_str], title_map[entity_type_str])
        
        if not selected_class:
            return None

        data = None
        if entity_type_str == 'test':
            data = self._show_generic_test_details_dialog(selected_class)
        elif entity_type_str in ['object', 'state']: # Refined: object and state share this logic
            selected_properties = self._select_object_properties_dialog(selected_class)
            if not selected_properties: return None
            
            if entity_type_str == 'object':
                data = self._show_generic_object_details_dialog(selected_class, selected_properties)
            else: # It's a state
                data = self._show_generic_state_details_dialog(selected_class, selected_properties)

        elif entity_type_str == 'variable':
            data = self._show_generic_variable_details_dialog(selected_class)
        else:
            messagebox.showinfo("Not Implemented", f"The UI for adding a '{entity_type_str}' is not fully implemented yet.")
            return None

        if not data:
            return None

        new_entity = self._create_oval_entity(selected_class, data, entity_type_str)
        if not new_entity: return None
        
        # Add the entity to the correct container in the datastream
        container = getattr(oval_defs_obj, f"get_{entity_type_str}s")()
        if not container:
            container_class = getattr(models, f"{entity_type_str.capitalize()}sType")
            container = container_class()
            getattr(oval_defs_obj, f"set_{entity_type_str}s")(container)
        
        getattr(container, f"add_{entity_type_str}")(new_entity)
        
        # Refresh the UI
        populate_tree_func = getattr(self, f"populate_oval_{entity_type_str}s_tree")
        populate_tree_func(oval_defs_obj)
        self._mark_as_dirty()
        return new_entity
        
    def edit_oval_entity(self, oval_defs_obj, entity_type_str):
        """Dispatcher to edit the selected OVAL entity based on its type."""
        tree = getattr(self, f"oval_{entity_type_str}s_tree")
        entity_map = self.maps[f"oval_{entity_type_str}"]
        
        selected_id = tree.focus()
        if not selected_id:
            messagebox.showwarning("No Selection", f"Please select an {entity_type_str} to edit.")
            return

        entity_to_edit = entity_map.get(selected_id)
        if not entity_to_edit:
            return
        entity_class = type(entity_to_edit)
        
        data = None
        if entity_type_str == 'test':
            data = self._show_generic_test_details_dialog(entity_class, entity_to_edit)
        elif entity_type_str in ['object', 'state']:
            properties_map = {}
            sig = inspect.signature(entity_class.__init__)
            for param in sig.parameters.values():
                if param.name not in ['self', 'id', 'gds_collector_', 'kwargs_'] and \
                   param.name not in self.DEPRECATED_OVAL_ENTITIES and \
                   param.name not in self.EXCLUDED_OVAL_PROPERTIES:
                    
                    datatype = self.OVAL_PROPERTY_DATATYPE_MAP.get(param.name, 'string')
                    properties_map[param.name] = {'type': datatype}
            
            if entity_type_str == 'object':
                data = self._show_generic_object_details_dialog(entity_class, properties_map, entity_to_edit)
            else: # It's a state
                data = self._show_generic_state_details_dialog(entity_class, properties_map, entity_to_edit)
        elif entity_type_str == 'variable':
            data = self._show_generic_variable_details_dialog(entity_class, entity_to_edit)
        else:
            messagebox.showinfo("Not Implemented", f"The editor for an OVAL {entity_type_str} is not implemented yet.")
            return

        if not data:
            return

        self._update_oval_entity(entity_to_edit, data, entity_type_str)

        # Refresh the UI and mark the change
        populate_tree_func = getattr(self, f"populate_oval_{entity_type_str}s_tree")
        populate_tree_func(oval_defs_obj)
        self._mark_as_dirty()
        
    def remove_oval_entity(self, oval_defs_obj, entity_type_str):
        """Generic function to remove any selected OVAL entity."""
        tree = getattr(self, f"oval_{entity_type_str}s_tree")
        
        entity_map = self.maps[f"oval_{entity_type_str}"]

        selected_id = tree.focus()
        if not selected_id: return
        
        entity_to_remove = entity_map.get(selected_id)
        if not entity_to_remove: return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete this {entity_type_str}?\n\n{entity_to_remove.get_id()}"):
            container = getattr(oval_defs_obj, f"get_{entity_type_str}s")()
            if container:
                entity_list = getattr(container, f"get_{entity_type_str}")()
                if entity_to_remove in entity_list:
                    entity_list.remove(entity_to_remove)
                    
                    populate_tree_func = getattr(self, f"populate_oval_{entity_type_str}s_tree")
                    populate_tree_func(oval_defs_obj)
                    self._mark_as_dirty() # Mark the change
                   
    def _get_available_entity_types(self, base_class_name):
        """
        Dynamically finds all OVAL entity classes by inspecting the unified model.
        """
        # Determine the required suffix from the base class name (e.g., 'TestType' -> '_test')
        suffix = "_" + base_class_name.replace('Type', '').lower()
        entity_families = {}

        # A map to group the entities by their original schema family
        family_map = {
            'independent': "Independent",
            'linux': "Linux",
            'unix': "Unix",
            'solaris': "Solaris",
        }
        
        for name, obj in inspect.getmembers(models):
            # Check if it's a class with the correct suffix (e.g., '_test')
            if inspect.isclass(obj) and name.endswith(suffix):
                if name in self.DEPRECATED_OVAL_ENTITIES:
                    continue
                
                # Determine the family by checking the class's module source
                module_name = obj.__module__
                family_name = "Core" # Default for variables
                for key, friendly_name in family_map.items():
                    if key in module_name:
                        family_name = friendly_name
                        break

                if family_name not in entity_families:
                    entity_families[family_name] = {}
                
                friendly_name = name.replace('_', ' ').capitalize()
                entity_families[family_name][friendly_name] = obj
                
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

    def _create_oval_entity(self, selected_class, data, entity_type_str):
        """Creates a new OVAL entity from dialog data."""
        if not data:
            return None
        print(f"data: {data}")
        print(f"selected_class: {selected_class}")
        # --- Create an empty instance first
        new_entity = selected_class()
        new_entity.original_tagname_ = selected_class.__name__
        print(new_entity.get_ns_prefix_())
        
        # --- Set COMMON attributes for all OVAL entities ---
        if 'id' in data: new_entity.set_id(data['id'])
        if 'version' in data: new_entity.set_version(data['version'])
        if 'comment' in data: new_entity.set_comment(data['comment'])

        if entity_type_str == 'test':
            if 'check' in data: new_entity.set_check(data['check'])
            if 'check_existence' in data: new_entity.set_check_existence(data['check_existence'])
            if data.get('object_ref'):
                obj_ref = models.ObjectRefType(object_ref=data['object_ref'])
                obj_ref.ns_prefix_ = new_entity.ns_prefix_
                new_entity.set_object(obj_ref)
            if data.get('state_ref'):
                state_ref = models.StateRefType(state_ref=data['state_ref'])
                state_ref.ns_prefix_ = new_entity.ns_prefix_
                new_entity.set_state([state_ref])      

        elif entity_type_str == 'object':
            if data.get('behaviors'):
                b_data = data['behaviors']
                b_kwargs = {k: v for k, v in b_data.items()}
                if isinstance(new_entity, models.textfilecontent54_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = models.Textfilecontent54Behaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, models.rpminfo_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = models.RpmInfoBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, models.rpmverifypackage_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = models.RpmVerifyPackageBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, models.rpmverifyfile_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = models.RpmVerifyFileBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, models.rpmverify_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = models.RpmVerifyBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                else:
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = models.FileBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)

            # --- FOR FILTERS ---
            if 'filter' in data:
                f_data = data['filter']
                if f_data.get('state_id'): # Only add a filter if a state was selected
                    new_filter = models.filter(valueOf_=f_data['state_id'], action=f_data['action'])
                    new_entity.add_filter(new_filter)
 
            for prop_name, prop_data in data.items():
                if prop_name in ['id', 'version', 'comment', 'behaviors', 'filter']:
                    continue # Skip common props and complex types handled elsewhere

                setter_name = f"set_{prop_name}"
                if hasattr(new_entity, setter_name):
                    # --- Determine which wrapper class to use based on the property name
                    if prop_name in ["version_"]:
                        if (isinstance(new_entity, models.sql57_object) or isinstance(new_entity, models.sql_object)):
                            wrapper_class = models.EntityObjectStringType
                        elif (isinstance(new_entity, models.rpmverifyfile_object) or isinstance(new_entity, models.rpmverifypackage_object)):
                            wrapper_class = models.EntityObjectAnySimpleType
                    elif prop_name in ['instance', 'pid', 'local_port']:
                        wrapper_class = models.EntityObjectIntType
                    elif prop_name in ['path', 'filename', 'filepath', 'name', 'connection_string', 'sql', 'xpath', 'pattern', 'domain_name', \
                       'attribute_name', 'key', 'source', 'protocol', 'service_name', 'username', 'command_line', 'runlevel', 'interface_name', \
                       'mount_point', 'arch', 'unit', 'property']:
                         wrapper_class = models.EntityObjectStringType
                    elif prop_name in ['epoch', 'release']:
                        wrapper_class = models.EntityObjectAnySimpleType
                    elif prop_name in ['local_address', 'destination']:
                        wrapper_class = models.EntityObjectIPAddressType
                    elif prop_name in ['var_ref']:
                        wrapper_class = models.EntityObjectVariableRefType
                    #Defined Problem Children
                    elif prop_name in ['hash_type', 'engine']:
                        wrapper_class = models.EntityObjectStringType
                    #Left Overs
                    else:
                        wrapper_class = models.EntityObjectStringType
                    
                    # --- Use the existing helper to create and set the property
                    self._set_wrapped_property(new_entity, data, prop_name, wrapper_class)

        elif entity_type_str == 'state':
            if 'operator' in data: new_entity.set_operator(data['operator'])

            for prop_name, prop_data in data.items():
                if prop_name in ['id', 'version', 'comment', 'operator']:
                    continue # Skip common props handled elsewhere

                setter_name = f"set_{prop_name}"

                # --- Check if the entity actually has this property
                if hasattr(new_entity, setter_name):
                    # --- This logic correctly determines which wrapper to use based on the property name
                    # --- This can be expanded as you add more types
                    
                    if prop_name in ['version_']:
                        if (isinstance(new_entity, models.slackwarepkginfo_state) or isinstance(new_entity, models.sql57_state)):
                            wrapper_class = models.EntityStateStringType
                        elif isinstance(new_entity, models.rpmverifypackage_state) or isinstance(new_entity, models.rpmverifyfile_state) or\
                           isinstance(new_entity, models.rpminfo_state) or isinstance(new_entity, models.dpkginfo_state):
                            wrapper_class = models.EntityObjectAnySimpleType                
                    elif prop_name in ['type']:
                        if (isinstance(new_entity, models.selinuxsecuritycontext_state) or isinstance(new_entity, models.file_state)):
                            wrapper_class = models.EntityStateStringType
                        elif isinstance(new_entity, models.interface_state):
                            wrapper_class = models.EntityStateInterfaceType
                        elif isinstance(new_entity, models.gconf_state):
                            wrapper_class = models.EntityStateGconfTypeType
                        elif isinstance(new_entity, models.xinetd_state):
                            wrapper_class = models.EntityStateXinetdTypeStatusType
                    elif prop_name in ['flags']:
                        if isinstance(new_entity, models.xinetd_state):
                            wrapper_class = models.EntityStateStringType
                        elif isinstance(new_entity, models.routingtable_state):
                            wrapper_class = models.EntityStateRoutingTableFlagsType
                    elif prop_name in ['arch', 'architecture', 'attribute_name', 'canonical_path', 'command_line', 'connection_string', 'dependency', \
                       'device', 'domain_name', 'exec_as_user', 'exec_time', 'extended_name', 'filename', 'filepath', 'flag', 'fs_type', 'gcos', \
                       'hardware_addr', 'hash', 'high_category', 'high_sensitivity', 'home_dir', 'hw_address', 'interface_name', 'key', 'login_shell', \
                       'low_category', 'low_sensitivity', 'machine_class', 'mod_user', 'mount_options', 'mount_point', 'name', 'no_access', 'node_name', \
                       'os_name', 'os_release', 'os_version', 'password', 'path', 'pattern', 'processor_type', 'program_name', 'property', 'protocol', \
                       'rawhigh_category', 'rawhigh_sensitivity', 'rawlow_category', 'rawlow_sensitivity', 'revision', 'role', 'runlevel', 'scheduling_class', \
                       'selinux_domain_label', 'server', 'server_arguments', 'server_program', 'service_name', 'signature_keyid', 'socket_type', 'source', \
                       'sql', 'start_time', 'tty', 'unit', 'user', 'username', 'uuid', 'xpath']:
                        wrapper_class = models.EntityStateStringType
                    elif prop_name in ['a_time', 'chg_allow', 'chg_lst', 'chg_req', 'c_time', 'exp_date', 'exp_inact', 'exp_warn', 'group_id', 'instance', \
                       'last_login', 'loginuid', 'mod_time', 'm_time', 'pid', 'port', 'ppid', 'priority', 'ruid', 'session_id', 'size', 'space_left', \
                       'space_used', 'total_space', 'ttl', 'user_id']:
                        wrapper_class = models.EntityStateIntType
                    elif prop_name in ['configuration_file', 'current_status', 'dependency_check_passed', 'digest_check_passed', 'disabled', 'documentation_file', \
                       'exec_shield', 'gexec', 'ghost_file', 'gread', 'gwrite', 'has_extended_acl', 'is_default', 'is_writable', 'kill', 'license_file', 'oexec', \
                       'oread', 'owrite', 'pending_status', 'readme_file', 'sgid', 'signature_check_passed', 'start', 'sticky', 'suid', 'uexec', 'uread', \
                       'uwrite', 'verification_script_successful', 'wait']:
                        wrapper_class = models.EntityStateBoolType
                    elif prop_name in ['capabilities_differ', 'device_differs', 'group_differs', 'link_mismatch', 'md5_differs', 'mode_differs', \
                       'mtime_differs', 'ownership_differs', 'size_differs']:
                        wrapper_class = models.EntityStateRpmVerifyResultType
                    elif prop_name in ['epoch', 'result', 'subexpression', 'text', 'value', 'value_of']:
                        wrapper_class = models.EntityStateAnySimpleType
                    elif prop_name in ['broadcast_addr', 'inet_addr', 'ip_address', 'netmask', 'only_from']:
                        wrapper_class = models.EntityStateIPAddressStringType
                    elif prop_name in ['destination', 'gateway']:
                        wrapper_class = models.EntityStateIPAddressType
                    elif prop_name in ['posix_capability', 'protocol']:
                        wrapper_class = models.EntityStateCapabilityType
                    elif prop_name in ['encrypt_method']:
                        wrapper_class = models.EntityStateEncryptMethodType
                    elif prop_name in ['endpoint_type']:
                        wrapper_class = models.EntityStateEndpointType
                    elif prop_name in ['engine']:
                        wrapper_class = models.EntityStateEngineType
                    elif prop_name in ['evr']:
                        wrapper_class = models.EntityStateEVRStringType
                    elif prop_name in ['family']:
                        wrapper_class = models.EntityStateFamilyType
                    elif prop_name in ['hash_type']:
                        wrapper_class = models.EntityStateHashTypeType
                    elif prop_name in ['release']:
                        wrapper_class = models.EntityStateProtocolType
                    elif prop_name in ['var_ref']:
                        wrapper_class = models.EntityStateRecordType
                    elif prop_name in ['wait_status']:
                        wrapper_class = models.EntityStateWaitStatusType
                    elif prop_name in ['windows_view']:
                        wrapper_class = models.EntityStateWindowsViewType
                    #Left Overs
                    else:
                        wrapper_class = models.EntityObjectStringType
                    
                    # --- Use the existing helper to create and set the property
                    self._set_wrapped_property(new_entity, data, prop_name, wrapper_class)

        elif entity_type_str == 'variable':
            new_entity.set_datatype(data['datatype'])
            
            if isinstance(new_entity, models.constant_variable) and 'value' in data:
                for val in data['value']:
                    new_entity.add_value(models.ValueType(valueOf_=val))

            elif isinstance(new_entity, models.external_variable):
                if 'possible_value' in data:
                    for pv_data in data['possible_value']:
                        pv = models.PossibleValueType(
                            valueOf_=pv_data.get('value'),
                            hint=pv_data.get('hint')
                        )
                        new_entity.add_possible_value(pv)
                
                if 'possible_restriction' in data:
                    for pr_data in data['possible_restriction']:
                        # Create the main <possible_restriction> container
                        pr = models.PossibleRestrictionType(
                            hint=pr_data.get('hint'),
                            operator=pr_data.get('operator')
                        )
                        # Loop through its child restrictions and add them
                        for r_data in pr_data.get('restrictions', []):
                            restriction_child = models.RestrictionType(
                                valueOf_=r_data.get('value'),
                                operation=r_data.get('operation')
                            )
                            pr.add_restriction(restriction_child)
                        new_entity.add_possible_restriction(pr)

            elif isinstance(new_entity, models.local_variable):
                comp_type = data.get('component_type')
                if comp_type == 'literal':
                    new_entity.set_literal_component(models.LiteralComponentType(valueOf_=data.get('literal_value')))
                elif comp_type == 'variable':
                    new_entity.set_variable_component(models.VariableComponentType(var_ref=data.get('var_ref')))
                elif comp_type == 'object':
                   # Build arguments, only including record_field if it has a value
                    comp_kwargs = {
                        'object_ref': data.get('object_ref'),
                        'item_field': data.get('item_field')
                    }
                    if data.get('record_field'):
                        comp_kwargs['record_field'] = data.get('record_field')
                    
                    new_entity.set_object_component(models.ObjectComponentType(**comp_kwargs))
                elif comp_type == 'function':
                    func_type = data.get('function_type')
                    components_data = data.get('components_data', [])
                    
                    func = None
                    if func_type == 'arithmetic':
                        func = models.ArithmeticFunctionType(arithmetic_operation=data.get('arithmetic_op'))
                        new_entity.set_arithmetic(func)
                    elif func_type == 'concat':
                        func = models.ConcatFunctionType()
                        new_entity.set_concat(func)
                    elif func_type == 'escape_regex':
                        func = models.EscapeRegexFunctionType()
                        new_entity.set_escape_regex(func)
                    elif func_type == 'unique':
                        func = models.UniqueFunctionType()
                        new_entity.set_unique(func)
                    elif func_type == 'count':
                        func = models.CountFunctionType()
                        new_entity.set_count(func)
                    elif func_type == 'time_difference':
                        func = models.TimeDifferenceFunctionType(
                            format_1=data.get('format_1'),
                            format_2=data.get('format_2')
                        )
                        new_entity.set_time_difference(func)
                    elif func_type in ['begin', 'end']:
                        func = models.BeginFunctionType(character=data.get('character')) if func_type == 'begin' else models.EndFunctionType(character=data.get('character'))
                        if func_type == 'begin': new_entity.set_begin(func)
                        else: new_entity.set_end(func)                   
                    elif func_type == 'split':
                        func = models.SplitFunctionType(delimiter=data.get('delimiter'))
                        new_entity.set_split(func)
                    elif func_type == 'regex_capture':
                        func = models.RegexCaptureFunctionType(pattern=data.get('pattern'))
                        comp_data = data.get('single_component_data')
                        new_entity.set_regex_capture(func)
                    elif func_type == 'glob_to_regex':
                        func = models.GlobToRegexFunctionType(glob_noescape=data.get('glob_noescape'))
                        new_entity.set_glob_to_regex(func)
                    elif func_type == 'substring':
                        func = models.SubstringFunctionType(
                            substring_start=data.get('substring_start'),
                            substring_length=data.get('substring_length')
                        )
                        new_entity.set_substring(func)
                        
                    if func:
#                        print(f"comp_data: {components_data}")
                        self._build_function_components(func, components_data, func_type)                    
                    
        print(f"entity: {new_entity}")
        return new_entity

    def _update_oval_entity(self, entity_to_edit, data, entity_type_str):
        """Updates an existing OVAL entity from dialog data."""
        if not data: return
        
        print(f"data: {data}")
        # --- Set COMMON attributes for all OVAL entities ---
        if 'id' in data: entity_to_edit.set_id(data['id'])
        if 'version' in data: entity_to_edit.set_version(data['version'])
        if 'comment' in data: entity_to_edit.set_comment(data['comment'])

        # --- Set SPECIFIC attributes based on the entity's type ---
        if entity_type_str == 'test':
            if 'check' in data: entity_to_edit.set_check(data['check'])
            if 'check_existence' in data: entity_to_edit.set_check_existence(data['check_existence'])
            if 'object_ref' in data:
                obj_ref = entity_to_edit.get_object() or models.ObjectRefType()
                obj_ref.set_object_ref(data['object_ref'])
                obj_ref.ns_prefix_ = entity_to_edit.ns_prefix_
                entity_to_edit.set_object(obj_ref)
            if 'state_ref' in data:
                state_ref = (entity_to_edit.get_state() or [models.StateRefType()])[0]
                state_ref.set_state_ref(data['state_ref'])
                state_ref.ns_prefix_ = entity_to_edit.ns_prefix_
                entity_to_edit.set_state([state_ref])

        elif entity_type_str == 'object':

            # --- FOR BEHAVIORS ---
            if 'behaviors' in data:
                b_data = data['behaviors']
                behaviors_obj = entity_to_edit.get_behaviors()
                
                if isinstance(entity_to_edit, models.textfilecontent54_object):
                    if b_data and not behaviors_obj: 
                        behaviors_obj = models.Textfilecontent54Behaviors()
                        behaviors_obj.ns_prefix_ = entity_to_edit.ns_prefix_
                        entity_to_edit.set_behaviors(behaviors_obj)                        
                else:
                    if b_data and not behaviors_obj: 
                        behaviors_obj = models.FileBehaviors()
                        behaviors_obj.ns_prefix_ = entity_to_edit.ns_prefix_
                        entity_to_edit.set_behaviors(behaviors_obj)
                if behaviors_obj:
                    for key, value in b_data.items():
                        setter_name = f"set_{key}"
                        if hasattr(behaviors_obj, setter_name):
                            getattr(behaviors_obj, setter_name)(value)

            # --- FOR FILTERS ---
            if 'filter' in data:
                f_data = data['filter']
                if f_data.get('state_id'):
                    filter_obj = entity_to_edit.get_filter()[0] if entity_to_edit.get_filter() else None
                    if not filter_obj: # Create if it doesn't exist
                        filter_obj = models.filter()
                        entity_to_edit.add_filter(filter_obj)
                    
                    # --- Update its properties
                    filter_obj.set_action(f_data['action'])
                    filter_obj.set_valueOf_(f_data['state_id'])
                else: # The state ID was cleared, so remove the filter
                    entity_to_edit.set_filter([])

            # --- FOR REST ---
            for prop_name, prop_data in data.items():
                if prop_name in ['id', 'version', 'comment', 'behaviors', 'filter']:
                    continue # Skip common props handled elsewhere

                getter_name = f"get_{prop_name}"
                setter_name = f"set_{prop_name}"

                # --- Check if the entity actually has this property
                if hasattr(entity_to_edit, getter_name) and hasattr(entity_to_edit, setter_name):
                    # --- This logic correctly determines which wrapper to use based on the property name
                    # --- This can be expanded as you add more types
                    
                    if prop_name in ["version_"]:
                        if (isinstance(entity_to_edit, models.sql57_object) or isinstance(entity_to_edit, models.sql_object)):
                            wrapper_class = models.EntityObjectStringType
                        elif (isinstance(entity_to_edit, models.rpmverifyfile_object) or isinstance(entity_to_edit, models.rpmverifypackage_object)):
                            wrapper_class = models.EntityObjectAnySimpleType
                    elif prop_name in ['instance', 'pid', 'local_port']:
                        wrapper_class = models.EntityObjectIntType
                    elif prop_name in ['path', 'filename', 'filepath', 'name', 'connection_string', 'sql', 'xpath', 'pattern', 'domain_name', \
                       'attribute_name', 'key', 'source', 'protocol', 'service_name', 'username', 'command_line', 'runlevel', 'interface_name', \
                       'mount_point', 'arch', 'unit', 'property']:
                         wrapper_class = models.EntityObjectStringType
                    elif prop_name in ['epoch', 'release']:
                        wrapper_class = models.EntityObjectAnySimpleType
                    elif prop_name in ['local_address', 'destination']:
                        wrapper_class = models.EntityObjectIPAddressType
                    #Defined Problem Children
                    elif prop_name in ['hash_type', 'engine']:
                        wrapper_class = models.EntityObjectStringType
                    elif prop_name in ['var_ref']:
                        wrapper_class = models.EntityObjectVariableRefType
                    #Left Overs
                    else:
                        wrapper_class = models.EntityObjectStringType
                         
                        
                    self._update_wrapped_entity(
                        entity_to_edit,
                        prop_data,
                        getattr(entity_to_edit, getter_name),
                        getattr(entity_to_edit, setter_name),
                        wrapper_class
                    )

        elif entity_type_str == 'state':
            if 'operator' in data: new_entity.set_operator(data['operator'])
            for prop_name, prop_data in data.items():
                if prop_name in ['id', 'version', 'comment', 'operator']:
                    continue # Skip common props handled elsewhere

                getter_name = f"get_{prop_name}"
                setter_name = f"set_{prop_name}"

                # --- Check if the entity actually has this property
                if hasattr(entity_to_edit, getter_name) and hasattr(entity_to_edit, setter_name):
                    # --- This logic correctly determines which wrapper to use based on the property name
                    # --- This can be expanded as you add more types
                    
                    if prop_name in ['version_']:
                        if (isinstance(entity_to_edit, models.slackwarepkginfo_state) or isinstance(entity_to_edit, models.sql57_state)):
                            wrapper_class = models.EntityStateStringType
                        elif isinstance(entity_to_edit, models.rpmverifypackage_state) or isinstance(entity_to_edit, models.rpmverifyfile_state) or\
                           isinstance(entity_to_edit, models.rpminfo_state) or isinstance(entity_to_edit, models.dpkginfo_state):
                            wrapper_class = models.EntityObjectAnySimpleType                
                    elif prop_name in ['type']:
                        if (isinstance(entity_to_edit, models.selinuxsecuritycontext_state) or isinstance(entity_to_edit, models.file_state)):
                            wrapper_class = models.EntityStateStringType
                        elif isinstance(entity_to_edit, models.interface_state):
                            wrapper_class = models.EntityStateInterfaceType
                        elif isinstance(entity_to_edit, models.gconf_state):
                            wrapper_class = models.EntityStateGconfTypeType
                        elif isinstance(entity_to_edit, models.xinetd_state):
                            wrapper_class = models.EntityStateXinetdTypeStatusType
                    elif prop_name in ['flags']:
                        if isinstance(entity_to_edit, models.xinetd_state):
                            wrapper_class = models.EntityStateStringType
                        elif isinstance(entity_to_edit, models.routingtable_state):
                            wrapper_class = models.EntityStateRoutingTableFlagsType
                    elif prop_name in ['arch', 'architecture', 'attribute_name', 'canonical_path', 'command_line', 'connection_string', 'dependency', \
                       'device', 'domain_name', 'exec_as_user', 'exec_time', 'extended_name', 'filename', 'filepath', 'flag', 'fs_type', 'gcos', \
                       'hardware_addr', 'hash', 'high_category', 'high_sensitivity', 'home_dir', 'hw_address', 'interface_name', 'key', 'login_shell', \
                       'low_category', 'low_sensitivity', 'machine_class', 'mod_user', 'mount_options', 'mount_point', 'name', 'no_access', 'node_name', \
                       'os_name', 'os_release', 'os_version', 'password', 'path', 'pattern', 'processor_type', 'program_name', 'property', 'protocol', \
                       'rawhigh_category', 'rawhigh_sensitivity', 'rawlow_category', 'rawlow_sensitivity', 'revision', 'role', 'runlevel', 'scheduling_class', \
                       'selinux_domain_label', 'server', 'server_arguments', 'server_program', 'service_name', 'signature_keyid', 'socket_type', 'source', \
                       'sql', 'start_time', 'tty', 'unit', 'user', 'username', 'uuid', 'xpath']:
                        wrapper_class = models.EntityStateStringType
                    elif prop_name in ['a_time', 'chg_allow', 'chg_lst', 'chg_req', 'c_time', 'exp_date', 'exp_inact', 'exp_warn', 'group_id', 'instance', \
                       'last_login', 'loginuid', 'mod_time', 'm_time', 'pid', 'port', 'ppid', 'priority', 'ruid', 'session_id', 'size', 'space_left', \
                       'space_used', 'total_space', 'ttl', 'user_id']:
                        wrapper_class = models.EntityStateIntType
                    elif prop_name in ['configuration_file', 'current_status', 'dependency_check_passed', 'digest_check_passed', 'disabled', 'documentation_file', \
                       'exec_shield', 'gexec', 'ghost_file', 'gread', 'gwrite', 'has_extended_acl', 'is_default', 'is_writable', 'kill', 'license_file', 'oexec', \
                       'oread', 'owrite', 'pending_status', 'readme_file', 'sgid', 'signature_check_passed', 'start', 'sticky', 'suid', 'uexec', 'uread', \
                       'uwrite', 'verification_script_successful', 'wait']:
                        wrapper_class = models.EntityStateBoolType
                    elif prop_name in ['capabilities_differ', 'device_differs', 'group_differs', 'link_mismatch', 'md5_differs', 'mode_differs', \
                       'mtime_differs', 'ownership_differs', 'size_differs']:
                        wrapper_class = models.EntityStateRpmVerifyResultType
                    elif prop_name in ['epoch', 'result', 'subexpression', 'text', 'value', 'value_of']:
                        wrapper_class = models.EntityStateAnySimpleType
                    elif prop_name in ['broadcast_addr', 'inet_addr', 'ip_address', 'netmask', 'only_from']:
                        wrapper_class = models.EntityStateIPAddressStringType
                    elif prop_name in ['destination', 'gateway']:
                        wrapper_class = models.EntityStateIPAddressType
                    elif prop_name in ['posix_capability', 'protocol']:
                        wrapper_class = models.EntityStateCapabilityType
                    elif prop_name in ['encrypt_method']:
                        wrapper_class = models.EntityStateEncryptMethodType
                    elif prop_name in ['endpoint_type']:
                        wrapper_class = models.EntityStateEndpointType
                    elif prop_name in ['engine']:
                        wrapper_class = models.EntityStateEngineType
                    elif prop_name in ['evr']:
                        wrapper_class = models.EntityStateEVRStringType
                    elif prop_name in ['family']:
                        wrapper_class = models.EntityStateFamilyType
                    elif prop_name in ['hash_type']:
                        wrapper_class = models.EntityStateHashTypeType
                    elif prop_name in ['release']:
                        wrapper_class = models.EntityStateProtocolType
                    elif prop_name in ['var_ref']:
                        wrapper_class = models.EntityStateRecordType
                    elif prop_name in ['wait_status']:
                        wrapper_class = models.EntityStateWaitStatusType
                    elif prop_name in ['windows_view']:
                        wrapper_class = models.EntityStateWindowsViewType
                    #Left Overs
                    else:
                        wrapper_class = models.EntityObjectStringType
                         
                    self._update_wrapped_entity(
                        entity_to_edit,
                        prop_data,
                        getattr(entity_to_edit, getter_name),
                        getattr(entity_to_edit, setter_name),
                        wrapper_class
                    )

        elif entity_type_str == 'variable':
            entity_to_edit.set_datatype(data['datatype'])
            
            if isinstance(entity_to_edit, models.constant_variable) and 'value' in data:
                entity_to_edit.set_value([])
                for val in data['value']:
                    entity_to_edit.add_value(models.ValueType(valueOf_=val))

            elif isinstance(entity_to_edit, models.external_variable):
                # Update possible values
                entity_to_edit.set_possible_value([])
                if 'possible_value' in data:
                    for pv_data in data['possible_value']:
                        pv = models.PossibleValueType(
                            valueOf_=pv_data.get('value'),
                            hint=pv_data.get('hint')
                        )
                        entity_to_edit.add_possible_value(pv)
                
                # Update possible restrictions
                entity_to_edit.set_possible_restriction([])
                if 'possible_restriction' in data:
                    for pr_data in data['possible_restriction']:
                        pr = models.PossibleRestrictionType(
                            hint=pr_data.get('hint'),
                            operator=pr_data.get('operator')
                        )
                        for r_data in pr_data.get('restrictions', []):
                            restriction_child = models.RestrictionType(
                                valueOf_=r_data.get('value'),
                                operation=r_data.get('operation')
                            )
                            pr.add_restriction(restriction_child)
                        entity_to_edit.add_possible_restriction(pr)

            elif isinstance(entity_to_edit, models.local_variable):
                # Clear all possible components first
                entity_to_edit.set_literal_component(None)
                entity_to_edit.set_variable_component(None)
                entity_to_edit.set_object_component(None)
                
                comp_type = data.get('component_type')
                if comp_type == 'literal':
                    entity_to_edit.set_literal_component(models.LiteralComponentType(valueOf_=data.get('literal_value')))
                elif comp_type == 'variable':
                    entity_to_edit.set_variable_component(models.VariableComponentType(var_ref=data.get('var_ref')))
                elif comp_type == 'object':
                    # Build arguments, only including record_field if it has a value
                    comp_kwargs = {
                        'object_ref': data.get('object_ref'),
                        'item_field': data.get('item_field')
                    }
                    if data.get('record_field'):
                        comp_kwargs['record_field'] = data.get('record_field')
                    
                    entity_to_edit.set_object_component(models.ObjectComponentType(**comp_kwargs))
                elif comp_type == 'function':
                    func_type = data.get('function_type')
                    components_data = data.get('components_data', [])
                     
                    if func_type == 'arithmetic':
                        func = models.ArithmeticFunctionType(arithmetic_operation=data.get('arithmetic_op'))
                        entity_to_edit.set_arithmetic(func)
                    elif func_type == 'concat':
                        func = models.ConcatFunctionType()
                        entity_to_edit.set_concat(func)
                    elif func_type == 'escape_regex':
                        func = models.EscapeRegexFunctionType()
                        entity_to_edit.set_escape_regex(func)
                    elif func_type == 'unique':
                        func = models.UniqueFunctionType()
                        entity_to_edit.set_unique(func)
                    elif func_type == 'count':
                        func = models.CountFunctionType()
                        entity_to_edit.set_count(func)
                    elif func_type == 'time_difference':
                        func = models.TimeDifferenceFunctionType(
                            format_1=data.get('format_1'),
                            format_2=data.get('format_2')
                        )
                        entity_to_edit.set_time_difference(func)                    
                    elif func_type in ['begin', 'end']:
                        func = models.BeginFunctionType(character=data.get('character')) if func_type == 'begin' else models.EndFunctionType(character=data.get('character'))

                        if func_type == 'begin': entity_to_edit.set_begin(func)
                        else: entity_to_edit.set_end(func)                        

                    elif func_type == 'split':
                        func = models.SplitFunctionType(delimiter=data.get('delimiter'))
                        entity_to_edit.set_split(func)
                    elif func_type == 'regex_capture':
                        func = models.RegexCaptureFunctionType(pattern=data.get('pattern'))
                        entity_to_edit.set_regex_capture(func)
                    elif func_type == 'glob_to_regex':
                        func = models.GlobToRegexFunctionType(glob_noescape=data.get('glob_noescape'))
                        entity_to_edit.set_glob_to_regex(func)

                    elif func_type == 'substring':
                        func = models.SubstringFunctionType(
                            substring_start=data.get('substring_start'),
                            substring_length=data.get('substring_length')
                        )
                        entity_to_edit.set_substring(func)
                        
                    if func:
                        self._build_function_components(func, components_data, func_type)
#        print(f"entity: {entity_to_edit}")  


##--  [  OVAL Tests ]---
    def populate_oval_tests_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL tests treeview."""
        for i in self.oval_tests_tree.get_children():
            self.oval_tests_tree.delete(i)
        
        self.maps['oval_test'].clear()
        
        tests_container = oval_defs_obj.get_tests()
        if tests_container and tests_container.get_test():
            for test in tests_container.get_test():
                test_type_name = test.__class__.__name__

                comment_text = test.get_comment() or ""
                
                item_id = self.oval_tests_tree.insert("", "end", values=(
                    test.get_id(),
                    test_type_name,
                    comment_text
                ))
                
                self.maps['oval_test'][item_id] = test

    def _show_generic_test_details_dialog(self, test_class, test_to_edit=None):
        """A smart dialog that filters object/state refs based on the test type."""
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        is_edit = test_to_edit is not None
        dialog.title(f"{'Edit' if is_edit else 'Add'} OVAL {test_class.__name__}")
        
        base_name = test_class.__name__.replace('_test', '')
        expected_obj_name = f"{base_name}_object"
        expected_state_name = f"{base_name}_state"
        
        expected_obj_class = getattr(models, expected_obj_name, None)
        expected_state_class = getattr(models, expected_state_name, None)
        
        results = {}
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        def _create_ref_editor(parent, row, label, get_ids_func, add_entity_func, initial_value, filter_class):
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=2)
            ref_frame = ttk.Frame(parent)
            ref_frame.grid(row=row, column=1, sticky="ew")
            
            ref_var = tk.StringVar(value=initial_value)
            combo = ttk.Combobox(ref_frame, textvariable=ref_var, values=get_ids_func(filter_class=filter_class))
            combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

            def _create_new():
                new_entity = add_entity_func(self.current_oval_defs, entity_type_str=label.split(' ')[0].lower(), selected_class=filter_class)
                if new_entity:
                    combo['values'] = get_ids_func(filter_class=filter_class)
                    ref_var.set(new_entity.get_id())

            ttk.Button(ref_frame, text="New...", command=_create_new).pack(side=tk.LEFT, padx=(5,0))
            return ref_var

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

        obj_ref_val = test_to_edit.get_object().get_object_ref() if is_edit and test_to_edit.get_object() else ""
        object_ref_var = _create_ref_editor(main_frame, 5, "Object Ref:", self.get_oval_object_ids, self.add_oval_entity, obj_ref_val, expected_obj_class)

        st_ref_val = test_to_edit.get_state()[0].get_state_ref() if is_edit and test_to_edit.get_state() else ""
        state_ref_var = _create_ref_editor(main_frame, 6, "State Ref:", self.get_oval_state_ids, self.add_oval_entity, st_ref_val, expected_state_class)
        
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
        if not self.datastream_collection or not self.maps['oval_object']:
            return []
        
        object_map = self.maps['oval_object']
        
        if filter_class:
            return [obj.get_id() for obj in object_map.values() if isinstance(obj, filter_class)]
        else:
            return [obj.get_id() for obj in object_map.values()]

    def get_oval_state_ids(self, filter_class=None):
        """Returns a list of all OVAL state IDs, optionally filtered by a specific class."""
        if not self.datastream_collection or not self.maps['oval_state']:
            return []
        
        state_map = self.maps['oval_state']
            
        if filter_class:
            return [state.get_id() for state in state_map.values() if isinstance(state, filter_class)]
        else:
            return [state.get_id() for state in state_map.values()]

            
##--  [  OVAL Objects ]---
    def populate_oval_objects_tree(self, oval_defs_obj):
        """Clears and repopulates the OVAL objects treeview."""
        for i in self.oval_objects_tree.get_children():
            self.oval_objects_tree.delete(i)
        
        self.maps['oval_object'].clear()
        
        objects_container = oval_defs_obj.get_objects()
        if objects_container and objects_container.get_object():
            for obj in objects_container.get_object():
                obj_type_name = obj.__class__.__name__
                comment_text = obj.get_comment() or ""
                
                item_id = self.oval_objects_tree.insert("", "end", values=(
                    obj.get_id(),
                    obj_type_name,
                    comment_text
                ))
                
                self.maps['oval_object'][item_id] = obj

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
                if obj_class is models.rpminfo_object:
                    b_widgets['filepaths'] = create_behavior_row(behaviors_frame, b_row, 'filepaths', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                elif obj_class is models.rpmverifypackage_object:
                    b_widgets['nodeps'] = create_behavior_row(behaviors_frame, b_row, 'nodeps', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nodigest'] = create_behavior_row(behaviors_frame, b_row, 'nodigest', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['noscripts'] = create_behavior_row(behaviors_frame, b_row, 'noscripts', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                    b_widgets['nosignature'] = create_behavior_row(behaviors_frame, b_row, 'nosignature', ttk.Combobox, values=['true', 'false'], state='readonly')
                    b_row += 1
                elif (obj_class is models.rpmverifyfile_object or obj_class is models.rpmverify_object):
                    if obj_class is models.rpmverify_object:
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
                
                if (obj_class is models.filehash58_object or obj_class is models.xmlfilecontent_object):
                    b_widgets['windows_view'] = create_behavior_row(behaviors_frame, b_row, 'windows_view', ttk.Combobox, values=['32_bit', '64_bit'], state='readonly')
                    b_row += 1

                if obj_class is models.textfilecontent54_object: 
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
            elif prop_name == 'var_ref_':
                ttk.Label(val_frame, text="Value:").pack(side=tk.LEFT)
                var_ids = self.get_oval_variable_ids(specific_oval_defs=self.current_oval_defs)
                ttk.Combobox(val_frame, textvariable=val_var, values=var_ids, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True)
            else:    
                ttk.Label(val_frame, text="Value:").pack(side=tk.LEFT)
                ttk.Entry(val_frame, textvariable=val_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
    
            attr_frame = ttk.Frame(prop_container, padding=(0, 5))

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
                
            mask_var = tk.StringVar(value=val_obj.get_mask() if val_obj else "")
            ttk.Label(attr_frame, text="Mask:").grid(row=1, column=0, sticky='w', pady=(5,0))
            ttk.Combobox(attr_frame, textvariable=mask_var, values=["true", "false"], state="readonly", width=8).grid(row=1, column=1, sticky='ew', padx=5, pady=(5,0))

             # Variable Reference (now a dropdown)
            var_ref_var = tk.StringVar(value=val_obj.get_var_ref() if val_obj and hasattr(val_obj, 'get_var_ref') else "")
            ttk.Label(attr_frame, text="Variable Ref:").grid(row=1, column=2, sticky='w', padx=10, pady=(5,0))
            ttk.Combobox(attr_frame, textvariable=var_ref_var, values=self.get_oval_variable_ids(specific_oval_defs=self.current_oval_defs)).grid(row=1, column=3, sticky='ew', padx=5, pady=(5,0))


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
               param.name not in self.DEPRECATED_OVAL_ENTITIES and \
               param.name not in self.EXCLUDED_OVAL_PROPERTIES:
                
                # --- Look up the datatype from our new map, defaulting to 'string'
                datatype = self.OVAL_PROPERTY_DATATYPE_MAP.get(param.name, 'string')
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
        self.maps['oval_state'].clear()
        
        states_container = oval_defs_obj.get_states()
        if states_container and states_container.get_state():
            for state in states_container.get_state():
                state_type_name = state.__class__.__name__
                item_id = self.oval_states_tree.insert("", "end", values=(
                    state.get_id(),
                    state_type_name,
                    state.get_comment()
                ))
                self.maps['oval_state'][item_id] = state

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

        version_var = None
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
            val_obj = getattr(state_to_edit, f"get_{prop_name}", lambda: None)() if is_edit else None
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
        self.maps['oval_variable'].clear()
        
        variables_container = oval_defs_obj.get_variables()
        if variables_container and variables_container.get_variable():
            for var in variables_container.get_variable():
                var_type_name = var.__class__.__name__
                item_id = self.oval_variables_tree.insert("", "end", values=(
                    var.get_id(),
                    var_type_name,
                    var.get_comment()
                ))
                self.maps['oval_variable'][item_id] = var

    def get_oval_variable_ids(self, specific_oval_defs=None):
        """
        Returns a list of all OVAL variable IDs. If specific_oval_defs is provided,
        it searches only within that object.
        """
        ids = []
        target_defs = [specific_oval_defs] if specific_oval_defs else \
                      [c.oval_definitions for c in self.datastream_collection.get_component() if c.oval_definitions]
        
        if not self.datastream_collection:
            return ids
        
        for oval_defs in target_defs:
            if oval_defs and oval_defs.get_variables():
                for var in oval_defs.get_variables().get_variable():
                    ids.append(var.get_id())
        
        return sorted(list(set(ids)))
            
    def _show_generic_variable_details_dialog(self, var_class, var_to_edit=None):
        """A smart dialog that builds an input form for any OVAL variable."""
##        from models import oval_core_models
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
        if var_class is models.constant_variable:
            initial_values = [v.get_valueOf_() for v in var_to_edit.get_value()] if is_edit and var_to_edit.get_value() else []
            frame, editor_data = create_list_editor(
                main_frame, "Values", initial_values, self._show_value_dialog, 
                lambda d: d, 'value_to_edit'
            )
            frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)
            results['value'] = editor_data.data

        elif var_class is models.external_variable:
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

        elif var_class is models.local_variable:
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
            if var_class is models.local_variable:
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
                self._mark_as_dirty() # Mark change

        def edit_item():
            selected_index = listbox.curselection()
            if not selected_index: return
            index = selected_index[0]
            edited_data = self._show_restriction_dialog(restriction_to_edit=restrictions_data[index])
            if edited_data:
                restrictions_data[index] = edited_data
                listbox.delete(index)
                listbox.insert(index, f"{edited_data['value']} (Operation: {edited_data.get('operation', 'equals')})")
                self._mark_as_dirty() # Mark change

        def remove_item():
            selected_index = listbox.curselection()
            if not selected_index: return
            index = selected_index[0]
            listbox.delete(index)
            del restrictions_data[index]
            self._mark_as_dirty() # Mark change

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
            self._mark_as_dirty()
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

        func_type_var = tk.StringVar()
        ttk.Label(function_frame, text="Function Type:").pack(anchor='w')
        func_options = ["arithmetic", "concat", "end", "escape_regex", "split", "substring", "time_difference", "regex_capture", "unique", "count", "glob_to_regex"]
        ttk.Combobox(function_frame, textvariable=func_type_var, values=func_options, state='readonly').pack(fill=tk.X)
        ttk.Button(function_frame, text="Define...", command=lambda: messagebox.showinfo("Info", "Nested function components are defined in the main editor.")).pack(pady=5)

        # Pre-fill if editing
        if component_to_edit:
            ctype = component_to_edit.get('type')
            component_type_var.set(ctype)
            if ctype == 'literal_component':
                lit_var.set(component_to_edit.get('value', ''))
            elif ctype == 'object_component':
                obj_ref_var.set(component_to_edit.get('object_ref', ''))
                item_field_var.set(component_to_edit.get('item_field', ''))
                rec_field_var.set(component_to_edit.get('record_field', ''))
            elif ctype == 'variable_component':
                var_ref_var.set(component_to_edit.get('var_ref', ''))
            elif ctype == 'function_group':
                func_type_var.set(component_to_edit.get('function_type', ''))
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
    def create_detail_entry(self, parent_frame, label_text, data_obj, attr_name, read_only=False):
        frame = ttk.Frame(parent_frame)
        frame.pack(fill=tk.X, pady=5)
        
        label = ttk.Label(frame, text=label_text, width=15)
        label.pack(side=tk.LEFT, anchor='n')
        
        var = tk.StringVar(self.root)
        var.set(getattr(data_obj, attr_name, ""))

        widget = ttk.Entry(frame, textvariable=var)
        widget.var = var
        
        if read_only:
            widget.config(state='readonly')

        else:            
            def update_data(*args):
                setattr(data_obj, attr_name, var.get())
                self._mark_as_dirty()
            var.trace_add("write", update_data)

        widget.pack(fill=tk.X, expand=True)
      
    def get_cpe_dictionary(self):
        """
        Finds and returns the first CPE List component in the datastream.
        Returns None if no datastream or CPE dictionary is found.
        """
        if self.datastream_collection and self.datastream_collection.get_component():
            for comp in self.datastream_collection.get_component():
                if hasattr(comp, 'cpe_list') and comp.cpe_list is not None:
                    return comp.cpe_list
        return None

    def get_oval_definition_ids(self, specific_oval_defs=None):
        """
        Finds and returns a sorted list of unique OVAL definition IDs.
        If specific_oval_defs is provided, searches only within that object.
        Otherwise, searches all OVAL components in the datastream.
        """
        ids = []
        if not self.datastream_collection:
            return ids

        # Determine which OVAL components to search
        if specific_oval_defs:
            targets = [specific_oval_defs]
        else:
            targets = [c.oval_definitions for c in self.datastream_collection.get_component() if c.oval_definitions]

        # Collect the definition IDs
        for oval_defs in targets:
            if oval_defs and oval_defs.get_definitions():
                for definition in oval_defs.get_definitions().get_definition():
                    ids.append(definition.get_id())
        
        return sorted(list(set(ids)))

    def get_oval_components(self):
        """Finds all OVAL components in the datastream and returns a map of their ID to the object."""
        components = {}
        if self.datastream_collection and self.datastream_collection.get_component():
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
        
    def show_welcome_message(self):
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        ttk.Label(self.detail_frame, text="Welcome!", font=("Helvetica", 16)).pack()
        ttk.Label(self.detail_frame, text="Use Create -> New Datastream to get started.", justify=tk.LEFT).pack()         


    def build_entity_from_node(self, node, entity_type_str):
        """Builds an OVAL entity object from an lxml etree node."""
        # Get the class name from the tag (e.g., 'textfilecontent54_test')
        class_name = node.tag.split('}')[-1]
        
        # Find the correct Python class for that name
        base_class = getattr(oval, f"{entity_type_str.capitalize()}Type")
        entity_map = self._get_available_entity_types(base_class)
        
        selected_class = None
        for family in entity_map.values():
            for friendly_name, class_obj in family.items():
                if class_obj.__name__ == class_name:
                    selected_class = class_obj
                    break
            if selected_class: break
        
        if not selected_class:
            return None

        # Create an empty instance and populate it
        new_entity = selected_class()
        new_entity.original_tagname_ = class_name
        
        # Set attributes from the XML node
        if 'id' in node.attrib: new_entity.set_id(node.attrib['id'])
        if 'version' in node.attrib: new_entity.set_version(node.attrib['version'])
        if 'comment' in node.attrib: new_entity.set_comment(node.attrib['comment'])
        if 'check' in node.attrib: new_entity.set_check(node.attrib['check'])
        if 'check_existence' in node.attrib: new_entity.set_check_existence(node.attrib['check_existence'])
        
        # This can be expanded to build child elements recursively
        
        return new_entity
        
    def _get_correct_wrapper_class(self, parent_entity_class, wrapper_name):
        """
        Finds the correct wrapper class (e.g., EntityObjectStringType) from the
        same module as the parent entity.
        """
        module = inspect.getmodule(parent_entity_class)
        return getattr(module, wrapper_name, None)
        
    def _create_wrapped_entity(self, parent_entity, prop_data, wrapper_class):
        """Helper to build a new wrapper object (e.g., EntityObjectStringType)."""
        if not prop_data or not prop_data.get('value'):
            return None
            
        kwargs = {'valueOf_': prop_data.get('value')}
        if prop_data.get('datatype'): kwargs['datatype'] = prop_data.get('datatype')
        if prop_data.get('operation'): kwargs['operation'] = prop_data.get('operation')
        if prop_data.get('mask'): kwargs['mask'] = prop_data.get('mask')
        if prop_data.get('var_ref'): kwargs['var_ref'] = prop_data.get('var_ref')
        
        wrapped_entity = wrapper_class(**kwargs)
        wrapped_entity.ns_prefix_ = parent_entity.ns_prefix_
        return wrapper_class(**kwargs)

    def _update_wrapped_entity(self, parent_entity, prop_data, getter_func, setter_func, wrapper_class):
        """Helper to update an existing wrapper object."""
        if not prop_data: return

        if prop_data.get('value'):
            existing_entity = getter_func()
            kwargs = {'valueOf_': prop_data.get('value')}
            if prop_data.get('datatype'): kwargs['datatype'] = prop_data.get('datatype')
            if prop_data.get('operation'): kwargs['operation'] = prop_data.get('operation')
            if prop_data.get('mask'): kwargs['mask'] = prop_data.get('mask')
            if prop_data.get('var_ref'): kwargs['var_ref'] = prop_data.get('var_ref')

            if not existing_entity:
                new_entity = wrapper_class(**kwargs)
                new_entity.ns_prefix_ = parent_entity.ns_prefix_
                setter_func(new_entity)
            else:
                for key, value in kwargs.items():
                    setter_name = f"set_{key}"
                    if hasattr(existing_entity, setter_name):
                         getattr(existing_entity, setter_name)(value)
        else:
            setter_func(None)

    def _set_wrapped_property(self, parent_entity, data, prop_name, wrapper_class):
        """
        A helper to create, prefix, and set a wrapped property on a parent entity.
        """
        if prop_name in data:
            entity = self._create_wrapped_entity(parent_entity, data[prop_name], wrapper_class)
            if entity:
                setter_method = getattr(parent_entity, f"set_{prop_name}")
                setter_method(entity)
                entity.ns_prefix_ = parent_entity.ns_prefix_

    def _build_function_components(self, parent_function, components_data, func_type):
        """A helper to build the components inside any function."""
        if not components_data:
#            print(f"No")
            return
        for comp_data in components_data:
            comp_type = comp_data.get('type')
#            print(f"comp_type: {comp_type}")
            if comp_type == 'literal_component':
                if func_type in ["begin", "end", "split", "regex_capture", "glob_to_regex", "substring"]:
                    parent_function.set_literal_component(models.LiteralComponentType(valueOf_=comp_data.get('value')))
                else:
                    parent_function.add_literal_component(models.LiteralComponentType(valueOf_=comp_data.get('value')))
            elif comp_type == 'object_component':
                oc_kwargs = {'object_ref': comp_data.get('object_ref'), 'item_field': comp_data.get('item_field')}
                if comp_data.get('record_field'): oc_kwargs['record_field'] = comp_data.get('record_field')
                if func_type in ["begin", "end", "split", "regex_capture", "glob_to_regex", "substring"]:
                    parent_function.set_object_component(models.ObjectComponentType(**oc_kwargs))
                else:
                    parent_function.add_object_component(models.ObjectComponentType(**oc_kwargs))
            elif comp_type == 'variable_component':
                if func_type in ["begin", "end", "split", "regex_capture", "glob_to_regex", "substring"]:
                    parent_function.set_variable_component(models.VariableComponentType(var_ref=comp_data.get('var_ref')))
                else:
                    parent_function.add_variable_component(models.VariableComponentType(var_ref=comp_data.get('var_ref')))

            # --- START RECURSIVE LOGIC ---
            elif comp_type == 'function_group':
                func_group = models.FunctionGroup()
                func_type = comp_data.get('function_type')
                
                func = None
                if func_type == 'arithmetic':
                    # A more advanced version would get the op and components
                    func = models.ArithmeticFunctionType()
                    func_group.set_arithmetic(func)
                # ... (add elif for other function types) ...
                
                # We would need a way to get the nested components' data
                # For now, we create an empty function group
                if func:
                    parent_function.add_function_group(func_group)
                    
  

####IMPORTS
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
            parsed_oval_defs = models.parse(oval_path, silence=True)
            
            comp_id = f"comp_oval_{uuid.uuid4()}"
            oval_component = models.component(
                id=comp_id,
                timestamp=datetime.now(),
                oval_definitions=parsed_oval_defs
            )
            
            self.datastream_collection.add_component(oval_component)
            comp_ref = self._create_component_ref(f"cref_oval_{uuid.uuid4()}", f"#{comp_id}")
            ds = self.datastream_collection.get_data_stream()[0]
            
            ref_list_obj = getattr(ds, f"get_{ref_list_name}")()
            if ref_list_obj is None:
                ref_list_obj = models.refListType()
                getattr(ds, f"set_{ref_list_name}")(ref_list_obj)
            
            ref_list_obj.add_component_ref(comp_ref)

            self.populate_treeview()
            messagebox.showinfo("Success", f"{component_type_str} component added.")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import OVAL file:\n{e}")


    def import_oval_component(self):
        self._import_oval_file("OVAL Check", "checks")
    
    def import_cpe_oval(self):
        self._import_oval_file("CPE OVAL", "dictionaries")


           
if __name__ == "__main__":
    root = tk.Tk()
    app = XccdfEditorApp(root)
    root.mainloop()