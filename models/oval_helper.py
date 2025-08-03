# --- models/oval_helper.py
import inspect
from . import oval
from . import oval_core_models

# --- A map defining the expected datatype for known OVAL properties.
OVAL_PROPERTY_DATATYPE_MAP = {
    #Integers
    'a_time': 'int',
    'chg_allow': 'int',
    'chg_lst': 'int',
    'chg_req': 'int',
    'c_time': 'int',
    'exp_date': 'int',
    'exp_inact': 'int',
    'exp_warn': 'int',
    'group_id': 'int',
    'instance': 'int',
    'last_login': 'int',
    'local_port': 'int',
    'loginuid': 'int',
    'mod_time': 'int',
    'm_time': 'int',
    'pid': 'int',
    'port': 'int',
    'ppid': 'int',
    'priority': 'int',
    'ruid': 'int',
    'session_id': 'int',
    'size': 'int',
    'space_left': 'int',
    'space_used': 'int',
    'total_space': 'int',
    'ttl': 'int',
    'user_id': 'int',
    #Strings
    'arch': 'string',
    'architecture': 'string',
    'attribute_name': 'string',
    'canonical_path': 'string',
    'command_line': 'string',
    'connection_string': 'string',
    'dependency': 'string',
    'device': 'string',
    'domain_name': 'string',
    'exec_as_user': 'string',
    'exec_time': 'string',
    'extended_name': 'string',
    'filename': 'string',
    'filepath': 'string',
    'flag': 'string',
    'fs_type': 'string',
    'gcos': 'string',
    'hardware_addr': 'string',
    'hash': 'string',
    'high_category': 'string',
    'high_sensitivity': 'string',
    'home_dir': 'string',
    'hw_address': 'string',
    'interface_name': 'string',
    'key': 'string',
    'login_shell': 'string',
    'low_category': 'string',
    'low_sensitivity': 'string',
    'machine_class': 'string',
    'mod_user': 'string',
    'mount_options': 'string',
    'mount_point': 'string',
    'name': 'string',
    'no_access': 'string',
    'node_name': 'string',
    'os_name': 'string',
    'os_release': 'string',
    'os_version': 'string',
    'password': 'string',
    'path': 'string',
    'pattern': 'string',
    'processor_type': 'string',
    'program_name': 'string',
    'property': 'string',
    'protocol': 'string',
    'rawhigh_category': 'string',
    'rawhigh_sensitivity': 'string',
    'rawlow_category': 'string',
    'rawlow_sensitivity': 'string',
    'revision': 'string',
    'role': 'string',
    'runlevel': 'string',
    'scheduling_class': 'string',
    'selinux_domain_label': 'string',
    'server': 'string',
    'server_arguments': 'string',
    'server_program': 'string',
    'service_name': 'string',
    'signature_keyid': 'string',
    'socket_type': 'string',
    'source': 'string',
    'sql': 'string',
    'start_time': 'string',
    'tty': 'string',
    'unit': 'string',
    'user': 'string',
    'username': 'string',
    'uuid': 'string',
    'xpath': 'string',
    
    'version': 'version',
    'hash_type': 'string',

    #Booleans
    'configuration_file': 'boolean',
    'current_status': 'boolean',
    'dependency_check_passed': 'boolean',
    'digest_check_passed': 'boolean',
    'disabled': 'boolean',
    'documentation_file': 'boolean',
    'exec_shield': 'boolean',
    'gexec': 'boolean',
    'ghost_file': 'boolean',
    'gread': 'boolean',
    'gwrite': 'boolean',
    'has_extended_acl': 'boolean',
    'is_default': 'boolean',
    'is_writable': 'boolean',
    'kill': 'boolean',
    'license_file': 'boolean',
    'oexec': 'boolean',
    'oread': 'boolean',
    'owrite': 'boolean',
    'pending_status': 'boolean',
    'readme_file': 'boolean',
    'sgid': 'boolean',
    'signature_check_passed': 'boolean',
    'start': 'boolean',
    'sticky': 'boolean',
    'suid': 'boolean',
    'uexec': 'boolean',
    'uread': 'boolean',
    'uwrite': 'boolean',
    'verification_script_successful': 'boolean',
    'wait': 'boolean',    
    # --- Add other properties and their types here as you support them
}

# --- A set of complex OVAL properties that should be excluded from the simple property selector.
EXCLUDED_OVAL_PROPERTIES = {
    'set_',        # This corresponds to the <set> element for OVAL Sets
    'Signature',
    'deprecated',
    'notes',
    'operator',
    'version',     # This is an attribute not an element
    'comment',     # This is an attribute not an element
}

# --- A set of OVAL entity class names that are deprecated and should not be shown in the UI.
DEPRECATED_OVAL_ENTITIES = {
    'family_test',
    'family_object',
    'family_state',
    'filehash_test',
    'filehash_object',
    'filehash_state',
    'sql_test',
    'sql_object',
    'sql_state',
#Oval >5.11.2    'sql57_test',
#Oval >5.11.2    'sql57_object',
#Oval >5.11.2    'sql57_state',
    'ldap_test',
    'ldap_object',
    'ldap_state',
    'ldap57_test',
    'ldap57_object',
    'ldap57_state',
    'textfilecontent_test',
    'textfilecontent_object',
    'textfilecontent_state',
    'environmentvariable_test',
    'environmentvariable_object',
    'environmentvariable_state',
    'patch_test',
    'patch_object',
    'process_test',
    'process_object',
    'process_state',
    'sccs_test',
    'sccs_object',
    'sccs_state',
    'apparmorstatus_test',
    'apparmorstatus_object',
    'apparmorstatus_state',
}

class OVAL_Entity_Factory:
    """A factory for creating and updating OVAL entity objects."""

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
                    parent_function.set_literal_component(oval.LiteralComponentType(valueOf_=comp_data.get('value')))
                else:
                    parent_function.add_literal_component(oval.LiteralComponentType(valueOf_=comp_data.get('value')))
            elif comp_type == 'object_component':
                oc_kwargs = {'object_ref': comp_data.get('object_ref'), 'item_field': comp_data.get('item_field')}
                if comp_data.get('record_field'): oc_kwargs['record_field'] = comp_data.get('record_field')
                if func_type in ["begin", "end", "split", "regex_capture", "glob_to_regex", "substring"]:
                    parent_function.set_object_component(oval.ObjectComponentType(**oc_kwargs))
                else:
                    parent_function.add_object_component(oval.ObjectComponentType(**oc_kwargs))
            elif comp_type == 'variable_component':
                if func_type in ["begin", "end", "split", "regex_capture", "glob_to_regex", "substring"]:
                    parent_function.set_variable_component(oval.VariableComponentType(var_ref=comp_data.get('var_ref')))
                else:
                    parent_function.add_variable_component(oval.VariableComponentType(var_ref=comp_data.get('var_ref')))

            # --- START RECURSIVE LOGIC ---
            elif comp_type == 'function_group':
                func_group = oval.FunctionGroup()
                func_type = comp_data.get('function_type')
                
                func = None
                if func_type == 'arithmetic':
                    # A more advanced version would get the op and components
                    func = oval.ArithmeticFunctionType()
                    func_group.set_arithmetic(func)
                # ... (add elif for other function types) ...
                
                # We would need a way to get the nested components' data
                # For now, we create an empty function group
                if func:
                    parent_function.add_function_group(func_group)
                    
    def create_entity(self, selected_class, data, entity_type_str):
        """Creates a new OVAL entity from dialog data."""
        if not data:
            return None
#        print(f"data: {data}")
        # --- Create an empty instance first
        new_entity = selected_class()
        new_entity.original_tagname_ = selected_class.__name__
        
        # --- Set COMMON attributes for all OVAL entities ---
        if 'id' in data: new_entity.set_id(data['id'])
        if 'version' in data: new_entity.set_version(data['version'])
        if 'comment' in data: new_entity.set_comment(data['comment'])

        if entity_type_str == 'test':
            if 'check' in data: new_entity.set_check(data['check'])
            if 'check_existence' in data: new_entity.set_check_existence(data['check_existence'])
            if data.get('object_ref'):
                obj_ref = oval.ObjectRefType(object_ref=data['object_ref'])
                obj_ref.ns_prefix_ = new_entity.ns_prefix_
                new_entity.set_object(obj_ref)
            if data.get('state_ref'):
                state_ref = oval.StateRefType(state_ref=data['state_ref'])
                state_ref.ns_prefix_ = new_entity.ns_prefix_
                new_entity.set_state([state_ref])      

        elif entity_type_str == 'object':
            if data.get('behaviors'):
                b_data = data['behaviors']
                b_kwargs = {k: v for k, v in b_data.items()}
                if isinstance(new_entity, oval.textfilecontent54_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = oval.Textfilecontent54Behaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, oval.rpminfo_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = oval.RpmInfoBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, oval.rpmverifypackage_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = oval.RpmVerifyPackageBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, oval.rpmverifyfile_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = oval.RpmVerifyFileBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                elif isinstance(new_entity, oval.rpmverify_object):
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = oval.RpmVerifyBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)
                else:
                    if b_kwargs: # Only create the object if at least one property was set
                        behaviors = oval.FileBehaviors(**b_kwargs)
                        behaviors.ns_prefix_ = new_entity.ns_prefix_
                        new_entity.set_behaviors(behaviors)

            # --- FOR FILTERS ---
            if 'filter' in data:
                f_data = data['filter']
                if f_data.get('state_id'): # Only add a filter if a state was selected
                    new_filter = oval.filter(valueOf_=f_data['state_id'], action=f_data['action'])
                    new_entity.add_filter(new_filter)
 
            for prop_name, prop_data in data.items():
                if prop_name in ['id', 'version', 'comment', 'behaviors', 'filter']:
                    continue # Skip common props and complex types handled elsewhere

                setter_name = f"set_{prop_name}"
                if hasattr(new_entity, setter_name):
                    # --- Determine which wrapper class to use based on the property name
                    if prop_name in ["version_"]:
                        if (isinstance(new_entity, oval.sql57_object) or isinstance(new_entity, oval.sql_object)):
                            wrapper_class = oval.EntityObjectStringType
                        elif (isinstance(new_entity, oval.rpmverifyfile_object) or isinstance(new_entity, oval.rpmverifypackage_object)):
                            wrapper_class = oval.EntityObjectAnySimpleType
                    elif prop_name in ['instance', 'pid', 'local_port']:
                        wrapper_class = oval.EntityObjectIntType
                    elif prop_name in ['path', 'filename', 'filepath', 'name', 'connection_string', 'sql', 'xpath', 'pattern', 'domain_name', \
                       'attribute_name', 'key', 'source', 'protocol', 'service_name', 'username', 'command_line', 'runlevel', 'interface_name', \
                       'mount_point', 'arch', 'unit', 'property']:
                         wrapper_class = oval.EntityObjectStringType
                    elif prop_name in ['epoch', 'release']:
                        wrapper_class = oval.EntityObjectAnySimpleType
                    elif prop_name in ['local_address', 'destination']:
                        wrapper_class = oval.EntityObjectIPAddressType
                    #Defined Problem Children
                    elif prop_name in ['hash_type', 'engine']:
                        wrapper_class = oval.EntityObjectStringType
                    #Left Overs
                    else:
                        wrapper_class = oval.EntityObjectStringType
                    
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
                        if (isinstance(new_entity, oval.slackwarepkginfo_state) or isinstance(new_entity, oval.sql57_state)):
                            wrapper_class = oval.EntityStateStringType
                        elif isinstance(new_entity, oval.rpmverifypackage_state) or isinstance(new_entity, oval.rpmverifyfile_state) or\
                           isinstance(new_entity, oval.rpminfo_state) or isinstance(new_entity, oval.dpkginfo_state):
                            wrapper_class = oval.EntityObjectAnySimpleType                
                    elif prop_name in ['type']:
                        if (isinstance(new_entity, oval.selinuxsecuritycontext_state) or isinstance(new_entity, oval.file_state)):
                            wrapper_class = oval.EntityStateStringType
                        elif isinstance(new_entity, oval.interface_state):
                            wrapper_class = oval.EntityStateInterfaceType
                        elif isinstance(new_entity, oval.gconf_state):
                            wrapper_class = oval.EntityStateGconfTypeType
                        elif isinstance(new_entity, oval.xinetd_state):
                            wrapper_class = oval.EntityStateXinetdTypeStatusType
                    elif prop_name in ['flags']:
                        if isinstance(new_entity, oval.xinetd_state):
                            wrapper_class = oval.EntityStateStringType
                        elif isinstance(new_entity, oval.routingtable_state):
                            wrapper_class = oval.EntityStateRoutingTableFlagsType
                    elif prop_name in ['arch', 'architecture', 'attribute_name', 'canonical_path', 'command_line', 'connection_string', 'dependency', \
                       'device', 'domain_name', 'exec_as_user', 'exec_time', 'extended_name', 'filename', 'filepath', 'flag', 'fs_type', 'gcos', \
                       'hardware_addr', 'hash', 'high_category', 'high_sensitivity', 'home_dir', 'hw_address', 'interface_name', 'key', 'login_shell', \
                       'low_category', 'low_sensitivity', 'machine_class', 'mod_user', 'mount_options', 'mount_point', 'name', 'no_access', 'node_name', \
                       'os_name', 'os_release', 'os_version', 'password', 'path', 'pattern', 'processor_type', 'program_name', 'property', 'protocol', \
                       'rawhigh_category', 'rawhigh_sensitivity', 'rawlow_category', 'rawlow_sensitivity', 'revision', 'role', 'runlevel', 'scheduling_class', \
                       'selinux_domain_label', 'server', 'server_arguments', 'server_program', 'service_name', 'signature_keyid', 'socket_type', 'source', \
                       'sql', 'start_time', 'tty', 'unit', 'user', 'username', 'uuid', 'xpath']:
                        wrapper_class = oval.EntityStateStringType
                    elif prop_name in ['a_time', 'chg_allow', 'chg_lst', 'chg_req', 'c_time', 'exp_date', 'exp_inact', 'exp_warn', 'group_id', 'instance', \
                       'last_login', 'loginuid', 'mod_time', 'm_time', 'pid', 'port', 'ppid', 'priority', 'ruid', 'session_id', 'size', 'space_left', \
                       'space_used', 'total_space', 'ttl', 'user_id']:
                        wrapper_class = oval.EntityStateIntType
                    elif prop_name in ['configuration_file', 'current_status', 'dependency_check_passed', 'digest_check_passed', 'disabled', 'documentation_file', \
                       'exec_shield', 'gexec', 'ghost_file', 'gread', 'gwrite', 'has_extended_acl', 'is_default', 'is_writable', 'kill', 'license_file', 'oexec', \
                       'oread', 'owrite', 'pending_status', 'readme_file', 'sgid', 'signature_check_passed', 'start', 'sticky', 'suid', 'uexec', 'uread', \
                       'uwrite', 'verification_script_successful', 'wait']:
                        wrapper_class = oval.EntityStateBoolType
                    elif prop_name in ['capabilities_differ', 'device_differs', 'group_differs', 'link_mismatch', 'md5_differs', 'mode_differs', \
                       'mtime_differs', 'ownership_differs', 'size_differs']:
                        wrapper_class = oval.EntityStateRpmVerifyResultType
                    elif prop_name in ['epoch', 'result', 'subexpression', 'text', 'value', 'value_of']:
                        wrapper_class = oval.EntityStateAnySimpleType
                    elif prop_name in ['broadcast_addr', 'inet_addr', 'ip_address', 'netmask', 'only_from']:
                        wrapper_class = oval.EntityStateIPAddressStringType
                    elif prop_name in ['destination', 'gateway']:
                        wrapper_class = oval.EntityStateIPAddressType
                    elif prop_name in ['posix_capability', 'protocol']:
                        wrapper_class = oval.EntityStateCapabilityType
                    elif prop_name in ['encrypt_method']:
                        wrapper_class = oval.EntityStateEncryptMethodType
                    elif prop_name in ['endpoint_type']:
                        wrapper_class = oval.EntityStateEndpointType
                    elif prop_name in ['engine']:
                        wrapper_class = oval.EntityStateEngineType
                    elif prop_name in ['evr']:
                        wrapper_class = oval.EntityStateEVRStringType
                    elif prop_name in ['family']:
                        wrapper_class = oval.EntityStateFamilyType
                    elif prop_name in ['hash_type']:
                        wrapper_class = oval.EntityStateHashTypeType
                    elif prop_name in ['release']:
                        wrapper_class = oval.EntityStateProtocolType
                    elif prop_name in ['var_ref']:
                        wrapper_class = oval.EntityStateRecordType
                    elif prop_name in ['wait_status']:
                        wrapper_class = oval.EntityStateWaitStatusType
                    elif prop_name in ['windows_view']:
                        wrapper_class = oval.EntityStateWindowsViewType
                    #Left Overs
                    else:
                        wrapper_class = oval.EntityObjectStringType
                    
                    # --- Use the existing helper to create and set the property
                    self._set_wrapped_property(new_entity, data, prop_name, wrapper_class)

        elif entity_type_str == 'variable':
            new_entity.set_datatype(data['datatype'])
            
            if isinstance(new_entity, oval.constant_variable) and 'value' in data:
                for val in data['value']:
                    new_entity.add_value(oval.ValueType(valueOf_=val))

            elif isinstance(new_entity, oval.external_variable):
                if 'possible_value' in data:
                    for pv_data in data['possible_value']:
                        pv = oval.PossibleValueType(
                            valueOf_=pv_data.get('value'),
                            hint=pv_data.get('hint')
                        )
                        new_entity.add_possible_value(pv)
                
                if 'possible_restriction' in data:
                    for pr_data in data['possible_restriction']:
                        # Create the main <possible_restriction> container
                        pr = oval.PossibleRestrictionType(
                            hint=pr_data.get('hint'),
                            operator=pr_data.get('operator')
                        )
                        # Loop through its child restrictions and add them
                        for r_data in pr_data.get('restrictions', []):
                            restriction_child = oval.RestrictionType(
                                valueOf_=r_data.get('value'),
                                operation=r_data.get('operation')
                            )
                            pr.add_restriction(restriction_child)
                        new_entity.add_possible_restriction(pr)

            elif isinstance(new_entity, oval.local_variable):
                comp_type = data.get('component_type')
                if comp_type == 'literal':
                    new_entity.set_literal_component(oval.LiteralComponentType(valueOf_=data.get('literal_value')))
                elif comp_type == 'variable':
                    new_entity.set_variable_component(oval.VariableComponentType(var_ref=data.get('var_ref')))
                elif comp_type == 'object':
                   # Build arguments, only including record_field if it has a value
                    comp_kwargs = {
                        'object_ref': data.get('object_ref'),
                        'item_field': data.get('item_field')
                    }
                    if data.get('record_field'):
                        comp_kwargs['record_field'] = data.get('record_field')
                    
                    new_entity.set_object_component(oval.ObjectComponentType(**comp_kwargs))
                elif comp_type == 'function':
                    func_type = data.get('function_type')
                    components_data = data.get('components_data', [])
                    
                    func = None
                    if func_type == 'arithmetic':
                        func = oval.ArithmeticFunctionType(arithmetic_operation=data.get('arithmetic_op'))
                        new_entity.set_arithmetic(func)
                    elif func_type == 'concat':
                        func = oval.ConcatFunctionType()
                        new_entity.set_concat(func)
                    elif func_type == 'escape_regex':
                        func = oval.EscapeRegexFunctionType()
                        new_entity.set_escape_regex(func)
                    elif func_type == 'unique':
                        func = oval.UniqueFunctionType()
                        new_entity.set_unique(func)
                    elif func_type == 'count':
                        func = oval.CountFunctionType()
                        new_entity.set_count(func)
                    elif func_type == 'time_difference':
                        func = oval.TimeDifferenceFunctionType(
                            format_1=data.get('format_1'),
                            format_2=data.get('format_2')
                        )
                        new_entity.set_time_difference(func)
                    elif func_type in ['begin', 'end']:
                        func = oval.BeginFunctionType(character=data.get('character')) if func_type == 'begin' else oval.EndFunctionType(character=data.get('character'))
                        if func_type == 'begin': new_entity.set_begin(func)
                        else: new_entity.set_end(func)                   
                    elif func_type == 'split':
                        func = oval.SplitFunctionType(delimiter=data.get('delimiter'))
                        new_entity.set_split(func)
                    elif func_type == 'regex_capture':
                        func = oval.RegexCaptureFunctionType(pattern=data.get('pattern'))
                        comp_data = data.get('single_component_data')
                        new_entity.set_regex_capture(func)
                    elif func_type == 'glob_to_regex':
                        func = oval.GlobToRegexFunctionType(glob_noescape=data.get('glob_noescape'))
                        new_entity.set_glob_to_regex(func)
                    elif func_type == 'substring':
                        func = oval.SubstringFunctionType(
                            substring_start=data.get('substring_start'),
                            substring_length=data.get('substring_length')
                        )
                        new_entity.set_substring(func)
                        
                    if func:
#                        print(f"comp_data: {components_data}")
                        self._build_function_components(func, components_data, func_type)                    
                    
#        print(f"entity: {new_entity}")
        return new_entity

    def update_entity(self, entity_to_edit, data, entity_type_str):
        """Updates an existing OVAL entity from dialog data."""
        if not data: return
        
#        print(f"data: {data}")
        # --- Set COMMON attributes for all OVAL entities ---
        if 'id' in data: entity_to_edit.set_id(data['id'])
        if 'version' in data: entity_to_edit.set_version(data['version'])
        if 'comment' in data: entity_to_edit.set_comment(data['comment'])

        # --- Set SPECIFIC attributes based on the entity's type ---
        if entity_type_str == 'test':
            if 'check' in data: entity_to_edit.set_check(data['check'])
            if 'check_existence' in data: entity_to_edit.set_check_existence(data['check_existence'])
            if 'object_ref' in data:
                obj_ref = entity_to_edit.get_object() or oval.ObjectRefType()
                obj_ref.set_object_ref(data['object_ref'])
                obj_ref.ns_prefix_ = entity_to_edit.ns_prefix_
                entity_to_edit.set_object(obj_ref)
            if 'state_ref' in data:
                state_ref = (entity_to_edit.get_state() or [oval.StateRefType()])[0]
                state_ref.set_state_ref(data['state_ref'])
                state_ref.ns_prefix_ = entity_to_edit.ns_prefix_
                entity_to_edit.set_state([state_ref])

        elif entity_type_str == 'object':

            # --- FOR BEHAVIORS ---
            if 'behaviors' in data:
                b_data = data['behaviors']
                behaviors_obj = entity_to_edit.get_behaviors()
                
                if isinstance(entity_to_edit, oval.textfilecontent54_object):
                    if b_data and not behaviors_obj: 
                        behaviors_obj = oval.Textfilecontent54Behaviors()
                        behaviors_obj.ns_prefix_ = entity_to_edit.ns_prefix_
                        entity_to_edit.set_behaviors(behaviors_obj)                        
                else:
                    if b_data and not behaviors_obj: 
                        behaviors_obj = oval.FileBehaviors()
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
                        filter_obj = oval.filter()
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
                        if (isinstance(entity_to_edit, oval.sql57_object) or isinstance(entity_to_edit, oval.sql_object)):
                            wrapper_class = oval.EntityObjectStringType
                        elif (isinstance(entity_to_edit, oval.rpmverifyfile_object) or isinstance(entity_to_edit, oval.rpmverifypackage_object)):
                            wrapper_class = oval.EntityObjectAnySimpleType
                    elif prop_name in ['instance', 'pid', 'local_port']:
                        wrapper_class = oval.EntityObjectIntType
                    elif prop_name in ['path', 'filename', 'filepath', 'name', 'connection_string', 'sql', 'xpath', 'pattern', 'domain_name', \
                       'attribute_name', 'key', 'source', 'protocol', 'service_name', 'username', 'command_line', 'runlevel', 'interface_name', \
                       'mount_point', 'arch', 'unit', 'property']:
                         wrapper_class = oval.EntityObjectStringType
                    elif prop_name in ['epoch', 'release']:
                        wrapper_class = oval.EntityObjectAnySimpleType
                    elif prop_name in ['local_address', 'destination']:
                        wrapper_class = oval.EntityObjectIPAddressType
                    #Defined Problem Children
                    elif prop_name in ['hash_type', 'engine']:
                        wrapper_class = oval.EntityObjectStringType
                    #Left Overs
                    else:
                        wrapper_class = oval.EntityObjectStringType
                         
                        
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
                        if (isinstance(entity_to_edit, oval.slackwarepkginfo_state) or isinstance(entity_to_edit, oval.sql57_state)):
                            wrapper_class = oval.EntityStateStringType
                        elif isinstance(entity_to_edit, oval.rpmverifypackage_state) or isinstance(entity_to_edit, oval.rpmverifyfile_state) or\
                           isinstance(entity_to_edit, oval.rpminfo_state) or isinstance(entity_to_edit, oval.dpkginfo_state):
                            wrapper_class = oval.EntityObjectAnySimpleType                
                    elif prop_name in ['type']:
                        if (isinstance(entity_to_edit, oval.selinuxsecuritycontext_state) or isinstance(entity_to_edit, oval.file_state)):
                            wrapper_class = oval.EntityStateStringType
                        elif isinstance(entity_to_edit, oval.interface_state):
                            wrapper_class = oval.EntityStateInterfaceType
                        elif isinstance(entity_to_edit, oval.gconf_state):
                            wrapper_class = oval.EntityStateGconfTypeType
                        elif isinstance(entity_to_edit, oval.xinetd_state):
                            wrapper_class = oval.EntityStateXinetdTypeStatusType
                    elif prop_name in ['flags']:
                        if isinstance(entity_to_edit, oval.xinetd_state):
                            wrapper_class = oval.EntityStateStringType
                        elif isinstance(entity_to_edit, oval.routingtable_state):
                            wrapper_class = oval.EntityStateRoutingTableFlagsType
                    elif prop_name in ['arch', 'architecture', 'attribute_name', 'canonical_path', 'command_line', 'connection_string', 'dependency', \
                       'device', 'domain_name', 'exec_as_user', 'exec_time', 'extended_name', 'filename', 'filepath', 'flag', 'fs_type', 'gcos', \
                       'hardware_addr', 'hash', 'high_category', 'high_sensitivity', 'home_dir', 'hw_address', 'interface_name', 'key', 'login_shell', \
                       'low_category', 'low_sensitivity', 'machine_class', 'mod_user', 'mount_options', 'mount_point', 'name', 'no_access', 'node_name', \
                       'os_name', 'os_release', 'os_version', 'password', 'path', 'pattern', 'processor_type', 'program_name', 'property', 'protocol', \
                       'rawhigh_category', 'rawhigh_sensitivity', 'rawlow_category', 'rawlow_sensitivity', 'revision', 'role', 'runlevel', 'scheduling_class', \
                       'selinux_domain_label', 'server', 'server_arguments', 'server_program', 'service_name', 'signature_keyid', 'socket_type', 'source', \
                       'sql', 'start_time', 'tty', 'unit', 'user', 'username', 'uuid', 'xpath']:
                        wrapper_class = oval.EntityStateStringType
                    elif prop_name in ['a_time', 'chg_allow', 'chg_lst', 'chg_req', 'c_time', 'exp_date', 'exp_inact', 'exp_warn', 'group_id', 'instance', \
                       'last_login', 'loginuid', 'mod_time', 'm_time', 'pid', 'port', 'ppid', 'priority', 'ruid', 'session_id', 'size', 'space_left', \
                       'space_used', 'total_space', 'ttl', 'user_id']:
                        wrapper_class = oval.EntityStateIntType
                    elif prop_name in ['configuration_file', 'current_status', 'dependency_check_passed', 'digest_check_passed', 'disabled', 'documentation_file', \
                       'exec_shield', 'gexec', 'ghost_file', 'gread', 'gwrite', 'has_extended_acl', 'is_default', 'is_writable', 'kill', 'license_file', 'oexec', \
                       'oread', 'owrite', 'pending_status', 'readme_file', 'sgid', 'signature_check_passed', 'start', 'sticky', 'suid', 'uexec', 'uread', \
                       'uwrite', 'verification_script_successful', 'wait']:
                        wrapper_class = oval.EntityStateBoolType
                    elif prop_name in ['capabilities_differ', 'device_differs', 'group_differs', 'link_mismatch', 'md5_differs', 'mode_differs', \
                       'mtime_differs', 'ownership_differs', 'size_differs']:
                        wrapper_class = oval.EntityStateRpmVerifyResultType
                    elif prop_name in ['epoch', 'result', 'subexpression', 'text', 'value', 'value_of']:
                        wrapper_class = oval.EntityStateAnySimpleType
                    elif prop_name in ['broadcast_addr', 'inet_addr', 'ip_address', 'netmask', 'only_from']:
                        wrapper_class = oval.EntityStateIPAddressStringType
                    elif prop_name in ['destination', 'gateway']:
                        wrapper_class = oval.EntityStateIPAddressType
                    elif prop_name in ['posix_capability', 'protocol']:
                        wrapper_class = oval.EntityStateCapabilityType
                    elif prop_name in ['encrypt_method']:
                        wrapper_class = oval.EntityStateEncryptMethodType
                    elif prop_name in ['endpoint_type']:
                        wrapper_class = oval.EntityStateEndpointType
                    elif prop_name in ['engine']:
                        wrapper_class = oval.EntityStateEngineType
                    elif prop_name in ['evr']:
                        wrapper_class = oval.EntityStateEVRStringType
                    elif prop_name in ['family']:
                        wrapper_class = oval.EntityStateFamilyType
                    elif prop_name in ['hash_type']:
                        wrapper_class = oval.EntityStateHashTypeType
                    elif prop_name in ['release']:
                        wrapper_class = oval.EntityStateProtocolType
                    elif prop_name in ['var_ref']:
                        wrapper_class = oval.EntityStateRecordType
                    elif prop_name in ['wait_status']:
                        wrapper_class = oval.EntityStateWaitStatusType
                    elif prop_name in ['windows_view']:
                        wrapper_class = oval.EntityStateWindowsViewType
                    #Left Overs
                    else:
                        wrapper_class = oval.EntityObjectStringType
                         
                    self._update_wrapped_entity(
                        entity_to_edit,
                        prop_data,
                        getattr(entity_to_edit, getter_name),
                        getattr(entity_to_edit, setter_name),
                        wrapper_class
                    )

        elif entity_type_str == 'variable':
            entity_to_edit.set_datatype(data['datatype'])
            
            if isinstance(entity_to_edit, oval.constant_variable) and 'value' in data:
                entity_to_edit.set_value([])
                for val in data['value']:
                    entity_to_edit.add_value(oval.ValueType(valueOf_=val))

            elif isinstance(entity_to_edit, oval.external_variable):
                # Update possible values
                entity_to_edit.set_possible_value([])
                if 'possible_value' in data:
                    for pv_data in data['possible_value']:
                        pv = oval.PossibleValueType(
                            valueOf_=pv_data.get('value'),
                            hint=pv_data.get('hint')
                        )
                        entity_to_edit.add_possible_value(pv)
                
                # Update possible restrictions
                entity_to_edit.set_possible_restriction([])
                if 'possible_restriction' in data:
                    for pr_data in data['possible_restriction']:
                        pr = oval.PossibleRestrictionType(
                            hint=pr_data.get('hint'),
                            operator=pr_data.get('operator')
                        )
                        for r_data in pr_data.get('restrictions', []):
                            restriction_child = oval.RestrictionType(
                                valueOf_=r_data.get('value'),
                                operation=r_data.get('operation')
                            )
                            pr.add_restriction(restriction_child)
                        entity_to_edit.add_possible_restriction(pr)

            elif isinstance(entity_to_edit, oval.local_variable):
                # Clear all possible components first
                entity_to_edit.set_literal_component(None)
                entity_to_edit.set_variable_component(None)
                entity_to_edit.set_object_component(None)
                
                comp_type = data.get('component_type')
                if comp_type == 'literal':
                    entity_to_edit.set_literal_component(oval.LiteralComponentType(valueOf_=data.get('literal_value')))
                elif comp_type == 'variable':
                    entity_to_edit.set_variable_component(oval.VariableComponentType(var_ref=data.get('var_ref')))
                elif comp_type == 'object':
                    # Build arguments, only including record_field if it has a value
                    comp_kwargs = {
                        'object_ref': data.get('object_ref'),
                        'item_field': data.get('item_field')
                    }
                    if data.get('record_field'):
                        comp_kwargs['record_field'] = data.get('record_field')
                    
                    entity_to_edit.set_object_component(oval.ObjectComponentType(**comp_kwargs))
                elif comp_type == 'function':
                    func_type = data.get('function_type')
                    components_data = data.get('components_data', [])
                     
                    if func_type == 'arithmetic':
                        func = oval.ArithmeticFunctionType(arithmetic_operation=data.get('arithmetic_op'))
                        entity_to_edit.set_arithmetic(func)
                    elif func_type == 'concat':
                        func = oval.ConcatFunctionType()
                        entity_to_edit.set_concat(func)
                    elif func_type == 'escape_regex':
                        func = oval.EscapeRegexFunctionType()
                        entity_to_edit.set_escape_regex(func)
                    elif func_type == 'unique':
                        func = oval.UniqueFunctionType()
                        entity_to_edit.set_unique(func)
                    elif func_type == 'count':
                        func = oval.CountFunctionType()
                        entity_to_edit.set_count(func)
                    elif func_type == 'time_difference':
                        func = oval.TimeDifferenceFunctionType(
                            format_1=data.get('format_1'),
                            format_2=data.get('format_2')
                        )
                        entity_to_edit.set_time_difference(func)                    
                    elif func_type in ['begin', 'end']:
                        func = oval.BeginFunctionType(character=data.get('character')) if func_type == 'begin' else oval.EndFunctionType(character=data.get('character'))

                        if func_type == 'begin': entity_to_edit.set_begin(func)
                        else: entity_to_edit.set_end(func)                        

                    elif func_type == 'split':
                        func = oval.SplitFunctionType(delimiter=data.get('delimiter'))
                        entity_to_edit.set_split(func)
                    elif func_type == 'regex_capture':
                        func = oval.RegexCaptureFunctionType(pattern=data.get('pattern'))
                        entity_to_edit.set_regex_capture(func)
                    elif func_type == 'glob_to_regex':
                        func = oval.GlobToRegexFunctionType(glob_noescape=data.get('glob_noescape'))
                        entity_to_edit.set_glob_to_regex(func)

                    elif func_type == 'substring':
                        func = oval.SubstringFunctionType(
                            substring_start=data.get('substring_start'),
                            substring_length=data.get('substring_length')
                        )
                        entity_to_edit.set_substring(func)
                        
                    if func:
                        self._build_function_components(func, components_data, func_type)
#        print(f"entity: {entity_to_edit}")    

