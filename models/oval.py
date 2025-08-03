# models/oval.py
import inspect

# Import all specific implementations from the component models
# This brings in FileTest, FileObject, Textfilecontent54Object, etc.
from .oval_independent_models import *
from .oval_unix_models import *
from .oval_linux_models import *
from .oval_solaris_models import *

# Import all core structures (DefinitionType, TestsType, etc.)
from .oval_core_models import *


def build_schema_location_string():
    """
    Dynamically builds the full xsi:schemaLocation string for OVAL
    by inspecting the component models.
    """
    from . import oval_independent_models, oval_linux_models, oval_unix_models, oval_solaris_models
    
    # Start with the mandatory base schemas
    locations = [
        'http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd '
        'http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd'
    ]
    
    component_modules = [
        oval_independent_models,
        oval_linux_models,
        oval_unix_models,
        oval_solaris_models
    ]
    
    for module in component_modules:
        if hasattr(module, 'SCHEMA_LOCATION_PAIR'):
            locations.append(getattr(module, 'SCHEMA_LOCATION_PAIR'))
            
    return ' '.join(locations)

# Create the map once when the module is imported.
OVAL_SCHEMA_LOCATION = build_schema_location_string()

# This is the crucial final step. It tells the generic base classes (like TestType)
# about the specific implementations (like FileTest), allowing them to work together.
DefinitionType.subclass = DefinitionType
ObjectType.subclass = ObjectType
StateType.subclass = StateType
TestType.subclass = TestType
VariableType.subclass = VariableType
