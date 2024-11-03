# Binary Ninja Cheatsheet

## Installation & Setup
```bash
# License activation
bn-license -i license.dat

# Command line interface
binaryninja-cli --help
binaryninja-cli --version
```

## Interface Navigation
| Shortcut | Action | Description |
|----------|--------|-------------|
| G | Go to address | Jump to specific location |
| Esc | Back | Return to previous view |
| Tab | Toggle views | Switch between views |
| Space | Graph/Linear | Toggle graph/linear view |
| P | Functions | List all functions |
| / | Search | Global search |
| ; | Comment | Add comment at current address |

## Analysis Controls
| Command | Purpose |
|---------|----------|
| Analysis | Start/stop analysis |
| Update Analysis | Refresh analysis |
| Run Plugin | Execute specific plugin |
| Load Symbols | Import symbol files |

## Views
### Types of Views
1. Linear View
   - Traditional disassembly view
   - Sequential instruction display

2. Graph View
   - Control flow visualization
   - Basic block relationships

3. HLIL View
   - High-level IL representation
   - C-like decompilation

4. LLIL View
   - Low-level IL representation
   - Architecture-independent view

## Scripting (Python API)
```python
# Basic script structure
from binaryninja import *

def analyze_binary(bv):
    # Get current function
    current_function = bv.entry_function
    
    # Iterate through functions
    for function in bv.functions:
        # Analysis code here
        pass

# Load binary
bv = BinaryViewType.get_view_of_file("binary")
analyze_binary(bv)
```

## Binary Ninja IL (BNIL)
### LLIL Operations
```python
# Access LLIL
function.llil

# Common operations
LLIL_SET_REG
LLIL_LOAD
LLIL_STORE
LLIL_CALL
LLIL_RET
```

### HLIL Operations
```python
# Access HLIL
function.hlil

# Common operations
HLIL_VAR_DECLARE
HLIL_VAR
HLIL_CALL
HLIL_WHILE
HLIL_IF
```

## Type System
### Custom Types
```python
# Create structure
struct = Structure()
struct.append(Type.int(), "field1")
struct.append(Type.pointer(Type.int()), "field2")

# Apply type
function.set_user_type(struct)
```

## Plugins
### Plugin Template
```python
from binaryninja import *

class ExamplePlugin(PluginCommand):
    def __init__(self):
        super(ExamplePlugin, self).__init__(
            "Example Plugin",
            "Plugin description"
        )
    
    def execute(self, bv):
        # Plugin code here
        pass
```

## Binary Patching
| Operation | Command | Description |
|-----------|---------|-------------|
| Modify Bytes | Write to offset | Change binary content |
| NOP Out | Convert to NOPs | Replace with NO-OP instructions |
| Add Section | Create section | Add new binary section |
| Save | Write modifications | Save changes to file |

## Advanced Features
### Data Flow Analysis
```python
# Get data flow graph
dfg = function.data_flow_graph

# Analyze variables
for var in function.vars:
    # Variable analysis
    uses = var.uses
    definitions = var.definitions
```

### Cross References
| Command | Purpose |
|---------|----------|
| Find References | Locate all xrefs |
| Code References | Find code usage |
| Data References | Find data usage |

## Debugging Integration
| Feature | Description |
|---------|-------------|
| Set Breakpoint | Create execution break |
| Step | Single instruction step |
| Run | Continue execution |
| Registers | View/modify registers |

## Common Tasks
### Function Analysis
```python
# Get function info
start = function.start
end = function.end
size = function.total_bytes
name = function.name

# Basic blocks
for block in function.basic_blocks:
    # Block analysis
    pass
```

### Pattern Matching
```python
# Search for pattern
pattern = "48 89 5C 24 ??"
results = bv.find_pattern(pattern)

# Search in function
function.find_pattern(pattern)
```

## Tips & Best Practices
1. Use Type Libraries
   - Import standard headers
   - Create custom types
   - Apply types for better analysis

2. Leverage IL
   - Use HLIL for logic understanding
   - LLIL for detailed analysis
   - MLIL for optimization

3. Custom Views
   - Create task-specific views
   - Customize existing views
   - Use split view for comparison
