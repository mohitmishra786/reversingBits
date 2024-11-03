# Hopper Disassembler Cheatsheet

## Basic Operations
| Command | Shortcut | Description |
|---------|----------|-------------|
| Open File | Cmd/Ctrl + O | Open a new binary file |
| Save Project | Cmd/Ctrl + S | Save current project |
| Close | Cmd/Ctrl + W | Close current file |
| Search | Cmd/Ctrl + F | Search in current view |
| Go to Address | Cmd/Ctrl + G | Jump to specific address |
| Navigate Back | Cmd/Ctrl + [ | Go to previous location |
| Navigate Forward | Cmd/Ctrl + ] | Go to next location |

## Analysis Features
| Feature | Shortcut | Description |
|---------|----------|-------------|
| Start Analysis | A | Begin automatic analysis |
| Create Procedure | P | Create new procedure |
| Create Segment | S | Create new segment |
| Find References | X | Find cross-references |
| Toggle Graph View | Space | Switch between linear/graph view |
| Show Decompiler | Tab | Switch to decompiled view |

## Navigation
### Assembly View
| Command | Shortcut | Purpose |
|---------|----------|----------|
| Next Procedure | N | Jump to next procedure |
| Previous Procedure | Shift + N | Jump to previous procedure |
| Follow Jump | Enter | Follow branch/jump instruction |
| Mark as Code | C | Mark selection as code |
| Mark as Data | D | Mark selection as data |

### Decompiler View
| Command | Shortcut | Purpose |
|---------|----------|----------|
| Rename Variable | N | Rename selected variable |
| Change Type | Y | Change variable type |
| Toggle Assembly | Tab | Switch to assembly view |
| Optimize | O | Apply decompiler optimizations |

## Patching
| Command | Shortcut | Description |
|---------|----------|-------------|
| Modify Instruction | M | Modify selected instruction |
| NOP Instruction | Delete | Replace with NOP |
| Assemble | A | Enter assembly code |
| Write File | Cmd/Ctrl + E | Export modified binary |

## Scripting
### Python API
```python
# Basic script structure
import hopperv4

def main(document):
    segment = document.getCurrentSegment()
    procedure = document.getCurrentProcedure()
    address = document.getCurrentAddress()
    
    # Common operations
    document.log("Message")
    document.showMessage("Alert")
    document.markAsCode(address)
```

## Plugin Development
### Template
```python
from hopperv4 import HPHopperTool

class MyPlugin(HPHopperTool):
    def init(self):
        self.name = "My Plugin"
        self.help = "Plugin description"
        
    def run(self, document):
        # Plugin code here
        pass
```

## Debugging Features
| Feature | Description |
|---------|-------------|
| Set Breakpoint | Toggle breakpoint at address |
| Step Over | Execute next instruction |
| Step Into | Enter called function |
| Run To Cursor | Execute until cursor position |
| Show Registers | Display CPU registers |

## File Formats
- Mach-O (macOS/iOS binaries)
- ELF (Linux/Unix binaries)
- PE (Windows binaries)
- Raw binary files
- Intel HEX format
- Universal binaries

## Tips & Tricks
1. Use Type Libraries
   - Import standard C/C++ types
   - Create custom type libraries
   - Apply types to improve decompilation

2. Cross References
   - Double-click variables for references
   - Use X key for comprehensive xref view
   - Filter references by type

3. Annotations
   - Add comments with semicolon (;)
   - Create named labels
   - Color code segments

4. Binary Diffing
   - Compare two binaries
   - Highlight differences
   - Sync navigation between files
