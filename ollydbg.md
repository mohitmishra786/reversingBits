# OllyDbg Cheatsheet

## Hotkeys & Navigation
### Basic Controls
| Shortcut | Action | Description |
|----------|--------|-------------|
| F2 | Toggle Breakpoint | Set/remove breakpoint |
| F7 | Step Into | Step into function call |
| F8 | Step Over | Execute function without stepping in |
| F9 | Run/Continue | Start/continue execution |
| F4 | Run to Selection | Execute until selected instruction |
| Ctrl+F2 | Restart | Restart debugging session |
| Alt+F9 | Execute till Return | Run until function return |
| Ctrl+F9 | Execute till User Code | Skip system code |

### Navigation
| Shortcut | Action |
|----------|--------|
| Ctrl+G | Go to Address |
| Ctrl+L | Go to Previous Position |
| Ctrl+N | Go to Next Position |
| Ctrl+F | Find Pattern |
| Ctrl+B | Binary Search |
| Alt+B | Binary Copy |

## Views & Windows
### CPU Window (Alt+C)
```
- Disassembly View
- Registers View
- Stack View
- Dump View
```

### Memory Map (Alt+M)
```
- View memory regions
- Set access rights
- View allocation info
```

### Log Window (Alt+L)
```
- Debug output
- Error messages
- Custom logging
```

## Debugging Commands
### Breakpoints
| Command | Description |
|---------|-------------|
| Ctrl+E | Edit Breakpoint |
| Shift+F4 | Set Conditional Break |
| Ctrl+Alt+B | Breakpoint Window |
| Shift+F2 | Toggle Bookmark |

### Tracing
```
Alt+F7    - Trace Into
Alt+F8    - Trace Over
Ctrl+F7   - Trace Condition
Ctrl+F11  - Trace Back
```

## Memory Operations
### Memory Editing
| Command | Action |
|---------|--------|
| Ctrl+E | Edit Data |
| Ctrl+M | Memory Map |
| Ctrl+B | Binary Fill |
| Right-Click -> Edit | Modify Memory |

### Memory Search
```
- Alt+S: String References
- Alt+E: Executable Modules
- Alt+I: Referenced Text
```

## Patching
### Code Patching
```assembly
; Replace instruction
Right-Click -> Assemble
; Fill with NOPs
Right-Click -> Binary -> Fill with NOPs
; Save patched file
Right-Click -> Copy to executable
```

### Binary Patching
```
1. Select bytes in dump
2. Right-click -> Binary -> Edit
3. Enter new values
4. Save to file
```

## Analysis Features
### Code Analysis
```
- Auto Comments (Ctrl+Alt+C)
- Label Management
- Function Analysis
- Cross-References
```

### Data Analysis
```
- String References
- Called DLLs/APIs
- Import/Export Tables
- Entry Points
```

## Plugins Support
### Common Plugins
```
- OllyDump: Process Dumper
- Phantom: Anti-Anti-Debug
- Hide Debugger: Anti-Detection
- Command Bar: Enhanced Navigation
```

### Plugin Development
```cpp
// Basic plugin structure
extern "C" __declspec(dllexport) 
int __cdecl ODBG_Plugindata(char *shortname) {
    strcpy(shortname,"Plugin Name");
    return PLUGIN_VERSION;
}
```

## Advanced Features
### Conditional Breakpoints
```
- Right-click breakpoint
- Set condition
- Use expressions
Example: EAX == 0x1234
```

### Expression Evaluation
```
- Mathematical operations
- Register values
- Memory references
Example: [ESP+4]+8
```

## Common Tasks
### Anti-Debugging Bypass
```
1. Find anti-debug checks
2. Set breakpoints
3. Patch or skip checks
4. Continue execution
```

### API Monitoring
```
1. View Imports (Alt+E)
2. Set API breakpoints
3. Monitor parameters
4. Log calls
```

## Tips & Tricks
### Performance
1. Selective Debugging
   ```
   - Use Run till User Code
   - Skip System DLLs
   - Use Memory Breakpoints
   ```

2. Custom Commands
   ```
   - Create command bars
   - Use keyboard shortcuts
   - Set up plugins
   ```

3. Anti-Anti-Debug
   ```
   - Hide debugger presence
   - Bypass integrity checks
   - Handle exceptions
   ```

### Best Practices
1. Before Debugging
   ```
   - Back up target file
   - Check for packers
   - Set up symbols
   ```

2. During Analysis
   ```
   - Use bookmarks
   - Document findings
   - Save important states
   ```

3. After Patching
   ```
   - Verify changes
   - Test functionality
   - Save modifications
   ```
