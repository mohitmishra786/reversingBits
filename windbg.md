# WinDbg Cheatsheet

## Basic Commands
### Starting & Attaching
```
.attach <pid>     # Attach to process
.create <file>    # Start new process
.restart          # Restart debugging
.detach           # Detach from process
```

### Navigation
| Command | Description |
|---------|-------------|
| g | Go/Continue |
| p | Step Over |
| t | Step Into |
| gu | Go Up (execute until return) |
| u [addr] | Unassemble |
| ln [addr] | List nearest symbols |

## Memory Commands
### Display Memory
```
d[a|b|c|d|p|u|w|W] [address]   # Display memory in different formats
    da - ASCII
    db - Bytes
    dc - DWORDs
    dd - Double-words
    dp - Pointers
    du - Unicode
    dw - Words
```

### Edit Memory
```
e[b|d|p|w] address [values]     # Edit memory
    eb - Edit bytes
    ed - Edit DWORDs
    ep - Edit pointers
    ew - Edit words
```

## Breakpoints
### Software Breakpoints
```
bp [address] "command"          # Set breakpoint
bl                             # List breakpoints
bc [breakpoint-id]             # Clear breakpoint
bd [breakpoint-id]             # Disable breakpoint
be [breakpoint-id]             # Enable breakpoint
```

### Hardware Breakpoints
```
ba [r|w|e] [size] [address]    # Set hardware breakpoint
    r - Break on read
    w - Break on write
    e - Break on execute
```

## Symbols & Modules
### Symbol Management
```
.sympath [path]                # Set symbol path
.reload                        # Reload symbols
x [module]!*                   # List symbols
!sym noisy                     # Enable verbose symbol loading
```

### Module Commands
```
lm                            # List modules
.chain                        # Show debugger extensions
.load [dll]                   # Load extension
.unload [dll]                 # Unload extension
```

## Stack Operations
### Stack Commands
```
k[n|L|P|B|V]                  # Display stack trace
    n - Show frame numbers
    L - Show source lines
    P - Show parameters
    B - Show first three parameters
    V - Show frame pointers
```

### Stack Manipulation
```
dv                            # Display local variables
dt [type]                     # Display type information
?? [expression]               # Evaluate expression
```

## Advanced Features
### Scripting
```javascript
// JavaScript example
function analyzeHeap() {
    const heap = host.namespace.Debugger.Utility.Analysis.Heap;
    for (let entry of heap) {
        host.diagnostics.debugLog(`Size: ${entry.size}\n`);
    }
}
```

### Time Travel Debugging
```
!tt                           # Start time travel session
!tt.time                      # Show current position
!tt.forward                   # Step forward in time
!tt.backward                  # Step backward in time
```

## Extensions
### Common Extensions
```
!analyze -v                   # Detailed crash analysis
!handle                       # Display handle information
!process                      # Show process information
!threads                      # Display thread information
```

### SOS Commands (for .NET)
```
!clrstack                     # Display managed call stack
!dumpheap                     # Display heap information
!do [address]                 # Display object information
!dumpdomain                   # Display AppDomain information
```

## Kernel Debugging
### Connection Setup
```
bcdedit /debug on            # Enable kernel debugging
bcdedit /dbgsettings serial  # Configure serial debugging
```

### Kernel Commands
```
!process 0 0                 # List all processes
!thread                      # Display current thread
!devstack                    # Display device stack
!drvobj                     # Display driver object
```

## Tips & Advanced Usage
### Performance Analysis
```
!analyze -v                  # Crash analysis
!runaway                     # Thread time usage
!locks                       # Lock analysis
!htrace                     # Handle trace
```

### Memory Analysis
```
!address -summary           # Memory usage summary
!vm                        # Virtual memory info
!pool                      # Pool memory analysis
!heap -s                   # Heap summary
```

## Custom Commands
### Command Aliases
```
as /mu alias command        # Create alias
al                         # List aliases
ad alias                   # Delete alias
```

### Command Log
```
.logopen filename          # Start logging
.logclose                  # Stop logging
.echo message              # Write to log
```

## Debugging Techniques
### Common Workflows
1. Crash Analysis
   ```
   !analyze -v
   kb
   !thread
   !locks
   ```

2. Memory Leaks
   ```
   !heap -s
   !heap -stat
   !heap -flt s size
   ```

3. Handle Leaks
   ```
   !handle
   !htrace -enable
   !htrace -snapshot
   ```

### Best Practices
1. Symbol Setup
   ```
   .symfix
   .sympath+ [local path]
   .reload /f
   ```

2. Extension Management
   ```
   .chain                  # Check loaded extensions
   .load [extension]       # Load needed extensions
   .unload [extension]     # Unload unnecessary extensions
   ```

3. Data Collection
   ```
   .dump /ma file.dmp     # Full memory dump
   .logopen log.txt       # Start logging
   !analyze -v            # Detailed analysis
   ```
