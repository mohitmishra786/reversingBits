# Rizin Cheatsheet

## Installation Guide

### From Package Manager
```bash
# Debian/Ubuntu
sudo apt install rizin

# Fedora
sudo dnf install rizin

# macOS
brew install rizin
```

### From Source
```bash
git clone https://github.com/rizinorg/rizin
cd rizin
meson build
ninja -C build
sudo ninja -C build install
```

## Basic Commands

### Analysis Commands
| Command | Description | Example |
|---------|------------|----------|
| `aa` | Analyze all | `rizin -A binary` |
| `aaa` | Analyze more aggressively | `[0x00000000]> aaa` |
| `aaaa` | Analyze even more | `[0x00000000]> aaaa` |
| `af` | Analyze function | `[0x00000000]> af` |
| `afl` | List functions | `[0x00000000]> afl` |
| `afi` | Function information | `[0x00000000]> afi` |

### Navigation
| Command | Description | Example |
|---------|------------|----------|
| `s` | Seek to address | `s main` |
| `sf` | Seek to function | `sf sym.main` |
| `ss` | Seek to string | `ss /bin/sh` |
| `sl` | Seek history | `sl` |
| `u` | Undo seek | `u` |

### Display/Print
| Command | Description | Example |
|---------|------------|----------|
| `pd` | Print disassembly | `pd 20` |
| `pxr` | Print reference | `pxr 32` |
| `ps` | Print string | `ps @ str.hello` |
| `pf` | Print formatted | `pf x` |
| `px` | Print hexdump | `px 64` |

### Visual Mode Commands
```text
V      : Enter visual mode
VV     : Enter graph mode
p/P    : Rotate print modes
hjkl   : Navigation keys
:      : Enter command
q      : Quit visual mode
```

### Debug Commands
| Command | Description | Example |
|---------|------------|----------|
| `db` | Set breakpoint | `db main` |
| `dc` | Continue execution | `dc` |
| `ds` | Step into | `ds` |
| `dso` | Step over | `dso` |
| `dbt` | Backtrace | `dbt` |

### Binary Information
| Command | Description | Example |
|---------|------------|----------|
| `i` | File info | `i` |
| `ie` | Entrypoints | `ie` |
| `iE` | Exports | `iE` |
| `ii` | Imports | `ii` |
| `iS` | Sections | `iS` |

## Advanced Features

### Project Management
```bash
# Save project
Ps project_name

# Load project
Po project_name

# Delete project
Pd project_name
```

### Scripting
```bash
# Run script
. script.rz

# Run command
rizin -qc 'px 32' binary

# Generate r2pipe script
rizin -qc '?' binary > script.py
```

### Graph Generation
```bash
# Generate function graph
agf

# Generate full program graph
ag

# Save graph
agf > graph.dot
```

## Common Workflows

### Binary Analysis
```bash
# Basic analysis workflow
rizin binary
[0x00000000]> aaa
[0x00000000]> afl
[0x00000000]> s main
[0x00000000]> VV
```

### Debugging
```bash
# Debug workflow
rizin -d binary
[0x00000000]> db main
[0x00000000]> dc
[0x00000000]> ds
[0x00000000]> px @ rsp
```

### String Analysis
```bash
# Find and analyze strings
iz      # List strings
izz     # Search for strings
axt @   # Cross references to string
```

## Configuration

### rizinrc
```bash
# ~/.rizinrc
e asm.syntax = intel
e asm.bytes = false
e asm.comments = false
```

### Environment Variables
```bash
# Set rizin home directory
export RIZIN_HOME="/path/to/rizin"

# Set temporary directory
export RIZIN_TMP="/tmp"
```

## Best Practices
1. Always run initial analysis (`aaa`)
2. Use projects for large binaries
3. Save commands in scripts
4. Use visual mode for navigation
5. Utilize cross-references
6. Keep configurations in rizinrc
7. Use appropriate analysis depth

## Tips and Tricks
1. Use `?` for help on any command
2. Use tab completion
3. Use `V!` for panel mode
4. Use `#!pipe` for shell commands
5. Use `@` for temporary seeks
6. Use `@@` for iteration
7. Use `~` for grep-like filtering

## Common Flags
```bash
-A      # Analysis at start
-d      # Debug mode
-w      # Open in write mode
-c cmd  # Run command
-i file # Run script file
-q      # Quiet mode
-z      # Load strings
```

## Error Handling
```bash
# Common errors and solutions
? ERROR: Cannot find function
Solution: Run analysis first (aa)

? ERROR: Cannot open file
Solution: Check permissions

? ERROR: Cannot allocate memory
Solution: Increase ulimit
```
