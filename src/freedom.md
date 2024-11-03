# FrEEdom Binary Analysis Framework Cheatsheet

## Installation Guide

### Prerequisites
```bash
# Install required dependencies
sudo apt-get update
sudo apt-get install build-essential git cmake python3-dev
```

### Building from Source
```bash
git clone https://github.com/FREEDOM/freedom.git
cd freedom
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

## Basic Commands

### Binary Loading
| Command | Usage | Purpose |
|---------|--------|---------|
| `freedom load` | `freedom load <binary>` | Load binary for analysis |
| `freedom info` | `freedom info <binary>` | Display binary information |
| `freedom sections` | `freedom sections <binary>` | List binary sections |
| `freedom symbols` | `freedom symbols <binary>` | Display symbol table |

### Analysis Commands
| Command | Usage | Purpose |
|---------|--------|---------|
| `freedom analyze` | `freedom analyze <binary>` | Perform static analysis |
| `freedom cfg` | `freedom cfg <binary>` | Generate control flow graph |
| `freedom decompile` | `freedom decompile <binary>` | Decompile binary to C-like code |
| `freedom strings` | `freedom strings <binary>` | Extract strings |

### Function Analysis
| Command | Usage | Purpose |
|---------|--------|---------|
| `freedom functions` | `freedom functions <binary>` | List all functions |
| `freedom xrefs` | `freedom xrefs <address>` | Find cross-references |
| `freedom calls` | `freedom calls <function>` | Show function call graph |
| `freedom stack` | `freedom stack <function>` | Analyze stack frame |

### Debugging Features
| Command | Usage | Purpose |
|---------|--------|---------|
| `freedom debug` | `freedom debug <binary>` | Start debugger |
| `freedom break` | `freedom break <address>` | Set breakpoint |
| `freedom step` | `freedom step` | Single step execution |
| `freedom continue` | `freedom continue` | Continue execution |

### Export Options
| Command | Usage | Purpose |
|---------|--------|---------|
| `freedom export` | `freedom export <format>` | Export analysis results |
| `freedom graph` | `freedom graph <function>` | Export function graph |
| `freedom report` | `freedom report <binary>` | Generate analysis report |

## Plugin System

### Plugin Management
```bash
# List available plugins
freedom plugin list

# Install plugin
freedom plugin install <plugin-name>

# Remove plugin
freedom plugin remove <plugin-name>

# Update plugins
freedom plugin update
```

### Common Plugins
| Plugin | Purpose |
|--------|---------|
| `symex` | Symbolic execution |
| `taint` | Taint analysis |
| `patch` | Binary patching |
| `trace` | Execution tracing |

## Configuration

### Config File Location
```bash
~/.freedom/config.yml
```

### Common Settings
```yaml
analysis:
  depth: 5
  timeout: 300
  threads: 4

output:
  format: json
  verbose: true
  log_level: info

plugins:
  enabled:
    - symex
    - taint
```

## Script Interface

### Python API Example
```python
from freedom import Binary

# Load binary
binary = Binary("./target")

# Analyze functions
funcs = binary.get_functions()
for func in funcs:
    print(f"Function: {func.name} at {hex(func.address)}")
    
# Generate CFG
cfg = binary.generate_cfg()
cfg.export("cfg.dot")
```

## Common Workflows

### Basic Binary Analysis
```bash
# Load and analyze binary
freedom load target
freedom analyze target

# Generate control flow graph
freedom cfg target > cfg.dot

# Export analysis results
freedom export --format json target > analysis.json
```

### Vulnerability Analysis
```bash
# Check security features
freedom checksec target

# Perform taint analysis
freedom taint target

# Generate vulnerability report
freedom vuln-scan target > vulns.txt
```
