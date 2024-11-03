# Unicorn Engine Cheatsheet

## Installation Guide

### Python Bindings
```bash
# Via pip
pip install unicorn

# From source
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn && ./make.sh
cd bindings/python && python setup.py install
```

### C/C++ Installation
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install unicorn-dev

# macOS
brew install unicorn

# Windows (MSYS2)
pacman -S mingw-w64-x86_64-unicorn
```

## Basic Operations

### Initialization
```python
from unicorn import *
from unicorn.x86_const import *

# Initialize emulator
mu = Uc(UC_ARCH_X86, UC_MODE_32)  # 32-bit x86
mu = Uc(UC_ARCH_X86, UC_MODE_64)  # 64-bit x86
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)  # ARM
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)  # ARM64
```

### Memory Operations
| Operation | Example | Purpose |
|-----------|---------|---------|
| `mem_map()` | `mu.mem_map(0x1000, 0x1000)` | Map memory region |
| `mem_write()` | `mu.mem_write(addr, code)` | Write to memory |
| `mem_read()` | `mu.mem_read(addr, size)` | Read from memory |
| `mem_unmap()` | `mu.mem_unmap(addr, size)` | Unmap memory |
| `mem_protect()` | `mu.mem_protect(addr, size, prot)` | Set protection |

### Execution Control
| Command | Usage | Purpose |
|---------|-------|---------|
| `emu_start()` | `mu.emu_start(start, end)` | Start emulation |
| `emu_stop()` | `mu.emu_stop()` | Stop emulation |
| `reg_write()` | `mu.reg_write(reg, val)` | Write register |
| `reg_read()` | `mu.reg_read(reg)` | Read register |

## Hooks and Callbacks

### Hook Types
| Hook | Purpose |
|------|---------|
| `UC_HOOK_CODE` | Instructions |
| `UC_HOOK_BLOCK` | Basic blocks |
| `UC_HOOK_MEM_READ` | Memory reads |
| `UC_HOOK_MEM_WRITE` | Memory writes |
| `UC_HOOK_MEM_FETCH` | Memory fetches |
| `UC_HOOK_INTR` | Interrupts |

### Hook Examples
```python
# Code hook
def hook_code(uc, address, size, user_data):
    print(f"Executing: 0x{address:x}")

mu.hook_add(UC_HOOK_CODE, hook_code)

# Memory hook
def hook_mem_access(uc, access, address, size, value, user_data):
    print(f"Memory access at 0x{address:x}")

mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)
```

## Advanced Features

### Context Management
| Operation | Usage | Purpose |
|-----------|-------|---------|
| `context_save()` | `context = mu.context_save()` | Save state |
| `context_restore()` | `mu.context_restore(context)` | Restore state |
| `context_update()` | `mu.context_update(context)` | Update state |

### Error Handling
```python
try:
    mu.emu_start(address, address + size)
except UcError as e:
    print(f"Error: {e}")
```

### Common Error Codes
| Code | Meaning |
|------|----------|
| `UC_ERR_WRITE_UNMAPPED` | Write to unmapped memory |
| `UC_ERR_READ_UNMAPPED` | Read from unmapped memory |
| `UC_ERR_FETCH_UNMAPPED` | Fetch from unmapped memory |
| `UC_ERR_WRITE_PROT` | Write to protected memory |
| `UC_ERR_READ_PROT` | Read from protected memory |

## Debugging and Analysis

### Debug Features
| Feature | Usage | Purpose |
|---------|-------|---------|
| `tracing()` | `mu.tracing()` | Enable tracing |
| `debug()` | `mu.debug()` | Debug mode |
| `query()` | `mu.query(UC_QUERY_*)` | Query emulator |

### Performance Optimization
| Setting | Purpose |
|---------|----------|
| `timeout` | Set execution timeout |
| `count` | Set instruction count |
| `page_size` | Configure page size |
| `arch_detail` | Toggle detailed mode |

### Integration Examples

#### Basic x86 Emulation
```python
# Define code to emulate
X86_CODE32 = b"\x41\x4a"  # INC ecx; DEC edx

# Initialize emulator
mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, X86_CODE32)
mu.reg_write(UC_X86_REG_ECX, 0x1)
mu.reg_write(UC_X86_REG_EDX, 0x2)
mu.emu_start(0x1000, 0x1000 + len(X86_CODE32))
```

#### ARM Emulation
```python
# Define ARM code
ARM_CODE = b"\x00\xe0\xa0\xe3"  # mov r0, #0

# Initialize emulator
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, ARM_CODE)
mu.emu_start(0x1000, 0x1000 + len(ARM_CODE))
```