# RetDec (Retargetable Decompiler) Cheatsheet

## Installation Guide

### Using Git
```bash
# Clone repository
git clone https://github.com/avast/retdec
cd retdec

# Initialize submodules
git submodule update --init --recursive

# Build
mkdir build && cd build
cmake ..
make
make install
```

### Using Docker
```bash
# Pull official image
docker pull retdec/retdec

# Run container
docker run -it retdec/retdec
```

## Basic Commands

### Decompilation
| Command | Usage | Purpose |
|---------|--------|---------|
| `retdec-decompiler` | `retdec-decompiler input.exe` | Basic decompilation |
| `--select-ranges` | `--select-ranges 0x1000-0x2000` | Decompile specific ranges |
| `--select-functions` | `--select-functions func1,func2` | Decompile specific functions |
| `--raw-entry-point` | `--raw-entry-point 0x1000` | Set entry point |
| `--raw-section-vma` | `--raw-section-vma 0x1000` | Set section VMA |

### Analysis Options
| Command | Usage | Purpose |
|---------|--------|---------|
| `--analysis-only` | `--analysis-only` | Only analyze, don't decompile |
| `--ar-index` | `--ar-index=n` | Set archive index |
| `--ar-name` | `--ar-name=name` | Set archive name |
| `--backend-aggressive-opts` | `--backend-aggressive-opts` | Aggressive optimizations |
| `--backend-no-opts` | `--backend-no-opts` | Disable optimizations |

### Output Control
| Command | Usage | Purpose |
|---------|--------|---------|
| `--output` | `--output file.c` | Set output file |
| `--keep-all` | `--keep-all` | Keep intermediate files |
| `--graph-format` | `--graph-format=pdf` | Set graph format |
| `--no-memory-limit` | `--no-memory-limit` | Disable memory limits |
| `--verbose` | `--verbose` | Verbose output |

## File Type Support
```bash
# Supported formats
ELF
PE
COFF
Intel HEX
Raw data
Mach-O
AR archives
```

## Architecture Support
```bash
# Supported architectures
x86
x64
ARM
ARM64
MIPS
PIC32
PowerPC
```

## Advanced Usage Examples
```bash
# Decompile with specific architecture
retdec-decompiler --arch arm input.bin

# Decompile with entry point
retdec-decompiler --raw-entry-point 0x1000 input.bin

# Generate control flow graph
retdec-decompiler --generate-cfg input.exe

# Keep all intermediate files
retdec-decompiler --keep-all input.exe

# Specify target language
retdec-decompiler --target-language c input.exe
```

## Script Integration
```python
#!/usr/bin/env python3
import subprocess

def decompile(input_file, output_file):
    cmd = [
        'retdec-decompiler',
        '--output', output_file,
        input_file
    ]
    subprocess.run(cmd, check=True)
```

## Best Practices
1. Use `--keep-all` for debugging
2. Set appropriate architecture
3. Specify entry points for raw binaries
4. Use selective decompilation for large files
5. Enable aggressive optimizations when needed
6. Check intermediate representations
7. Use verbose mode for troubleshooting

## Troubleshooting
1. Check file permissions
2. Verify file format
3. Monitor memory usage
4. Check for missing dependencies
5. Verify architecture settings
6. Review error logs
7. Check intermediate files

## Common Errors and Solutions
```text
Error: Unable to detect file format
Solution: Specify format manually

Error: Memory limit exceeded
Solution: Use --no-memory-limit

Error: Unknown architecture
Solution: Specify architecture with --arch

Error: Invalid entry point
Solution: Verify entry point address
```
