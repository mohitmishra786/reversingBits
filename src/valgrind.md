# Valgrind Cheatsheet

## Installation Guide

### Linux
```bash
# Debian/Ubuntu
sudo apt-get install valgrind

# Fedora/RHEL
sudo dnf install valgrind

# Build from source
wget https://sourceware.org/pub/valgrind/valgrind-VERSION.tar.bz2
tar -xjf valgrind-VERSION.tar.bz2
cd valgrind-VERSION
./configure
make
sudo make install
```

## Basic Tools and Commands

### Memcheck (Memory Error Detector)
| Command | Usage | Purpose |
|---------|--------|---------|
| `valgrind` | `valgrind --tool=memcheck ./program` | Basic memory check |
| `--leak-check` | `valgrind --leak-check=full ./program` | Detailed leak check |
| `--show-reachable` | `--show-reachable=yes` | Show reachable leaks |
| `--track-origins` | `--track-origins=yes` | Track uninitialized values |
| `--xml` | `--xml=yes --xml-file=report.xml` | XML output |

### Cachegrind (Cache Profiler)
| Command | Usage | Purpose |
|---------|--------|---------|
| `cachegrind` | `valgrind --tool=cachegrind ./program` | Cache analysis |
| `cg_annotate` | `cg_annotate cachegrind.out.pid` | Analyze output |
| `--branch-sim` | `--branch-sim=yes` | Branch prediction sim |
| `--cache-sim` | `--cache-sim=yes` | Cache simulation |

### Callgrind (Call Graph Generator)
| Command | Usage | Purpose |
|---------|--------|---------|
| `callgrind` | `valgrind --tool=callgrind ./program` | Profile execution |
| `callgrind_control` | `callgrind_control -d` | Dump profile data |
| `callgrind_annotate` | `callgrind_annotate callgrind.out.pid` | Analyze profile |
| `--dump-instr` | `--dump-instr=yes` | Dump instruction info |

### Massif (Heap Profiler)
| Command | Usage | Purpose |
|---------|--------|---------|
| `massif` | `valgrind --tool=massif ./program` | Heap profiling |
| `ms_print` | `ms_print massif.out.pid` | Print heap profile |
| `--heap` | `--heap=yes` | Profile heap |
| `--detailed-freq` | `--detailed-freq=10` | Detail frequency |

### Helgrind (Thread Debugger)
| Command | Usage | Purpose |
|---------|--------|---------|
| `helgrind` | `valgrind --tool=helgrind ./program` | Thread error check |
| `--history-level` | `--history-level=full` | Lock order history |
| `--conflict-cache-size` | `--conflict-cache-size=2097152` | Cache size |

## Common Options for All Tools
```bash
# Suppress errors
--suppressions=supp.file

# Track file descriptors
--track-fds=yes

# Child process debugging
--trace-children=yes

# Time stamp logging
--time-stamp=yes

# Only show errors
--quiet

# Verbose output
-v
```

## Error Types and Meanings

### Memory Errors
```text
Invalid read/write
Uninitialized value
Memory leak
Invalid free
Mismatched free/delete
Double free
Overlap in memcpy
```

### Thread Errors
```text
Data race
Lock order violation
Thread exit with locked mutex
Invalid mutex operation
```

## Suppression File Format
```text
{
   <suppression_name>
   <tool_name>:MemCheck
   ...
   fun:function_name
   obj:object_file
}
```

## Best Practices
1. Always use `--leak-check=full`
2. Enable `--track-origins` for uninitialized values
3. Create suppressions for known issues
4. Use `--gen-suppressions=all` to generate suppressions
5. Run with optimized binaries for accurate profiling
6. Use `--xml` output for automated analysis
7. Regular profiling during development

## Performance Tips
1. Use `--num-callers` to reduce stack trace size
2. Disable expensive checks when not needed
3. Use selective instrumentation
4. Profile specific functions with `--toggle-collect`
5. Use `--max-stackframe` for large stack frames
6. Optimize suppression files
7. Use `--time-stamp` for long-running programs

## Debugging Examples
```bash
# Basic memory check
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./program

# Profile with callgraph
valgrind --tool=callgrind --dump-instr=yes --collect-jumps=yes ./program

# Thread check with history
valgrind --tool=helgrind --history-level=full ./program

# Heap profile
valgrind --tool=massif --heap=yes --detailed-freq=10 ./program

# Cache analysis
valgrind --tool=cachegrind --branch-sim=yes ./program
```
