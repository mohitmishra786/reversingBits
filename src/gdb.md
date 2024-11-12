# GDB (GNU Debugger) Cheatsheet

## Table of Contents
1. [Installation Instructions](#installation-instructions)
2. [Program Execution Controls](#program-execution-controls)
3. [Breakpoint Management](#breakpoint-management)
4. [Watchpoint Operations](#watchpoint-operations)
5. [Conditional Debugging](#conditional-debugging)
6. [Stack Examination](#stack-examination)
7. [Program Flow Control](#program-flow-control)
8. [Variable and Memory Inspection](#variable-and-memory-inspection)
9. [Thread Management](#thread-management)
10. [Program Manipulation](#program-manipulation)
11. [Source Code Navigation](#source-code-navigation)
12. [Signal Handling](#signal-handling)
13. [Debug Information](#debug-information)
14. [Advanced Features](#advanced-features)
15. [Reverse Debugging](#reverse-debugging)
16. [Process Information](#process-information)
17. [Convenience Features](#convenience-features)
18. [Best Practices](#best-practices)
19. [Common Issues and Solutions](#common-issues-and-solutions)

## Installation Instructions

### Windows
```powershell
# Using Chocolatey
choco install mingw

# Using MSYS2
pacman -S mingw-w64-x86_64-gdb
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install gdb
```

### macOS
```bash
# Using Homebrew
brew install gdb
# Note: Additional signing steps required for macOS
```

## Program Execution Controls

### Starting GDB

```bash
# Basic GDB startup
gdb <program>                  # Start GDB with a program
gdb <program> [core dump]      # Start GDB with a core dump file
gdb --args <program> <args...> # Start GDB with program arguments
gdb --pid <pid>               # Attach GDB to a running process
gdb -p <pid>                  # Alternative syntax for attaching to process
```

### Program Control Commands

```bash
set args <args...>    # Set arguments for the program to be debugged
run                   # Start program execution
run arg1 arg2         # Run with specific arguments
kill                  # Terminate the running program
quit                  # Exit GDB
attach <pid>         # Attach to a running process
detach               # Detach from the current process
continue (or c)      # Continue execution
```

## Breakpoint Management

### Basic Breakpoint Operations

```bash
break <where>              # Set a new breakpoint
b <where>                 # Short form for break
delete <breakpoint#>       # Remove a specific breakpoint
clear                      # Delete all breakpoints
enable <breakpoint#>       # Enable a disabled breakpoint
disable <breakpoint#>      # Disable a breakpoint
info breakpoints          # List all breakpoints
i b                       # Short form for info breakpoints
```

### Breakpoint Locations (`<where>` can be)

```bash
function_name              # Break at function entry
line_number               # Break at specific line in current file
file:line_number          # Break at specific line in named file
*address                  # Break at specific memory address (e.g., *0x4004e7)
class::method            # Break at class method (C++)
+offset                  # Break at offset lines from current
-offset                  # Break at offset lines before current
```

## Watchpoint Operations

### Basic Watchpoint Commands

```bash
watch <where>              # Set a new watchpoint
rwatch <where>             # Set read watchpoint
awatch <where>             # Set access watchpoint
watch *0x4004e7           # Watch specific memory location
watch expr                # Watch expression
delete <watchpoint#>       # Remove a watchpoint
enable <watchpoint#>       # Enable a disabled watchpoint
disable <watchpoint#>      # Disable a watchpoint
info watchpoints          # List all watchpoints
```

## Stack Examination

### Stack Navigation and Information

```bash
backtrace                 # Show call stack
bt                        # Short form for backtrace
where                     # Alias for backtrace
backtrace full           # Show call stack with local variables
where full               # Alias for backtrace full
frame <frame#>           # Select stack frame to examine
f <frame#>               # Short form for frame
up                       # Move up one stack frame
down                     # Move down one stack frame
info frame              # Information about current frame
info args               # Show function arguments
info locals             # Show local variables
```

## Program Flow Control

### Execution Control

```bash
step (or s)              # Step into next instruction
next (or n)              # Step over next instruction
finish                   # Continue until current function returns
continue (or c)         # Continue normal execution
until <location>        # Continue until location
advance <location>      # Continue until location
return [expression]     # Force immediate return from function
```

## Variable and Memory Inspection

### Print Formats

```bash
print/[format] <what>    # Print variable/memory/register
p <what>                # Short form for print
display/[format] <what>  # Print value after each step
display/i $pc           # Display instruction pointer
undisplay <display#>     # Remove display
enable display <display#> # Enable display
disable display <display#> # Disable display
```

### Memory Examination

```bash
x/nfu <address>          # Examine memory
x/10x $rsp              # Show 10 hex words at stack pointer
p *array@length         # Print array contents
x/s string_ptr         # Print string
p *struct_ptr          # Print structure contents
```

### Register Operations

```bash
info registers         # Show all registers
i r                    # Short form for info registers
info registers rax    # Show specific register
p $rax                # Print RAX register value
```

## Advanced Features

### Python Integration

```bash
python
def print_rax():
    rax = gdb.selected_frame().read_register("rax")
    print(f"RAX = {rax}")
end
```

### Command Aliases and Scripts

```bash
# Define custom command
define mycommand
commands
end

# Create breakpoint commands
break main
commands
    print argc
    continue
end
```

### Remote Debugging

```bash
target remote host:port  # Connect to remote GDB server
target remote localhost:1234  # Common local debugging setup
set remotebaud baud    # Set remote baud rate
set remotelogfile file # Set remote log file
monitor cmd            # Send command to remote monitor
```

## Reverse Debugging

```bash
record                  # Start recording execution trace
record stop            # Stop recording
reverse-continue (rc)  # Continue backward
reverse-step (rs)     # Step backward
reverse-next          # Step over backward
reverse-finish        # Run backward until function entry
```

## Process Information

```bash
info proc mappings     # Show memory map
info sharedlibrary    # Show loaded shared libraries
info threads         # List all threads
thread <thread#>     # Switch to specified thread
set follow-fork-mode child  # Follow child process on fork
```

## Best Practices

### Performance Optimization

```bash
# Use hardware breakpoints
hbreak <location>     # Set hardware breakpoint

# Conditional breakpoints
break main if argc > 1

# Catchpoints for system calls
catch syscall
commands
    print $rax
    continue
end
```

### Security Analysis

```bash
# Check ASLR status
show disable-randomization

# Handle signals
handle SIGSEGV nostop noprint

# Examine security features
checksec
```

## Configuration Settings

```bash
# History
set history save on
set history filename ~/.gdb_history

# Output formatting
set print pretty on
set print array on
set print elements 0   # No limit on array elements

# Custom prompt
set prompt (gdb-custom) 
```

## Common Issues and Solutions

### Symbol Loading Issues

```bash
# Load symbols
symbol-file file
add-symbol-file file address

# Set system root for symbols
set sysroot /path/to/sysroot
```

### Memory Analysis

```bash
# Memory leak detection helper
define leak_check
  set $start = 0
  while $start < 0x7fffffffffff
    if *(void**)$start != 0
      print $start
    end
    set $start = $start + 8
  end
end
```

### Debugging Helpers

```bash
# Automatic backtrace on segfault
catch signal SIGSEGV
commands
    where
    backtrace full
end
```

## Advanced Analysis

```bash
# Disassemble
disassemble function_name
disas function_name    # Short form

# Set architecture
set architecture i386

# Examine core dumps
generate-core-file
core-file corefile
```

---

**Note**: This cheatsheet combines common GDB commands, advanced features, and best practices. For the most up-to-date and complete documentation, please check:
- The GDB manual (use `help` command within GDB)
- The official [GDB Documentation](https://sourceware.org/gdb/documentation/)

Compile programs with debugging information (`-g` flag) for optimal debugging experience.
