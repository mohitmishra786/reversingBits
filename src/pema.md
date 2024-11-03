# PEDA Cheatsheet

## Installation & Setup
```bash
# Clone PEDA
git clone https://github.com/longld/peda.git ~/peda

# Add to GDB config
echo "source ~/peda/peda.py" >> ~/.gdbinit

# Start GDB with PEDA
gdb [binary]
```

## Basic Commands
### Program Execution
| Command | Description |
|---------|-------------|
| start | Start program and break at main |
| run | Run program |
| continue | Continue execution |
| next/n | Step over |
| step/s | Step into |
| finish | Run until return |

### Memory Examination
```
pdisas          # Disassemble with enhanced output
telescope       # Display memory content
hexdump         # Show hex dump of memory
vmmap           # Show virtual memory mapping
xinfo address   # Show detail info of address
```

## Pattern Operations
### Pattern Creation
```
pattern_create length [file]    # Create cyclic pattern
pattern_offset pattern          # Find offset of pattern
pattern_patch address pattern   # Patch memory with pattern
pattern_search                  # Search for pattern in memory
```

### Pattern Analysis
```
pattern_arg length             # Set pattern as command line arg
pattern_env length            # Set pattern as environment var
```

## Registers & Stack
### Register Commands
```
context         # Show registers, code, stack
registers       # Show all registers
xinfo $reg      # Show register information
set $reg=value  # Modify register value
```

### Stack Operations
```
stack          # Show stack content
stackup n      # Stack up n words
stackdown n    # Stack down n words
```

## Enhanced Commands
### Assembly
```
assemble       # Convert assembly to opcodes
asm            # Assemble instruction
asmsearch      # Search for assembly instructions
```

### Binary Analysis
```
checksec       # Check binary security
elfheader     # Show ELF header info
procinfo      # Show process info
```

## Exploit Development
### ROP Gadgets
```
ropsearch "pop rdi"    # Search for ROP gadgets
ropgadget            # Show all ROP gadgets
ropper              # Use ropper for gadget search
```

### Shellcode
```
shellcode generate            # Generate shellcode
shellcode search "execve"    # Search for shellcode
skeleton [type]              # Generate exploit skeleton
```

## Memory Operations
### Memory Search
```
searchmem pattern     # Search pattern in memory
searchstring str      # Search string in memory
find /bin/sh         # Find string in memory
```

### Memory Manipulation
```
patch address bytes          # Patch memory
writemem file start end     # Write memory to file
loadmem file address        # Load file into memory
```

## Breakpoints
### Advanced Breakpoints
```
bp address [command]        # Set breakpoint with command
trace address              # Trace execution at address
tracecall                 # Trace all function calls
traceinst                 # Trace all instructions
```

### Conditional Breaks
```
break *address if condition
watch expression
rwatch expression
```

## Analysis Features
### Function Analysis
```
pdisas function           # Disassemble function
context code n           # Show n lines of code
nearpc [n]              # Show n instructions near PC
```

### Program Flow
```
goto address            # Continue to address
skip [n]               # Skip n instructions
stepuntil expression   # Step until expression true
```

## Advanced Features
### Custom Commands
```python
# Create custom PEDA command
class MyCommand(PEDACmd):
    def __init__(self):
        super().__init__()
        
    def help(self):
        return "My custom command"
        
    def execute(self, args):
        # Command implementation
        pass
```

### Scripting
```python
# PEDA script example
python
def analyze_stack():
    print("Analyzing stack...")
    peda.execute("stack 20")
    peda.execute("context")
end
```

## Tips & Best Practices
### Debugging Workflow
1. Initial Analysis
```
checksec
elfheader
vmmap
```

2. Memory Layout
```
vmmap
telescope
stack
```

3. Exploit Development
```
pattern_create
pattern_offset
ropsearch
shellcode
```

### Performance
1. Disable ASLR
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

2. Debug Output
```
set debug on
show debug
```

3. Command Log
```
set logging on
set logging file output.txt
```

### Common Tasks
1. Buffer Overflow
```
pattern_create 100
run
pattern_offset $esp
```

2. ROP Chain
```
ropsearch "pop rdi"
ropper
checksec
```

3. Shellcode Testing
```
shellcode generate
patch address
continue
```

### Configuration
1. PEDA Options
```
show option
set option name value
```

2. Display Settings
```
set context-code-lines n
set context-stack-lines n
```

3. Custom Prompts
```
set prompt \001\033[1;32m\002peda> \001\033[0m\002
```
