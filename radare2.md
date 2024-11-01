# Radare2 Comprehensive Cheatsheet

## Installation Instructions

### Windows
```powershell
# Using Git
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh

# Using Binary
Download Windows installer from rada.re/r
```

### Linux (Ubuntu/Debian)
```bash
# Using apt
sudo apt-get install radare2

# Building from source
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

### macOS
```bash
# Using Homebrew
brew install radare2

# Using source
git clone https://github.com/radareorg/radare2
sys/install.sh
```

## Basic Commands

### Starting Radare2

1. **Open Binary**
```bash
r2 binary
```

2. **Open Binary in Debug Mode**
```bash
r2 -d binary
```

3. **Open Binary in Write Mode**
```bash
r2 -w binary
```

### Analysis Commands

4. **Analyze All**
```bash
aa
```

5. **Analyze More**
```bash
aaa
```

6. **Analyze Even More**
```bash
aaaa
```

7. **List Functions**
```bash
afl
```

### Navigation

8. **Seek to Address**
```bash
s address
s main
```

9. **Print Disassembly**
```bash
pd
pdf        # Print disassembly of function
pdf @main  # Print main function
```

10. **Visual Mode**
```bash
V      # Enter visual mode
VV     # Enter visual graph mode
v      # Enter visual panels mode
```

### Memory Operations

11. **Write String**
```bash
w string
```

12. **Write Hex**
```bash
wx 90909090
```

13. **Read Memory**
```bash
x        # Read hexdump
px      # Print hexdump
ps      # Print string
```

### Debug Commands

14. **Set Breakpoint**
```bash
db address
```

15. **Remove Breakpoint**
```bash
db -address
```

16. **List Breakpoints**
```bash
db
```

17. **Continue Execution**
```bash
dc
```

18. **Step Into**
```bash
ds
```

19. **Step Over**
```bash
dso
```

### Information Commands

20. **File Information**
```bash
i      # Info
iz     # Strings in data sections
ii     # Imports
ie     # Entries (entrypoints)
```

21. **Headers**
```bash
ih     # Headers
iH     # Verbose Headers
```

### Search Commands

22. **Search String**
```bash
/ string
/x pattern    # Search hex
/w string     # Search wide string
```

23. **References**
```bash
axt address  # Find references to address
axf address  # Find references from address
```

### Visual Mode Commands

24. **Graph Commands**
```bash
VV            # Enter graph mode
p             # Cycle through different views
.             # Seek to program counter
:             # Enter command mode
```

25. **Visual Panels**
```bash
v             # Enter visual panels mode
!             # Run shell command
+             # Add new panel
-             # Remove current panel
```

### Analysis Features

26. **Function Analysis**
```bash
af            # Analyze function
afr           # Analyze references
afl           # List functions
afi           # Function information
```

27. **Type Analysis**
```bash
ta            # Type analysis
te            # List enums
tc            # List types
```

### Scripting

28. **Run Script**
```bash
. script.r2
```

29. **Write Script**
```bash
#!pipe python
import r2pipe
r2 = r2pipe.open()
print(r2.cmd("pi 5"))
```

### Project Management

30. **Save Project**
```bash
Ps name       # Save project
Po name       # Open project
```

### Advanced Features

31. **Binary Patching**
```bash
w             # Write bytes
wa            # Write assembly
wc            # Write cache
```

32. **Binary Diffing**
```bash
radiff2 file1 file2
```

33. **Debugging with ESIL**
```bash
aei           # Initialize ESIL
aeim          # Initialize ESIL memory
aeip          # Initialize ESIL program counter
```

### Configuration

34. **Set Configuration**
```bash
e key=value
e asm.syntax=intel
e asm.bytes=false
```

35. **Graph Settings**
```bash
e graph.depth=4
e graph.font=Helvetica
```

## Advanced Usage Examples

### Automated Analysis
```bash
# Full analysis script
aa
pdf @main
afl
s sym.main
VV
```

### Binary Patching
```bash
# Replace instruction with NOP
s address
wa nop
```

### Function Analysis
```bash
# Analyze function and generate graph
af @main
agf
```

## Useful Tips

### Visual Mode Navigation
- hjkl: Move around
- p: Rotate through modes
- x: References
- v: Variable analysis
- g: Goto command

### Debug Mode Tips
- F7: Step into
- F8: Step over
- F9: Continue
- F2: Toggle breakpoint

### Analysis Tips
- Start with 'aa' analysis
- Use 'aaa' for deeper analysis
- Check strings with 'iz'
- Use 'axt' to find xrefs

## Common Scripts

### Function Analysis
```bash
#!/usr/bin/env rarun2
program=./binary
arg1=argument

# Analysis commands
e asm.syntax=intel
aa
s main
pdf
```

### Memory Analysis
```bash
# Search for pattern
/x 90909090
# Follow memory references
axf
```

## Best Practices

### Performance
- Use minimal analysis when possible
- Cache analysis results
- Use projects for large binaries

### Organization
- Use projects for complex analysis
- Document findings inline
- Use meaningful flags and comments

### Automation
- Use r2pipe for scripting
- Create custom r2 scripts
- Use radare2 plugins

## Common Issues and Solutions

### Symbol Resolution
```bash
# Load symbols
is
# Analyze symbols
aa
```

### File Format Issues
```bash
# Force binary format
r2 -f format binary
```

### Memory Issues
```bash
# Set bigger memory map
e dbg.bep=entry
e dbg.maps=true
```
