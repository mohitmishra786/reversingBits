# Objdump Comprehensive Cheatsheet

## Installation Instructions

### Windows
```powershell
# Using Chocolatey
choco install binutils

# Using MSYS2
pacman -S mingw-w64-x86_64-binutils
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install binutils
```

### macOS
```bash
# Using Homebrew
brew install binutils

# Using MacPorts
sudo port install binutils
```

## Basic Commands and Usage

### Basic File Analysis

1. **Display File Headers**
```bash
objdump -f executable
```

2. **Display All Headers**
```bash
objdump -x executable
```

3. **Disassemble All Sections**
```bash
objdump -d executable
```

4. **Display Relocation Entries**
```bash
objdump -r executable
```

### Disassembly Options

5. **Intel Syntax Disassembly**
```bash
objdump -M intel -d executable
```

6. **AT&T Syntax Disassembly**
```bash
objdump -M att -d executable
```

7. **Disassemble Specific Section**
```bash
objdump -d -j .text executable
```

8. **Source Code Intermixed**
```bash
objdump -S executable
```

### Symbol Table Analysis

9. **Display Symbol Table**
```bash
objdump -t executable
```

10. **Display Dynamic Symbol Table**
```bash
objdump -T executable
```

### Section Analysis

11. **Display All Sections Content**
```bash
objdump -s executable
```

12. **Display Full Contents of Sections**
```bash
objdump -s -j .rodata executable
```

### Advanced Options

13. **Show File Offsets**
```bash
objdump --show-raw-insn -d executable
```

14. **Demangle C++ Symbols**
```bash
objdump -C -d executable
```

15. **Display Debug Information**
```bash
objdump --dwarf executable
```

### Format-Specific Options

16. **Display Architecture Specific Information**
```bash
objdump -a executable
```

17. **Display Private Headers**
```bash
objdump -p executable
```

### Analysis Techniques

18. **Find String References**
```bash
objdump -s -j .rodata executable | grep "string"
```

19. **Analyze Function Calls**
```bash
objdump -d executable | grep "call"
```

20. **Extract All Strings**
```bash
objdump -s -j .rodata executable
```

### Advanced Analysis

21. **Display Line Numbers**
```bash
objdump -l -d executable
```

22. **Show All Information**
```bash
objdump -x -d -s executable
```

23. **Analyze Dynamic Relocations**
```bash
objdump -R executable
```

### Section Information

24. **Display Section Headers**
```bash
objdump -h executable
```

25. **Show Section Contents and Disassembly**
```bash
objdump -s -d executable
```

### Special Purpose Analysis

26. **Extract CTF (Compact C Type Format) Data**
```bash
objdump --ctf executable
```

27. **Display Source File Names**
```bash
objdump -W executable
```

### Binary Analysis Tips

28. **Find Entry Point**
```bash
objdump -f executable | grep "start address"
```

29. **Examine GOT (Global Offset Table)**
```bash
objdump -R executable | grep "GLOB"
```

30. **Analyze PLT (Procedure Linkage Table)**
```bash
objdump -d -j .plt executable
```

## Common Use Cases

### Malware Analysis
```bash
# Extract all strings and disassembly
objdump -s -d suspicious_file > analysis.txt

# Look for suspicious functions
objdump -d suspicious_file | grep -E "system|exec|shell"
```

### Reverse Engineering
```bash
# Generate full disassembly with source
objdump -S -d --no-show-raw-insn binary > disassembly.txt

# Analyze specific function
objdump -d binary | grep -A20 "<function_name>:"
```

### Debugging
```bash
# Get debugging symbols
objdump -g executable

# Show line numbers with disassembly
objdump -d -l executable
```

## Best Practices

- Always back up binaries before analysis
- Use multiple analysis passes with different options
- Combine with other tools (strings, readelf, etc.)
- Document findings systematically
- Verify findings with multiple approaches

## Common Issues and Solutions

### Permission Issues
```bash
# Fix permission denied
chmod +x executable
```

### Large Files
```bash
# Handle large output
objdump -d large_executable | tee analysis.txt
```

### Symbol Resolution
```bash
# Resolve stripped binaries
objdump -d stripped_binary --syms
```

## Advanced Usage Examples

### Custom Format Output
```bash
objdump -s --section=.data -j .data executable
```

### Scripting Integration
```bash
# Extract all function names
objdump -t executable | grep "F .text" | cut -d " " -f12
```

### Security Analysis
```bash
# Check for security features
objdump -x executable | grep -E "RELRO|BIND_NOW|NX"
```
