# Hexdump Comprehensive Cheatsheet

## Installation Instructions

### Windows
```powershell
# Using Chocolatey
choco install hexdump

# Using MSYS2
pacman -S util-linux
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install bsdmainutils
```

### macOS
```bash
# Using Homebrew
brew install hexdump

# Already installed by default on macOS
```

## Basic Commands

### Standard Output Formats

1. **Basic Hexdump**
```bash
hexdump file
```

2. **Canonical Hex+ASCII Display**
```bash
hexdump -C file
```

3. **Two-byte Hex Display**
```bash
hexdump -x file
```

4. **One-byte Octal Display**
```bash
hexdump -b file
```

### Format Specifiers

5. **Custom Format**
```bash
hexdump -e '16/1 "%02X " "\n"' file
```

6. **Format with ASCII**
```bash
hexdump -e '16/1 "%02X " "  |" 16/1 "%_p" "|\n"' file
```

7. **Four-byte Words**
```bash
hexdump -e '4/4 "%08X " "\n"' file
```

### Offset Control

8. **Skip Bytes**
```bash
hexdump -s offset file
```

9. **Limit Length**
```bash
hexdump -n length file
```

10. **Custom Offset Format**
```bash
hexdump -e '"0x%08.8_ax  " 16/1 "%02X " "\n"' file
```

### Data Analysis

11. **Search for Pattern**
```bash
hexdump -C file | grep "pattern"
```

12. **Compare Files**
```bash
cmp <(hexdump file1) <(hexdump file2)
```

13. **Extract Specific Bytes**
```bash
hexdump -s offset -n length -C file
```

### Advanced Format Strings

14. **Custom Byte Grouping**
```bash
hexdump -e '8/1 "%02X " "  " 8/1 "%02X " "\n"' file
```

15. **Include Decimal Values**
```bash
hexdump -e '4/1 "%3d " "\n"' file
```

16. **Mixed Hex and ASCII**
```bash
hexdump -e '"%08.8_ax  " 8/1 "%02X " "  " 8/1 "%02X "' -e '"  |" 16/1 "%_p" "|\n"' file
```

### File Analysis Techniques

17. **Find String Patterns**
```bash
hexdump -C file | grep -A1 -B1 "text"
```

18. **Analyze File Headers**
```bash
hexdump -n 16 -C file
```

19. **Check File Type**
```bash
hexdump -n 4 -C file
```

### Binary Analysis

20. **Analyze Executable Headers**
```bash
hexdump -n 64 -C executable
```

21. **Extract Sections**
```bash
hexdump -s section_offset -n section_size -C file
```

22. **Find Null Sequences**
```bash
hexdump -C file | grep "00 00 00 00"
```

### Special Uses

23. **Memory Dump Analysis**
```bash
hexdump -C memory.dump
```

24. **Network Packet Analysis**
```bash
hexdump -C packet.cap
```

25. **Firmware Analysis**
```bash
hexdump -C firmware.bin
```

## Advanced Usage

### Custom Scripts

26. **Pattern Matching Script**
```bash
#!/bin/bash
hexdump -C "$1" | grep -A2 -B2 "$2"
```

27. **Binary Diff Script**
```bash
#!/bin/bash
diff <(hexdump -C "$1") <(hexdump -C "$2")
```

### Format String Examples

28. **32-bit Integer Format**
```bash
hexdump -e '4/4 "0x%08x " "\n"' file
```

29. **Float Format**
```bash
hexdump -e '4/4 "%f " "\n"' file
```

30. **Mixed Format**
```bash
hexdump -e '"%-8_ad  " 8/1 " %02x" "  " 8/1 " %02x" "  |" 16/1 "%_p" "|\n"' file
```

## Practical Applications

### File Format Analysis

31. **PDF Header Analysis**
```bash
hexdump -n 32 -C file.pdf
```

32. **ZIP File Analysis**
```bash
hexdump -C file.zip | grep "PK"
```

33. **Image File Analysis**
```bash
hexdump -n 8 -C image.jpg
```

### Malware Analysis

34. **String Extraction**
```bash
hexdump -C malware.bin | grep -i "http"
```

35. **Signature Detection**
```bash
hexdump -C file | grep -A4 "MZ"
```

### Data Recovery

36. **Find File Headers**
```bash
hexdump -C disk.img | grep -A16 -B16 "PDF"
```

37. **Carve File Boundaries**
```bash
hexdump -C disk.img | grep -A32 "FFD8"
```

## Best Practices

### Performance Tips

38. **Large File Handling**
```bash
# Use dd to split large files
dd if=large_file bs=1M count=1 | hexdump -C
```

39. **Efficient Searching**
```bash
hexdump -C file | grep --color=auto pattern
```

### Analysis Workflow

40. **Initial Assessment**
```bash
# Quick file overview
head -c 512 file | hexdump -C
```

41. **Detailed Analysis**
```bash
# Full file with custom format
hexdump -e '"%08.8_ax  " 16/1 "%02X " "  |" 16/1 "%_p" "|\n"' file
```

## Common Issues and Solutions

42. **File Encoding**
```bash
# Handle different encodings
iconv -f utf-16 -t utf-8 file | hexdump -C
```

43. **Large Files**
```bash
# Split analysis
split -b 1M file chunk_
for f in chunk_*; do hexdump -C "$f"; done
```

## Scripting Examples

44. **Automated Analysis**
```bash
#!/bin/bash
for file in *.bin; do
    echo "Analyzing $file..."
    hexdump -C "$file" | grep -A4 -B4 "pattern"
done
```

45. **Format Conversion**
```bash
#!/bin/bash
hexdump -e '16/1 "%02X" "\n"' file > file.hex
```
