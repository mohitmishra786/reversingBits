# readelf Command Cheatsheet

## Installation Instructions

### Windows
```bash
# Using MSYS2
pacman -S binutils

# Using Chocolatey
choco install mingw-w64
```

### Linux
```bash
# Debian/Ubuntu
sudo apt-get install binutils

# RHEL/CentOS
sudo yum install binutils

# Arch Linux
sudo pacman -S binutils
```

### macOS
```bash
# Using Homebrew
brew install binutils
# Command might be available as 'greadelf'
```

## Basic Header Information

1. Display all headers:
```bash
readelf -a binary_file
```

2. Show file header:
```bash
readelf -h binary_file
```

3. Display section headers:
```bash
readelf -S binary_file
```

4. Show program headers:
```bash
readelf -l binary_file
```

## Symbol Table Analysis

5. Display symbol table:
```bash
readelf -s binary_file
```

6. Show dynamic symbol table:
```bash
readelf --dyn-syms binary_file
```

7. Display symbol versioning:
```bash
readelf -V binary_file
```

## Dynamic Section Information

8. Show dynamic section:
```bash
readelf -d binary_file
```

9. Display needed libraries:
```bash
readelf -d binary_file | grep "NEEDED"
```

10. Show RPATH/RUNPATH:
```bash
readelf -d binary_file | grep "RPATH\|RUNPATH"
```

## Relocation Information

11. Display relocations:
```bash
readelf -r binary_file
```

12. Show dynamic relocations:
```bash
readelf --dyn-rel binary_file
```

13. Display PLT relocations:
```bash
readelf -R binary_file
```

## Section Analysis

14. List sections:
```bash
readelf --sections binary_file
```

15. Show section contents:
```bash
readelf -x section_name binary_file
```

16. Display string tables:
```bash
readelf -p .strtab binary_file
```

## Notes and Comments

17. Show notes:
```bash
readelf -n binary_file
```

18. Display build attributes:
```bash
readelf -A binary_file
```

19. Show file comments:
```bash
readelf --string-dump=.comment binary_file
```

## Architecture Information

20. Display architecture-specific info:
```bash
readelf -A binary_file
```

21. Show processor-specific flags:
```bash
readelf --arm-attributes binary_file
```

## Version Information

22. Show version info:
```bash
readelf --version-info binary_file
```

23. Display version symbols:
```bash
readelf --version-symbols binary_file
```

## Header Details

24. Show ELF file type:
```bash
readelf -h binary_file | grep "Type:"
```

25. Display entry point:
```bash
readelf -h binary_file | grep "Entry point"
```

## Section Groups

26. Display section groups:
```bash
readelf -g binary_file
```

27. Show group sections:
```bash
readelf --section-groups binary_file
```

## Advanced Analysis

28. Display unwind information:
```bash
readelf --unwind binary_file
```

29. Show archive index:
```bash
readelf --archive-index archive.a
```

30. Display hex dump of section:
```bash
readelf -x .text binary_file
```

## Debug Information

31. Show debug sections:
```bash
readelf -w binary_file
```

32. Display DWARF info:
```bash
readelf --debug-dump binary_file
```

33. Show frame information:
```bash
readelf --debug-dump=frames binary_file
```

## Security Analysis

34. Check for security features:
```bash
readelf -l binary_file | grep "GNU_STACK"
```

35. Display stack canary:
```bash
readelf -s binary_file | grep "__stack_chk"
```

36. Show RELRO status:
```bash
readelf -l binary_file | grep "GNU_RELRO"
```

## Core Dump Analysis

37. Analyze core dump:
```bash
readelf -n core.dump
```

38. Show core dump sections:
```bash
readelf -S core.dump
```

## Special Sections

39. Display .init section:
```bash
readelf -x .init binary_file
```

40. Show .fini section:
```bash
readelf -x .fini binary_file
```

## Output Formatting

41. Wide output format:
```bash
readelf -W binary_file
```

42. Hex dump with ASCII:
```bash
readelf -x .data --string binary_file
```

## Integration Features

43. Generate script-friendly output:
```bash
readelf --demangle --wide binary_file
```

44. Show all strings:
```bash
readelf -p .rodata binary_file
```

## Advanced Options

45. Display histogram:
```bash
readelf --histogram binary_file
```

46. Show archive headers:
```bash
readelf --archive-index archive.a
```

47. Display symbol size:
```bash
readelf -s --wide binary_file
```

## Special Analysis

48. Check for stripped symbols:
```bash
readelf -s binary_file | grep "Symbol table"
```

49. Analyze dynamic loader:
```bash
readelf -l binary_file | grep "Requesting"
```

50. Show segment permissions:
```bash
readelf -l binary_file | grep "FLAGS"
```
