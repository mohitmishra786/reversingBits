# File Command Cheatsheet

## Installation Instructions

### Windows
```bash
# Using Chocolatey
choco install file

# Using MSYS2
pacman -S file
```

### Linux
```bash
# Debian/Ubuntu
sudo apt-get install file

# RHEL/CentOS
sudo yum install file

# Arch Linux
sudo pacman -S file
```

### macOS
```bash
# Usually pre-installed, if not:
brew install file
```

## Basic Usage

1. Basic file identification:
```bash
file filename
```

2. Don't follow symlinks:
```bash
file -P filename
```

3. Show mime type:
```bash
file --mime-type filename
```

## Multiple File Operations

4. Process multiple files:
```bash
file file1 file2 file3
```

5. Process entire directory:
```bash
file *
```

6. Recursive file analysis:
```bash
file -R directory/
```

## Output Formatting

7. Brief mode:
```bash
file -b filename
```

8. No filename in output:
```bash
file -b filename
```

9. Detailed mime type:
```bash
file --mime filename
```

## Special File Types

10. Analyze compressed file:
```bash
file -z compressed.gz
```

11. Look inside ZIP files:
```bash
file -z archive.zip
```

12. Examine device files:
```bash
file -s /dev/sda1
```

## Binary Analysis

13. Show ELF details:
```bash
file -h binary
```

14. Check for stripped binaries:
```bash
file binary | grep stripped
```

15. Display architecture:
```bash
file binary | grep -o ".*bit"
```

## Advanced Options

16. Use specific magic file:
```bash
file -m /path/to/magic filename
```

17. Show magic file compilation:
```bash
file -C -m filename
```

18. Debug magic file compilation:
```bash
file --debug-magic filename
```

## Network Operations

19. Examine URLs:
```bash
file -L http://example.com/file
```

20. Follow symbolic links:
```bash
file -L symlink
```

## Special Analysis

21. Preserve file times:
```bash
file -k filename
```

22. Show file version info:
```bash
file --version
```

23. Check magic file syntax:
```bash
file -c magic_file
```

## Security Analysis

24. Check for malformed files:
```bash
file --apple filename
```

25. Analyze raw data:
```bash
file -r filename
```

## Filesystem Analysis

26. Examine filesystem type:
```bash
file -s /dev/sda
```

27. Show partition info:
```bash
file -s /dev/sda1
```

## Archive Analysis

28. Look inside tar files:
```bash
file -z archive.tar.gz
```

29. Examine ISO images:
```bash
file disk.iso
```

## Character Encoding

30. Check text encoding:
```bash
file -i textfile
```

31. Show line endings:
```bash
file -k textfile | grep -o "text.*"
```

## Output Control

32. Separator string:
```bash
file -F ":" filename
```

33. Custom output format:
```bash
file -f namefile
```

## Special File Systems

34. Analyze core dumps:
```bash
file core.dump
```

35. Examine memory dumps:
```bash
file memory.dmp
```

## Performance Options

36. No pad option:
```bash
file -N filename
```

37. Fast mode:
```bash
file -f -
```

## Integration Features

38. Generate machine-readable output:
```bash
file --print0 filename
```

39. Print magic database:
```bash
file -m -
```

## System Information

40. Show supported filesystems:
```bash
file -v
```

41. Display compilation options:
```bash
file -v | grep "compiled"
```

## Advanced File Types

42. Check for scripts:
```bash
file --keep-going script.sh
```

43. Analyze symbolic links:
```bash
file -h symlink
```

## Special Modes

44. No buffering:
```bash
file --no-buffer filename
```

45. Raw output mode:
```bash
file -r filename
```

## Error Handling

46. Continue after errors:
```bash
file --keep-going filename
```

47. Show error details:
```bash
file --debug filename
```

## Custom Magic

48. Test magic patterns:
```bash
file -M magic_file filename
```

49. Compile magic file:
```bash
file -C -m magic_file
```

50. Check magic syntax:
```bash
file -c magic_file
```
