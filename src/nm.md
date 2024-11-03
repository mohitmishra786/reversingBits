# nm (Name List) Command Cheatsheet

## Installation Instructions

### Windows
```bash
# Using MinGW
pacman -S binutils    # If using MSYS2
# Or via Chocolatey
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
# Command might be available as 'gnm'
```

## Basic Usage

1. List all symbols:
```bash
nm binary_file
```

2. Show dynamic symbols:
```bash
nm -D binary_file
```

3. Show debug symbols:
```bash
nm --debug-syms binary_file
```

## Symbol Types and Filtering

4. Show only external symbols:
```bash
nm -g binary_file
```

5. Show only undefined symbols:
```bash
nm -u binary_file
```

6. Show only defined symbols:
```bash
nm -U binary_file
```

7. Sort symbols by address:
```bash
nm -n binary_file
```

8. Sort symbols alphabetically:
```bash
nm -p binary_file
```

## Output Formatting

9. Display size of symbols:
```bash
nm --size-sort binary_file
```

10. Show symbol value and size:
```bash
nm --print-size binary_file
```

11. Display in BSD format:
```bash
nm -B binary_file
```

12. Display in POSIX format:
```bash
nm -P binary_file
```

## Advanced Filtering

13. Show only functions:
```bash
nm binary_file | grep -w "T"
```

14. Show only global variables:
```bash
nm binary_file | grep -w "D"
```

15. Show only static symbols:
```bash
nm binary_file | grep -w "t"
```

## Special Operations

16. Demangle C++ symbols:
```bash
nm --demangle binary_file
```

17. Show symbol types:
```bash
nm -t x binary_file
```

18. Print line numbers:
```bash
nm --line-numbers binary_file
```

## Multiple File Operations

19. Process multiple files:
```bash
nm file1.o file2.o
```

20. Show filename with symbols:
```bash
nm --print-file-name file1.o file2.o
```

## Symbol Analysis

21. Find main function:
```bash
nm binary_file | grep " main$"
```

22. List all constructors:
```bash
nm binary_file | grep "_init"
```

23. List all destructors:
```bash
nm binary_file | grep "_fini"
```

## Advanced Usage

24. Generate output in portable format:
```bash
nm -P --portability binary_file
```

25. Show synthetic symbols:
```bash
nm --synthetic binary_file
```

26. Show all symbols with addresses:
```bash
nm -A binary_file
```

## Integration with Other Tools

27. Sort by symbol size:
```bash
nm --print-size --size-sort binary_file
```

28. Format output for processing:
```bash
nm -p -g binary_file | cut -d' ' -f3
```

29. Count symbols by type:
```bash
nm binary_file | awk '{print $2}' | sort | uniq -c
```

## Specialized Analysis

30. Find weak symbols:
```bash
nm binary_file | grep " W "
```

31. List read-only data:
```bash
nm binary_file | grep " R "
```

32. Find unitialized data:
```bash
nm binary_file | grep " B "
```

## Architecture-Specific Options

33. Display 32-bit format:
```bash
nm -32 binary_file
```

34. Display 64-bit format:
```bash
nm -64 binary_file
```

35. Show target specific symbol types:
```bash
nm --target=target_type binary_file
```

## Debug Information

36. Show debugging symbols only:
```bash
nm --debug-syms binary_file
```

37. Show demangled symbols with types:
```bash
nm -C --demangle binary_file
```

38. Display symbol versions:
```bash
nm --version-info binary_file
```

## Export and Import Analysis

39. List imported functions:
```bash
nm -D --undefined-only binary_file
```

40. List exported functions:
```bash
nm -D --defined-only binary_file
```

## Symbol Classification

41. Show only private symbols:
```bash
nm --private-symbols binary_file
```

42. Show only public symbols:
```bash
nm --public-symbols binary_file
```

43. List external symbols:
```bash
nm --extern-only binary_file
```

## Special Symbol Types

44. Find thread-local symbols:
```bash
nm binary_file | grep " TLS "
```

45. List common symbols:
```bash
nm binary_file | grep " C "
```

46. Show absolute symbols:
```bash
nm binary_file | grep " A "
```

## Output Manipulation

47. Generate wide output:
```bash
nm --wide binary_file
```

48. Show numeric radix:
```bash
nm -t d binary_file  # decimal
nm -t x binary_file  # hexadecimal
nm -t o binary_file  # octal
```

## Archive Operations

49. List archive symbols:
```bash
nm --print-armap archive.a
```

50. Process all archive members:
```bash
nm --print-file-name archive.a
```
