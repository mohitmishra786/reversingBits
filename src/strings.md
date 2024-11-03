# Strings Command Cheatsheet

## Installation Instructions

### Windows
```bash
# Option 1: Download from Windows Sysinternals
# Visit: https://docs.microsoft.com/en-us/sysinternals/downloads/strings

# Option 2: Install via Chocolatey
choco install sysinternals
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

# Note: The command might be accessible as gstrings
```

## Basic Commands

1. Basic string extraction:
```bash
strings filename
```

2. Set minimum string length:
```bash
strings -n [length] filename
```

3. Show file offsets in decimal:
```bash
strings -t d filename
```

4. Show file offsets in hexadecimal:
```bash
strings -t x filename
```

## Advanced Usage

5. Search for wide character strings:
```bash
strings -e l filename  # little-endian 16-bit
strings -e b filename  # big-endian 16-bit
strings -e L filename  # little-endian 32-bit
strings -e B filename  # big-endian 32-bit
```

6. Print filename before each string:
```bash
strings -f filename
```

7. Print section header before each string:
```bash
strings --section filename
```

8. Scan entire file (not just data sections):
```bash
strings -a filename
```

## Output Manipulation

9. Output to file:
```bash
strings filename > output.txt
```

10. Find specific strings:
```bash
strings filename | grep "pattern"
```

11. Count number of strings:
```bash
strings filename | wc -l
```

12. Sort strings uniquely:
```bash
strings filename | sort -u
```

## Multiple Files

13. Process multiple files:
```bash
strings file1 file2 file3
```

14. Process all files in directory:
```bash
strings *
```

15. Recursive string search:
```bash
find . -type f -exec strings {} \;
```

## Encoding Options

16. Search for specific encoding:
```bash
strings -e s filename  # single-7-bit-byte characters (ASCII, ISO 8859)
strings -e S filename  # single-8-bit-byte characters
strings -e b filename  # 16-bit big-endian
strings -e l filename  # 16-bit little-endian
```

## Advanced Filtering

17. Show strings with context:
```bash
strings -c filename
```

18. Target specific sections:
```bash
strings --target=section_name filename
```

19. Print strings in octal:
```bash
strings -t o filename
```

20. Combine with other tools:
```bash
strings filename | grep -i "password"
strings filename | awk 'length($0)>20'
strings filename | sed 's/^/FOUND: /'
```

## Memory Analysis

21. Analyze process memory:
```bash
strings /proc/pid/mem
```

22. Analyze core dump:
```bash
strings core.dump
```

23. Analyze memory dump:
```bash
strings memory.dmp
```

## Custom Patterns

24. Find email addresses:
```bash
strings filename | grep -E "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}"
```

25. Find URLs:
```bash
strings filename | grep -E "https?://[^\s]+"
```

26. Find IP addresses:
```bash
strings filename | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
```

## Special Usage

27. Print only printable characters:
```bash
strings -tx filename
```

28. Ignore case in pattern matching:
```bash
strings filename | grep -i "pattern"
```

29. Count string occurrences:
```bash
strings filename | sort | uniq -c
```

30. Find strings between markers:
```bash
strings filename | sed -n '/START/,/END/p'
```

## Performance Options

31. Use multiple threads:
```bash
strings --threads=4 filename
```

32. Set buffer size:
```bash
strings --buffer-size=1024 filename
```

33. Process compressed files:
```bash
zcat file.gz | strings
```

## Security Analysis

34. Find potential passwords:
```bash
strings filename | grep -i "pass"
```

35. Find potential usernames:
```bash
strings filename | grep -i "user"
```

36. Find potential API keys:
```bash
strings filename | grep -E "[A-Za-z0-9]{32}"
```

## Format-Specific Analysis

37. Analyze PDF strings:
```bash
strings -a file.pdf | grep "/Uri"
```

38. Analyze ELF headers:
```bash
strings -a binary | grep "^ELF"
```

39. Find embedded scripts:
```bash
strings filename | grep -E "^#!"
```

## Output Formatting

40. Custom delimiter:
```bash
strings filename | tr '\n' ','
```

41. Remove empty lines:
```bash
strings filename | grep .
```

42. Format as JSON:
```bash
strings filename | jq -R -s 'split("\n")[:-1]'
```

## Forensics Usage

43. Timeline analysis:
```bash
strings -t d filename | grep "2024"
```

44. Find file signatures:
```bash
strings -a filename | grep -i "JFIF\|PNG\|PDF"
```

45. Extract metadata strings:
```bash
strings filename | grep -i "creator\|producer\|author"
```

## Integration with Other Tools

46. Pipe to less:
```bash
strings filename | less
```

47. Create word frequency list:
```bash
strings filename | tr ' ' '\n' | sort | uniq -c | sort -nr
```

48. Extract and decode base64:
```bash
strings filename | grep -Eo '[A-Za-z0-9+/]{40,}' | base64 -d
```

## Debugging Support

49. Find debug strings:
```bash
strings filename | grep -i "debug\|error\|warning"
```

50. Locate version strings:
```bash
strings filename | grep -i "version\|v[0-9]\.[0-9]"
```
