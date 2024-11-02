# YARA Rules Cheatsheet for Malware Analysis

## Installation Guide

### Linux/macOS
```bash
# Using package manager
sudo apt-get install yara  # Debian/Ubuntu
brew install yara         # macOS

# From source
git clone https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure
make
sudo make install
```

### Windows
```powershell
# Using Chocolatey
choco install yara

# Using Python (platform-independent)
pip install yara-python
```

## Basic Rule Structure

### Rule Template
```yara
rule RuleName
{
    meta:
        author = "Analyst Name"
        description = "Malware description"
        date = "2024-01-01"
        hash = "SHA256 hash"
    
    strings:
        $string1 = "suspicious string"
        $hex1 = { 4D 5A 90 00 }
        $regex1 = /pattern[0-9]{4}/
    
    condition:
        $string1 or $hex1 or $regex1
}
```

## String Definitions

### String Types
| Type | Example | Description |
|------|---------|-------------|
| Text | `$s1 = "malware"` | Plain text string |
| Hex | `$h1 = { 4D 5A }` | Hexadecimal pattern |
| Regex | `$r1 = /mal[0-9]+/` | Regular expression |

### String Modifiers
| Modifier | Example | Purpose |
|----------|---------|---------|
| nocase | `$s1 = "malware" nocase` | Case-insensitive |
| wide | `$s1 = "malware" wide` | Unicode strings |
| ascii | `$s1 = "malware" ascii` | ASCII strings |
| fullword | `$s1 = "mal" fullword` | Full word match |

## Conditions

### Basic Operators
| Operator | Example | Description |
|----------|---------|-------------|
| and | `$s1 and $s2` | Both conditions |
| or | `$s1 or $s2` | Either condition |
| not | `not $s1` | Negation |
| at | `$s1 at 0x1000` | Position match |

### Count Operations
```yara
condition:
    #s* > 5           // More than 5 strings
    #s1 > 2           // String appears more than twice
    @s1[1] < @s2[1]   // Position comparison
```

### File Properties
```yara
condition:
    filesize < 1MB
    entrypoint == 0x1000
    uint16(0) == 0x5A4D    // MZ header
```

## Advanced Features

### Private Rules
```yara
private rule InternalRule
{
    condition:
        true
}

rule PublicRule
{
    condition:
        InternalRule
}
```

### Global Rules
```yara
global rule GlobalRule
{
    condition:
        true
}
```

### Rule Sets
```yara
include "./other_rules.yar"

rule SetExample
{
    condition:
        OtherRule and ThisRule
}
```

## Command Line Usage

### Basic Scanning
```bash
# Scan single file
yara rule.yar target_file

# Scan directory
yara -r rule.yar directory/

# Output matches only
yara -c rule.yar target
```

### Advanced Options
| Option | Usage | Purpose |
|--------|-------|---------|
| `-s` | `yara -s rule.yar file` | Print matching strings |
| `-m` | `yara -m rule.yar file` | Print metadata |
| `-d` | `yara -d var=value` | Define external variable |
| `-t` | `yara -t rule.yar file` | Print tags |

## Performance Optimization

### Fast Matching
```yara
rule FastRule
{
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and filesize < 1MB
}
```

### Memory Usage
```bash
# Limit memory usage
yara --stack-size=32MB rule.yar target
```

## Integration Examples

### Python Integration
```python
import yara

# Compile rules
rules = yara.compile(filepath='rules.yar')

# Match file
matches = rules.match('target_file')

# Process matches
for match in matches:
    print(f"Rule: {match.rule}")
    print(f"Tags: {match.tags}")
    print(f"Strings: {match.strings}")
```

### Command Line Integration
```bash
# Pipe results to other tools
yara rules.yar suspicious_file | grep "DETECTED"

# Use with find
find . -type f -exec yara rules.yar {} \;
```

## Best Practices

### Rule Writing
1. Use descriptive rule names
2. Include comprehensive metadata
3. Start with specific patterns
4. Use condition combinations
5. Test against known samples

### Performance Tips
1. Use `at` operator when possible
2. Limit string count
3. Use filesize checks early
4. Avoid complex regex
5. Use private rules for common patterns
