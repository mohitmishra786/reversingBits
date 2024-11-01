# IDA Pro CLI Cheatsheet

## Installation Guide

### Windows
1. Download IDA Pro from the official website
2. Run the installer executable
3. Add IDA Pro directory to system PATH:
   - Right-click on 'This PC' → Properties
   - Click 'Advanced system settings'
   - Click 'Environment Variables'
   - Under System Variables, find PATH
   - Add IDA Pro installation directory

### Linux
```bash
# Extract the archive
tar -xf idapro_[version]_linux.tar.gz

# Move to /opt
sudo mv idapro /opt/

# Create symbolic links
sudo ln -s /opt/idapro/idat64 /usr/local/bin/idat64
sudo ln -s /opt/idapro/idat /usr/local/bin/idat
```

### macOS
```bash
# Extract the archive
tar -xf idapro_[version]_mac.tar.gz

# Move to Applications
mv idapro /Applications/

# Add to PATH in ~/.zshrc or ~/.bash_profile
echo 'export PATH="/Applications/idapro:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

## Basic Commands

### Analysis Commands

| Command | Usage | Purpose |
|---------|--------|---------|
| `-A` | `idat64 -A file.exe` | Auto analyze file |
| `-B` | `idat64 -B file.exe` | Batch mode (no interface) |
| `-c` | `idat64 -c file.exe` | Create database only |
| `-p<type>` | `idat64 -ppc file.exe` | Specify processor type |
| `-S<script>` | `idat64 -S"script.idc" file.exe` | Execute IDC/Python script |

### Database Operations

| Command | Usage | Purpose |
|---------|--------|---------|
| `-T<format>` | `idat64 -Thex file.idb` | Specify output format |
| `-o<file>` | `idat64 -o output.idb input.exe` | Specify output file |
| `-P+` | `idat64 -P+ file.exe` | Load debugging info |
| `-iPATH` | `idat64 -i/path/to/imports file.exe` | Specify import directory |
| `-b` | `idat64 -b file.exe` | Don't save database |

### Script Integration

| Command | Usage | Purpose |
|---------|--------|---------|
| `-OIDAPython` | `idat64 -OIDAPython:script.py file.exe` | Run Python script |
| `-OIDC` | `idat64 -OIDC:script.idc file.exe` | Run IDC script |
| `-S"cmd"` | `idat64 -S"PrintEntryPoint()" file.exe` | Execute IDC command |
| `-Llog.txt` | `idat64 -Llog.txt file.exe` | Log output to file |
| `-Q` | `idat64 -Q file.exe` | Quick analysis |

### Export Commands

| Command | Usage | Purpose |
|---------|--------|---------|
| `-Otext` | `idat64 -Otext:output.txt file.idb` | Export as text |
| `-Ohex` | `idat64 -Ohex:output.hex file.idb` | Export as hex |
| `-Oasm` | `idat64 -Oasm:output.asm file.idb` | Export as assembly |
| `-Oc` | `idat64 -Oc:output.c file.idb` | Export as C code |
| `-Ohtml` | `idat64 -Ohtml:output.html file.idb` | Export as HTML |

### Analysis Options

| Command | Usage | Purpose |
|---------|--------|---------|
| `-a` | `idat64 -a file.exe` | Automatic analysis |
| `-p` | `idat64 -p file.exe` | Parse debug info |
| `-c` | `idat64 -c file.exe` | Create IDB only |
| `-B` | `idat64 -B file.exe` | Batch mode |
| `-M` | `idat64 -M file.exe` | No memory limit |

### Debug Commands

| Command | Usage | Purpose |
|---------|--------|---------|
| `-r` | `idat64 -r file.exe` | Remote debug server |
| `-R` | `idat64 -R file.exe` | Remote debug client |
| `-z` | `idat64 -z file.exe` | Don't compress |
| `-v` | `idat64 -v file.exe` | Verbose mode |
| `-D` | `idat64 -D file.exe` | Debug mode |

### File Type Specifications

| Command | Usage | Purpose |
|---------|--------|---------|
| `-fPE` | `idat64 -fPE file` | Force PE format |
| `-fELF` | `idat64 -fELF file` | Force ELF format |
| `-fMACH` | `idat64 -fMACH file` | Force MACH-O format |
| `-fBIN` | `idat64 -fBIN file` | Force binary format |
| `-fCOFF` | `idat64 -fCOFF file` | Force COFF format |

### Memory Options

| Command | Usage | Purpose |
|---------|--------|---------|
| `-m` | `idat64 -m file.exe` | Map files larger than 4GB |
| `-i` | `idat64 -i file.exe` | Ignore input file format |
| `-k` | `idat64 -k file.exe` | Use kernel mode paths |
| `-x` | `idat64 -x file.exe` | Extract unknown files |
| `-z` | `idat64 -z file.exe` | Don't compress idb |

### Script Automation

| Command | Usage | Purpose |
|---------|--------|---------|
| `-S<file>` | `idat64 -Sscript.py file.exe` | Run script file |
| `-t` | `idat64 -t file.exe` | Text mode interface |
| `-q` | `idat64 -q file.exe` | Quick mode |
| `-u` | `idat64 -u file.exe` | Don't update registry |
| `-n` | `idat64 -n file.exe` | No analysis |

### Advanced Options

| Command | Usage | Purpose |
|---------|--------|---------|
| `-c+` | `idat64 -c+ file.exe` | Create database with analysis |
| `-X` | `idat64 -X file.exe` | No exception handling |
| `-z+` | `idat64 -z+ file.exe` | Maximum compression |
| `-p-` | `idat64 -p- file.exe` | Don't parse debug info |
| `-a-` | `idat64 -a- file.exe` | No auto analysis |

### Network Options

| Command | Usage | Purpose |
|---------|--------|---------|
| `-N` | `idat64 -N file.exe` | No network |
| `-R<host>` | `idat64 -R127.0.0.1 file.exe` | Remote debugging host |
| `-P<port>` | `idat64 -P23946 file.exe` | Remote debugging port |
| `-j` | `idat64 -j file.exe` | Use JSON for communication |
| `-Y` | `idat64 -Y file.exe` | Accept all network certificates |

### Plugin Commands

| Command | Usage | Purpose |
|---------|--------|---------|
| `-L<dir>` | `idat64 -L/plugins file.exe` | Plugin directory |
| `-P<plugin>` | `idat64 -Pmyplugin file.exe` | Load specific plugin |
| `-O<options>` | `idat64 -Ooption=value file.exe` | Plugin options |
| `-g<group>` | `idat64 -ganalysis file.exe` | Plugin group |
| `-h` | `idat64 -h file.exe` | Show plugin help |

### Output Formatting

| Command | Usage | Purpose |
|---------|--------|---------|
| `-d` | `idat64 -d file.exe` | Don't display output |
| `-e<format>` | `idat64 -easm file.exe` | Export format |
| `-f` | `idat64 -f file.exe` | Force overwrite |
| `-l<lang>` | `idat64 -len-US file.exe` | Set language |
| `-w` | `idat64 -w file.exe` | Wait for completion |

### Database Management

| Command | Usage | Purpose |
|---------|--------|---------|
| `-k` | `idat64 -k file.exe` | Create backup |
| `-r` | `idat64 -r file.exe` | Restore backup |
| `-u` | `idat64 -u file.exe` | Update database |
| `-x` | `idat64 -x file.exe` | Extract types |
| `-y` | `idat64 -y file.exe` | Synchronize types |

### Analysis Configuration

| Command | Usage | Purpose |
|---------|--------|---------|
| `-C` | `idat64 -C file.exe` | Use custom config |
| `-I` | `idat64 -I file.exe` | No FLIRT signatures |
| `-S` | `idat64 -S file.exe` | Silent mode |
| `-T` | `idat64 -T file.exe` | Time analysis |
| `-U` | `idat64 -U file.exe` | Update signatures |

### Debugging Features

| Command | Usage | Purpose |
|---------|--------|---------|
| `-D` | `idat64 -D file.exe` | Debug mode |
| `-K` | `idat64 -K file.exe` | Kernel debugging |
| `-R` | `idat64 -R file.exe` | Remote debugging |
| `-V` | `idat64 -V file.exe` | Verbose debugging |
| `-W` | `idat64 -W file.exe` | Wait for debugger |

## Common Workflows

### Basic Analysis
```bash
# Quick analysis of a file
idat64 -A -B file.exe

# Create database with full analysis
idat64 -c+ -A file.exe

# Export analysis to text
idat64 -Otext:output.txt file.idb
```

### Scripting Workflow
```bash
# Run Python script during analysis
idat64 -S"myscript.py" file.exe

# Execute multiple commands
idat64 -S"cmd1;cmd2" file.exe

# Batch processing with log
idat64 -B -L"log.txt" file.exe
```

### Remote Debugging
```bash
# Start debug server
idat64 -R -P23946 file.exe

# Connect to debug server
idat64 -R127.0.0.1:23946 file.exe
```

## Tips and Best Practices

1. Always use `-B` for batch processing
2. Combine `-A` with `-c` for quick database creation
3. Use `-S` for automation scripts
4. Enable logging with `-L` for troubleshooting
5. Use `-M` for large files
