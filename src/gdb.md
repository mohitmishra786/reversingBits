# GDB (GNU Debugger) Cheatsheet

## Installation Instructions

### Windows
```powershell
# Using Chocolatey
choco install mingw

# Using MSYS2
pacman -S mingw-w64-x86_64-gdb
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install gdb
```

### macOS
```bash
# Using Homebrew
brew install gdb
# Note: Additional signing steps required for macOS
```

## Basic GDB Commands

### Starting GDB

1. **Launch GDB**
```bash
gdb program
```

2. **Attach to Running Process**
```bash
gdb -p PID
```

3. **Start with Arguments**
```bash
gdb --args program arg1 arg2
```

### Running and Stopping

4. **Run Program**
```gdb
run
run arg1 arg2
```

5. **Continue Execution**
```gdb
continue
c
```

6. **Step Into**
```gdb
step
s
```

7. **Step Over**
```gdb
next
n
```

8. **Step Out**
```gdb
finish
```

### Breakpoints

9. **Set Breakpoint at Function**
```gdb
break function_name
b main
```

10. **Set Breakpoint at Line**
```gdb
break filename:linenum
b 42
```

11. **Set Breakpoint at Address**
```gdb
break *0x4004e7
```

12. **List Breakpoints**
```gdb
info breakpoints
i b
```

13. **Delete Breakpoint**
```gdb
delete 1
d 1
```

14. **Enable/Disable Breakpoint**
```gdb
enable 1
disable 1
```

### Memory Examination

15. **Examine Memory**
```gdb
x/nfu addr
x/10x $rsp    # Show 10 hex words at stack pointer
```

16. **Print Variable**
```gdb
print variable
p $rax
```

17. **Display Memory Change**
```gdb
display/i $pc
```

### Stack Navigation

18. **Backtrace**
```gdb
backtrace
bt
```

19. **Select Frame**
```gdb
frame n
f n
```

20. **Show Arguments**
```gdb
info args
```

### Register Operations

21. **Show Registers**
```gdb
info registers
i r
```

22. **Show Specific Register**
```gdb
p $rax
info registers rax
```

### Data Display

23. **Print Array**
```gdb
p *array@length
```

24. **Print String**
```gdb
x/s string_ptr
```

25. **Print Struct**
```gdb
p *struct_ptr
```

### Watchpoints

26. **Watch Variable**
```gdb
watch variable
```

27. **Watch Memory Location**
```gdb
watch *0x4004e7
```

28. **Watch Expression**
```gdb
watch expr
```

### Source Code Navigation

29. **List Source**
```gdb
list
l
```

30. **List Function**
```gdb
list function_name
```

### Advanced Features

31. **Define Command Alias**
```gdb
define mycommand
commands
end
```

32. **Python Scripting**
```gdb
python
def print_rax():
    rax = gdb.selected_frame().read_register("rax")
    print(f"RAX = {rax}")
end
```

33. **Remote Debugging**
```gdb
target remote localhost:1234
```

### Reverse Debugging

34. **Record Execution**
```gdb
record
```

35. **Reverse Continue**
```gdb
reverse-continue
rc
```

36. **Reverse Step**
```gdb
reverse-step
rs
```

### Process Information

37. **Show Loaded Libraries**
```gdb
info sharedlibrary
```

38. **Show Threads**
```gdb
info threads
```

39. **Switch Thread**
```gdb
thread thread_num
```

### Advanced Analysis

40. **Disassemble Function**
```gdb
disassemble function_name
```

41. **Set Architecture**
```gdb
set architecture i386
```

42. **Memory Mapping**
```gdb
info proc mappings
```

### Convenience Variables

43. **Last Value**
```gdb
print $
```

44. **Define Variable**
```gdb
set $count = 0
```

### File Operations

45. **Load Symbols**
```gdb
symbol-file file
```

46. **Add Symbol File**
```gdb
add-symbol-file file address
```

## Advanced Usage Examples

### Binary Analysis
```gdb
# Analyze function call
catch syscall
commands
  print $rax
  continue
end
```

### Memory Analysis
```gdb
# Find memory leaks
define leak_check
  set $start = 0
  while $start < 0x7fffffffffff
    if *(void**)$start != 0
      print $start
    end
    set $start = $start + 8
  end
end
```

### Debugging Helpers
```gdb
# Print stack trace on segfault
catch signal SIGSEGV
commands
  where
end
```

## Best Practices

### Performance Tips
- Use hardware breakpoints for watching memory
- Avoid excessive printing in loops
- Use conditional breakpoints wisely

### Security Analysis
- Check for ASLR: `show disable-randomization`
- Examine security mitigations
- Use catchpoints for syscall analysis

### Automation
- Create .gdbinit file
- Use Python scripts for complex analysis
- Save common command sequences

## Common Issues and Solutions

### Memory Access
```gdb
# Handle invalid memory access
handle SIGSEGV nostop noprint
```

### Symbol Loading
```gdb
# Fix missing symbols
set sysroot /path/to/sysroot
```

### Multi-threaded Debugging
```gdb
# Follow fork mode
set follow-fork-mode child
```

## Advanced Configuration

### Custom Prompt
```gdb
set prompt (gdb-custom) 
```

### History Settings
```gdb
set history save on
set history filename ~/.gdb_history
```

### Pretty Printing
```gdb
set print pretty on
set print array on
```
