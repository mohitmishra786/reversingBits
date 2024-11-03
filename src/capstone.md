# Capstone Disassembler Cheatsheet

## Installation Instructions

### All Platforms - Python
```bash
pip install capstone
```

### Windows
```bash
# Using vcpkg
vcpkg install capstone

# Using Chocolatey
choco install capstone
```

### Linux
```bash
# Debian/Ubuntu
sudo apt-get install libcapstone-dev python3-capstone

# RHEL/CentOS
sudo yum install capstone-devel python3-capstone

# Arch Linux
sudo pacman -S capstone python-capstone
```

### macOS
```bash
brew install capstone
pip3 install capstone
```

## Basic Python Usage

1. Initialize Capstone:
```python
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
```

2. Basic disassembly:
```python
CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
for i in md.disasm(CODE, 0x1000):
    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
```

## Architecture Selection

3. ARM disassembly:
```python
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
```

4. MIPS disassembly:
```python
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
```

5. PowerPC disassembly:
```python
md = Cs(CS_ARCH_PPC, CS_MODE_32)
```

## Mode Configuration

6. 32-bit mode:
```python
md = Cs(CS_ARCH_X86, CS_MODE_32)
```

7. ARM thumb mode:
```python
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
```

8. Big endian mode:
```python
md = Cs(CS_ARCH_ARM, CS_MODE_BIG_ENDIAN)
```

## Detailed Analysis

9. Get instruction details:
```python
for i in md.disasm(CODE, 0x1000, count=1):
    print(f"ID: {i.id}")
    print(f"Size: {i.size}")
    print(f"Bytes: {i.bytes}")
```

10. Access operands:
```python
for i in md.disasm(CODE, 0x1000):
    for op in i.operands:
        print(f"Operand: {op.type}")
```

## Advanced Features

11. Skip data:
```python
md.skipdata = True
md.skipdata_setup = ("db", None, None)
```

12. Set syntax:
```python
md.syntax = CS_OPT_SYNTAX_ATT  # AT&T syntax
```

13. Enable detail mode:
```python
md.detail = True
```

## Memory Operations

14. Analyze memory references:
```python
for i in md.disasm(CODE, 0x1000):
    if i.op_str.find('[') != -1:
        print(f"Memory reference: {i.op_str}")
```

15. Get memory operands:
```python
for i in md.disasm(CODE, 0x1000):
    if len(i.operands) > 0:
        for op in i.operands:
            if op.type == CS_OP_MEM:
                print(f"Base: {op.mem.base}")
                print(f"Index: {op.mem.index}")
                print(f"Scale: {op.mem.scale}")
```

## Register Analysis

16. Get register name:
```python
reg_name = md.reg_name(reg_id)
```

17. Get register groups:
```python
for i in md.disasm(CODE, 0x1000):
    if len(i.regs_read) > 0:
        print("Registers read:", [md.reg_name(x) for x in i.regs_read])
```

## Error Handling

18. Check for errors:
```python
if md.errno != CS_ERR_OK:
    print(f"Error: {md.errno}")
```

19. Error handling wrapper:
```python
try:
    for i in md.disasm(CODE, 0x1000):
        print(f"{i.mnemonic} {i.op_str}")
except CsError as e:
    print(f"Error: {e}")
```

## Instruction Groups

20. Get instruction groups:
```python
for i in md.disasm(CODE, 0x1000):
    if len(i.groups) > 0:
        print("Groups:", i.groups)
```

## Advanced Options

21. Set option:
```python
md.set_option(CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL)
```

22. Get option:
```python
syntax = md.get_option(CS_OPT_SYNTAX)
```

## Binary Analysis

23. Analyze function:
```python
def analyze_function(code, address):
    for i in md.disasm(code, address):
        if i.group(CS_GRP_CALL):
            print(f"Call at 0x{i.address:x}")
```

24. Find specific instructions:
```python
def find_instruction(code, mnemonic):
    return [i for i in md.disasm(code, 0) if i.mnemonic == mnemonic]
```

## Control Flow Analysis

25. Identify jumps:
```python
def find_jumps(code, address):
    jumps = []
    for i in md.disasm(code, address):
        if i.group(CS_GRP_JUMP):
            jumps.append(i)
    return jumps
```

## Integration Examples

26. With Binary Ninja:
```python
def capstone_to_binja(instruction):
    return {
        'address': instruction.address,
        'size': instruction.size,
        'mnemonic': instruction.mnemonic,
        'op_str': instruction.op_str
    }
```

27. With IDA Pro:
```python
def ida_to_capstone(ea, size):
    bytes = get_bytes(ea, size)
    return next(md.disasm(bytes, ea))
```

## Performance Optimization

28. Batch processing:
```python
def process_batch(code, batch_size=1000):
    for i in range(0, len(code), batch_size):
        batch = code[i:i+batch_size]
        for insn in md.disasm(batch, 0x1000 + i):
            yield insn
```

29. Iterator usage:
```python
iterator = md.disasm_lite(CODE, 0x1000)
```

## Custom Formatting

30. Custom output format:
```python
def format_instruction(insn):
    return f"{insn.address:08x}: {insn.mnemonic:8} {insn.op_str}"
```

## Debugging Support

31. Print all details:
```python
def print_instruction_details(insn):
    print(f"Address: 0x{insn.address:x}")
    print(f"Mnemonic: {insn.mnemonic}")
    print(f"Op str: {insn.op_str}")
    print(f"Size: {insn.size}")
    print(f"Bytes: {insn.bytes.hex()}")
```

## File Analysis

32. Analyze binary file:
```python
def analyze_file(filename):
    with open(filename, 'rb') as f:
        code = f.read()
        for i in md.disasm(code, 0x0):
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
```

## Statistics

33. Instruction statistics:
```python
def get_statistics(code):
    stats = {}
    for i in md.disasm(code, 0):
        stats[i.mnemonic] = stats.get(i.mnemonic, 0) + 1
    return stats
```

## Advanced Analysis

34. Function boundary detection:
```python
def find_function_end(code, start):
    for i in md.disasm(code[start:], 0):
        if i.mnemonic == 'ret':
            return start + i.address
```

35. Cross references:
```python
def find_xrefs(code, target):
    xrefs = []
    for i in md.disasm(code, 0):
        if i.op_str.find(hex(target)) != -1:
            xrefs.append(i.address)
    return xrefs
```

## Special Instructions

36. Check for privileged instructions:
```python
def check_privileged(code):
    privileged = []
    for i in md.disasm(code, 0):
        if i.group(CS_GRP_PRIVILEGE):
            privileged.append(i)
    return privileged
```

37. Find system calls:
```python
def find_syscalls(code):
    return [i for i in md.disasm(code, 0) if i.mnemonic == 'syscall']
```

## Stack Analysis

38. Track stack operations:
```python
def analyze_stack(code):
    stack_delta = 0
    for i in md.disasm(code, 0):
        if i.mnemonic == 'push':
            stack_delta -= 8
        elif i.mnemonic == 'pop':
            stack_delta += 8
    return stack_delta
```

## Pattern Matching

39. Find instruction patterns:
```python
def find_pattern(code, pattern):
    results = []
    for i in md.disasm(code, 0):
        if all(getattr(i, attr) == value for attr, value in pattern.items()):
            results.append(i)
    return results
```

40. Match instruction sequence:
```python
def match_sequence(code, sequence):
    matches = []
    buffer = []
    for i in md.disasm(code, 0):
        buffer.append(i)
        if len(buffer) == len(sequence):
            if all(b.mnemonic == s for b, s in zip(buffer, sequence)):
                matches.append(buffer[0].address)
            buffer.pop(0)
    return matches
```

## Export and Integration

41. Export to JSON:
```python
import json
def export_to_json(instructions):
    return json.dumps([{
        'address': i.address,
        'mnemonic': i.mnemonic,
        'op_str': i.op_str
    } for i in instructions])
```
