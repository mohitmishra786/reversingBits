# GAS (GNU Assembler) Comprehensive Cheatsheet

## Installation Instructions

### Windows
```powershell
# Using MSYS2
pacman -S mingw-w64-x86_64-gcc
# Or install via MinGW
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install gcc-multilib binutils
```

### macOS
```bash
# Using Homebrew
brew install gcc
brew install binutils
```

## Essential GAS Assembly Directives and Instructions

### Basic Syntax and Directives

1. **Basic Instruction Syntax**
```gas
instruction source, destination
```

2. **Define Byte**
```gas
.byte 42         # 8-bit value
.byte 'A'        # Character literal
```

3. **Define Word (16-bit)**
```gas
.word 1000       # 16-bit integer
```

4. **Define Long (32-bit)**
```gas
.long 65536      # 32-bit integer
```

5. **Define Quad (64-bit)**
```gas
.quad 1000000    # 64-bit integer
```

6. **Reserving Memory Space**
```gas
.comm buffer, 100  # Reserve 100 bytes of uninitialized memory
```

7. **Global Symbol Declaration**
```gas
.globl main      # Make symbol visible globally
```

8. **External Symbol Import**
```gas
.extern printf   # Import external function
```

### Register Operations

9. **64-bit Register Move**
```gas
movq $42, %rax   # Move immediate to 64-bit register
```

10. **32-bit Register Move**
```gas
movl $100, %eax  # Move immediate to 32-bit register
```

11. **Register to Register Move**
```gas
movq %rbx, %rax  # Copy value from rbx to rax
```

12. **Memory to Register Move**
```gas
movq (address), %rax  # Move from memory to register
```

### Arithmetic Operations

13. **Addition**
```gas
addq $10, %rax   # Add 10 to rax
```

14. **Subtraction**
```gas
subq $5, %rbx    # Subtract 5 from rbx
```

15. **Multiplication**
```gas
imulq %rcx       # Multiply rax by rcx
```

16. **Division**
```gas
idivq %rdx       # Divide rax by rdx
```

### Comparison and Branching

17. **Compare Instructions**
```gas
cmpq %rax, %rbx  # Compare rax and rbx
```

18. **Conditional Jumps**
```gas
je label         # Jump if equal
jne label        # Jump if not equal
jg label         # Jump if greater
jl label         # Jump if less
```

### Stack Operations

19. **Push to Stack**
```gas
pushq %rax       # Push rax onto stack
```

20. **Pop from Stack**
```gas
popq %rbx        # Pop top of stack to rbx
```

### System Calls (Linux x86_64)

21. **Exit System Call**
```gas
movq $60, %rax   # Exit syscall number
movq $0, %rdi    # Exit status
syscall          # Invoke syscall
```

22. **Write System Call**
```gas
movq $1, %rax    # Write syscall
movq $1, %rdi    # Stdout
movq $message, %rsi  # Buffer
movq $14, %rdx   # Length
syscall
```

### Macro Definitions

23. **Simple Macro**
```gas
.macro print_msg
    movq $1, %rax
    movq $1, %rdi
    movq $message, %rsi
    movq $14, %rdx
    syscall
.endm
```

### Conditional Assembly

24. **Preprocessor Conditionals**
```gas
#ifdef DEBUG
    # Debug-specific code
#endif
```

### Advanced Memory Operations

25. **Indirect Addressing**
```gas
movq (%rax), %rbx  # Move value pointed by rax to rbx
```

26. **Base + Displacement Addressing**
```gas
movq 8(%rsp), %rax  # Move value 8 bytes above stack pointer
```

### Floating Point Operations

27. **SSE Floating Point Move**
```gas
movsd x(%rip), %xmm0  # Move double precision float
```

### String Operations

28. **String Copy**
```gas
rep movsb        # Repeat move string byte
```

### Bit Manipulation

29. **Shift Left**
```gas
shlq $2, %rax    # Shift left by 2 bits
```

30. **Shift Right**
```gas
shrq $1, %rbx    # Shift right by 1 bit
```

## Compilation and Linking

### 32-bit Compilation
```bash
as -o output.o input.s
ld -o program output.o
```

### 64-bit Compilation
```bash
gcc -c input.s -o output.o
gcc output.o -o program
```

## Best Practices

- Use AT&T syntax consistently
- Be mindful of register sizes
- Comment your code thoroughly
- Handle potential overflow scenarios
- Use appropriate addressing modes

## Common Debugging Tips

- Use `-g` flag for debugging symbols
- Leverage `gdb` for step-by-step execution
- Check register states during debugging
- Understand memory layout and alignment
