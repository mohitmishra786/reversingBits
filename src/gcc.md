# GCC Commands and Compiler Flags Reference

## General Compilation Flags

| Command | Purpose |
|---------|---------|
| `gcc -c -fPIC file.c` | Generates position-independent code for shared libraries. |
| `gcc -DMACRO file.c` | Defines a macro for use in the source code. |
| `gcc -Werror file.c` | Treats all compiler warnings as errors. |
| `gcc file.c @options_file` | Reads compiler options from the specified file. |
| `gcc -s file.c -o file` | Strips symbol table and debugging info from the executable. |
| `gcc -g file.c -o file` | Includes debugging information in the executable. |
| `gcc -MM file.c` | Generates Makefile dependencies for the source file. |
| `gcc -Wall file.c` | Enables all commonly used compiler warnings. |
| `gcc -c file.c` | Compiles source code into an object file without linking. |
| `gcc -save-temps file.c` | Saves all intermediate files from compilation stages. |

---

## Compilation Stages

| Command | Purpose |
|---------|---------|
| `gcc -E file.c > file.i` | Preprocesses the source code. |
| `gcc -S file.i -o file.S` | Compiles preprocessed source to assembly code. |
| `gcc -c file.S -o file.o` | Assembles code into an object file. |
| `gcc file.o -o file` | Links object files into an executable. |

---

## Linking and Libraries

| Command | Purpose |
|---------|---------|
| `gcc file.c -o file -lcppfile` | Links the executable with the specified shared library. |
| `gcc -o res main.c libhello.a` | Links the static library into an executable. |
| `gcc -print-file-name=libc.so` | Prints the full path of the specified library. |
| `gcc -L /path/to/lib file.c -o file -lmylib` | Adds a directory to the list of library search paths. |
| `gcc -o file -Wl,--whole-archive lib.a -Wl,--no-whole-archive other.o` | Links all object files from the specified archive. |

---

## Architecture-Specific Flags

| Command | Purpose |
|---------|---------|
| `gcc -m32 file.c` | Compiles code for a 32-bit architecture. |
| `gcc -m64 file.c` | Compiles code for a 64-bit architecture. |
| `gcc -march=native file.c -o file` | Optimizes code for the build machine's CPU architecture. |
| `gcc -mavx file.c -o file` | Enables AVX instructions in the generated code. |
| `gcc -mno-sse file.c` | Uses x87 FPU registers instead of SSE instructions. |

---

## Optimization Flags

| Command | Purpose |
|---------|---------|
| `gcc -O0 file.c -o file` | Disables optimizations for easier debugging. |
| `gcc -O1 file.c -o file` | Enables basic optimizations. |
| `gcc -O2 file.c -o file` | Optimizes code for speed. |
| `gcc -O3 file.c -o file` | Aggressively optimizes code for speed. |
| `gcc -Os file.c -o file` | Optimizes code for size. |
| `gcc -fprofile-generate file.c -o file` | Generates code for profile-guided optimization. |
| `gcc -fprofile-use file.c -o file_optimized` | Uses profiling data to optimize the code. |

---

## Debugging and Profiling

| Command | Purpose |
|---------|---------|
| `gcc -g file.c -o file` | Includes debugging information in the executable. |
| `gcc -g3 file.c -o file` | Includes extensive debugging information with optimizations. |
| `gcc -fno-stack-protector file.c` | Disables stack protection mechanisms. |
| `gcc -v file.c` | Prints compilation commands and version information. |

---

## Advanced Compiler Flags

| Command | Purpose |
|---------|---------|
| `gcc -fomit-frame-pointer file.c` | Omits the frame pointer in the generated code. |
| `gcc -no-pie file.c` | Disables position-independent executables. |
| `gcc -nostdinc file.c` | Does not search standard include directories. |
| `gcc -I /path/to/include file.c -o file` | Adds a directory to the list of include file search paths. |
| `gcc -fdump-tree-all hello.c` | Dumps abstract syntax tree information. |
| `gcc test.c -o test -Wa,-adhln=test.s -g -fverbose-asm -masm=intel` | Generates assembly with embedded source code lines. |

---

## Static and Shared Libraries

| Command | Purpose |
|---------|---------|
| `gcc -c hello.c -o hello.o` | Compiles source to object file. |
| `ar -cvq libhello.a hello.o` | Creates a static library from object file. |
| `gcc -shared -o libhello.so hello.o` | Creates a shared library from object file. |
| `gcc -o res main.c -L. -lhello` | Links the executable with a shared or static library. |

---

## Miscellaneous

| Command | Purpose |
|---------|---------|
| `gcc -dumpversion` | Prints the GCC version. |
| `gcc -dM -E - < /dev/null` | Prints all predefined macros. |
| `gcc -Q --help=target` | Lists all target-specific options. |
| `gcc -Q --help=optimizers` | Lists all optimization options. |

---

## Best Practices

- **Always Use -Wall:** Enables all common warnings to catch potential issues early.
- **Use -Werror:** Treat warnings as errors to maintain clean code.
- **Optimize Carefully:** Use optimization flags appropriate for your use case.
- **Document Macros:** Clearly document any macros used with -D.
- **Understand Architecture Flags:** Be aware of the implications of architecture-specific flags.

## Reference & Further Reading

- [GCC Online Documentation](https://gcc.gnu.org/onlinedocs/)
- [GCC Compiler Flags](https://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html)
- [Creating and Using Libraries](http://www.yolinux.com/TUTORIALS/LibraryArchives-StaticAndDynamic.html)
