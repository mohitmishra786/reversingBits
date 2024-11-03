# PIN (Dynamic Binary Instrumentation) Cheatsheet

## Installation Guide

### Linux
```bash
# Download PIN from Intel's website
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-VERSION-gcc-linux.tar.gz
tar -xzf pin-VERSION-gcc-linux.tar.gz
export PIN_ROOT=/path/to/pin
```

### Windows
```batch
# Download PIN from Intel's website
# Extract to C:\pin
set PIN_ROOT=C:\pin
```

## Basic Commands

### Building Tools
| Command | Usage | Purpose |
|---------|--------|---------|
| `make` | `make obj-intel64/tool.so` | Build 64-bit tool |
| `make32` | `make obj-ia32/tool.so` | Build 32-bit tool |
| `make clean` | `make clean` | Clean build files |
| `make debug` | `make DEBUG=1` | Debug build |

### Running PIN
| Command | Usage | Purpose |
|---------|--------|---------|
| `pin` | `pin -t tool.so -- program` | Run program with tool |
| `pin -follow_execv` | `pin -follow_execv -t tool.so -- program` | Follow child processes |
| `pin -pid` | `pin -pid 1234 -t tool.so` | Attach to process |
| `pin -probe` | `pin -probe -t tool.so -- program` | Use probe mode |

### Common API Functions
| Function | Usage | Purpose |
|---------|--------|---------|
| `PIN_Init()` | `int main(int argc, char* argv[])` | Initialize PIN |
| `INS_AddInstrumentFunction()` | `VOID Instruction(INS ins, VOID *v)` | Instrument instructions |
| `RTN_AddInstrumentFunction()` | `VOID Routine(RTN rtn, VOID *v)` | Instrument routines |
| `IMG_AddInstrumentFunction()` | `VOID Image(IMG img, VOID *v)` | Instrument images |

### Instrumentation Commands
| Command | Usage | Purpose |
|---------|--------|---------|
| `INS_InsertCall()` | `INS_InsertCall(ins, IPOINT_BEFORE, ...)` | Insert analysis call |
| `RTN_InsertCall()` | `RTN_InsertCall(rtn, IPOINT_BEFORE, ...)` | Insert routine call |
| `INS_Delete()` | `INS_Delete(ins)` | Delete instruction |
| `RTN_Replace()` | `RTN_Replace(rtn, rtnReplacement)` | Replace routine |

### Analysis Functions
| Function | Usage | Purpose |
|---------|--------|---------|
| `IARG_INST_PTR` | `IARG_INST_PTR` | Get instruction pointer |
| `IARG_MEMORYREAD_EA` | `IARG_MEMORYREAD_EA` | Get memory read address |
| `IARG_MEMORYWRITE_EA` | `IARG_MEMORYWRITE_EA` | Get memory write address |
| `IARG_REG_VALUE` | `IARG_REG_VALUE, REG_EAX` | Get register value |

## Common Pintool Templates

### Instruction Counter
```cpp
#include "pin.H"

UINT64 icount = 0;

VOID CountIns(void) {
    icount++;
}

VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE,
        (AFUNPTR)CountIns, IARG_END);
}

VOID Fini(INT32 code, VOID *v) {
    fprintf(stderr, "Count: %lu\n", icount);
}

int main(int argc, char * argv[]) {
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
```

### Memory Trace
```cpp
VOID RecordMemRead(VOID * ip, VOID * addr) {
    fprintf(trace, "%p: R %p\n", ip, addr);
}

VOID RecordMemWrite(VOID * ip, VOID * addr) {
    fprintf(trace, "%p: W %p\n", ip, addr);
}

VOID Instruction(INS ins, VOID *v) {
    if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)RecordMemRead,
            IARG_INST_PTR, IARG_MEMORYREAD_EA,
            IARG_END);
    }
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)RecordMemWrite,
            IARG_INST_PTR, IARG_MEMORYWRITE_EA,
            IARG_END);
    }
}
```

## Debugging Tips
1. Use `-pause_tool` for debugging
2. Enable PIN_DEBUG output
3. Check PIN.LOG for errors
4. Use PIN_SafeCopy for memory access
5. Implement proper error handling
6. Use PIN_GetTid() for thread identification
7. Check tool compatibility with PIN version

## Best Practices
1. Minimize analysis overhead
2. Use fast buffers for logging
3. Implement proper cleanup
4. Handle exceptions properly
5. Use atomic operations for threading
6. Keep instrumentation simple
7. Cache frequently used values
