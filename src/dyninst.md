# Dyninst Binary Instrumentation Cheatsheet

## Installation Guide

### Prerequisites
```bash
# Debian/Ubuntu
sudo apt-get install build-essential cmake libelf-dev libdw-dev \
    libboost-all-dev libiberty-dev

# Fedora/RHEL
sudo dnf install elfutils-devel boost-devel binutils-devel
```

### Building from Source
```bash
git clone https://github.com/dyninst/dyninst.git
cd dyninst
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

## Basic API Usage

### Program Loading
```cpp
#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"

BPatch bpatch;
BPatch_addressSpace *app = bpatch.openBinary("./program");
```

### Function Analysis
```cpp
// Get image
BPatch_image *appImage = app->getImage();

// Find functions
vector<BPatch_function *> functions;
appImage->findFunction("main", functions);

// Get entry point
BPatch_function *mainFunction = functions[0];
BPatch_Vector<BPatch_point *> *entries = mainFunction->findPoint(BPatch_entry);
```

## Instrumentation Types

### Function Entry/Exit
```cpp
// Insert at function entry
BPatch_point *entryPoint = entries->at(0);
BPatchSnippetHandle *handle = app->insertSnippet(
    snippet, *entryPoint);

// Insert at function exit
BPatch_Vector<BPatch_point *> *exits = 
    mainFunction->findPoint(BPatch_exit);
```

### Memory Access
```cpp
// Find memory accesses
BPatch_Vector<BPatch_point *> *reads = 
    mainFunction->findPoint(BPatch_memRead);
BPatch_Vector<BPatch_point *> *writes = 
    mainFunction->findPoint(BPatch_memWrite);
```

## Common Operations

### Creating Snippets
```cpp
// Create function call snippet
vector<BPatch_function *> printfFuncs;
appImage->findFunction("printf", printfFuncs);
BPatch_function *printfFunc = printfFuncs[0];

// Create parameters
BPatch_Vector<BPatch_snippet *> args;
args.push_back(BPatch_constExpr("Hello\n"));

// Create call
BPatch_funcCallExpr printfCall(*printfFunc, args);
```

### Variable Access
```cpp
// Find variable
BPatch_variableExpr *var = 
    appImage->findVariable("globalVar");

// Read variable
BPatch_snippet *readVar = 
    new BPatch_varExpr(*var);

// Write variable
BPatch_snippet *writeVar = 
    new BPatch_arithExpr(BPatch_assign, 
        *var, BPatch_constExpr(42));
```

## Advanced Features

### Process Control
```cpp
// Create process
BPatch_process *proc = 
    bpatch.processCreate("./program", argv);

// Attach to process
BPatch_process *proc = 
    bpatch.processAttach("program", pid);

// Continue execution
proc->continueExecution();

// Terminate process
proc->terminateExecution();
```

### Binary Rewriting
```cpp
// Create binary rewriter
BPatch_binaryEdit *appBin = 
    bpatch.openBinary("program", true);

// Save modified binary
appBin->writeFile("program.modified");
```

## Error Handling
```cpp
// Set error callback
BPatch::setErrorCallback(errorFunc);

// Error handling function
void errorFunc(BPatchErrorLevel level, 
    int num, const char* const* params) {
    // Handle error
}
```

## Best Practices
1. Always check function lookup results
2. Use error callbacks
3. Clean up resources properly
4. Handle instrumentation failures
5. Test on small programs first
6. Back up binaries before modification
7. Use appropriate instrumentation points

## Common Patterns

### Function Wrapping
```cpp
// Find target function
vector<BPatch_function *> funcs;
appImage->findFunction("targetFunc", funcs);

// Create wrapper
BPatch_function *wrapper = 
    createWrapperFunction(funcs[0]);

// Replace calls
replaceCallSites(funcs[0], wrapper);
```

### Performance Monitoring
```cpp
// Insert timing code
BPatch_timestamp startTime;
insertSnippet(startTime, entry);

BPatch_timestamp endTime;
insertSnippet(endTime, exit);

// Calculate duration
BPatch_arithExpr duration(BPatch_subtract, 
    endTime, startTime);
```

## Debugging Tips
1. Use BPatch debug flags
2. Check symbol table availability
3. Verify function signatures
4. Monitor memory usage
5. Test instrumentations incrementally
6. Use process tracing
7. Validate binary modifications

## Performance Considerations
1. Minimize instrumentation points
2. Use efficient snippets
3. Batch modifications
4. Consider overhead
5. Use appropriate analysis levels
6. Cache commonly used data
7. Clean up unused instruments
