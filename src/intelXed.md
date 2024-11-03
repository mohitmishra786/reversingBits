# Intel XED (x86 Encoder Decoder) Cheatsheet

## Installation Guide

### Building from Source
```bash
# Clone repository
git clone https://github.com/intelxed/xed.git
git clone https://github.com/intelxed/mbuild.git

# Build
cd xed
./mfile.py

# Install
sudo ./mfile.py --prefix=/usr/local install
```

## Basic Usage

### Command Line Interface
```bash
# Decode hex bytes
xed -d 90

# Decode instruction from binary
xed -i /bin/ls

# Encode assembly
xed -e MOV RAX, RBX
```

## API Usage

### Initialization
```c
#include "xed/xed-interface.h"

// Initialize the XED tables
xed_tables_init();

// Set machine mode
xed_state_t state;
xed_state_init(&state,
    XED_MACHINE_MODE_LONG_64,
    XED_ADDRESS_WIDTH_64b);
```

### Decoding
```c
// Basic decoding
xed_decoded_inst_t xedd;
xed_decoded_inst_zero(&xedd);
xed_decoded_inst_set_mode(&xedd, &state);

// Decode bytes
xed_error_enum_t err = xed_decode(&xedd, 
    bytes, length);

// Get information
xed_iclass_enum_t iclass = 
    xed_decoded_inst_get_iclass(&xedd);
```

### Encoding
```c
// Initialize encoder request
xed_encoder_request_t enc_req;
xed_encoder_request_zero_set_mode(&enc_req, &state);

// Set instruction attributes
xed_encoder_request_set_iclass(&enc_req,
    XED_ICLASS_MOV);

// Encode
unsigned char buf[XED_MAX_INSTRUCTION_BYTES];
unsigned int olen;
xed_error_enum_t err = xed_encode(&enc_req, 
    buf, XED_MAX_INSTRUCTION_BYTES, &olen);
```

## Common Operations

### Instruction Analysis
```c
// Get operands
const xed_inst_t* xi = 
    xed_decoded_inst_inst(&xedd);
xed_uint_t noperands = 
    xed_inst_noperands(xi);

// Get memory operands
xed_uint_t memops = 
    xed_decoded_inst_number_of_memory_operands(&xedd);

// Get branch info
xed_bool_t is_branch =
    xed_decoded_inst_is_branch(&xedd);
```

### Operand Access
```c
// Get operand type
const xed_operand_t* op = 
    xed_inst_operand(xi, i);
xed_operand_enum_t op_name = 
    xed_operand_name(op);

// Get register operands
xed_reg_enum_t reg = 
    xed_decoded_inst_get_reg(&xedd, op_name);
```

## Advanced Features

### Instruction Categories
```c
// Check instruction category
xed_category_enum_t category = 
    xed_decoded_inst_get_category(&xedd);

// Check ISA set
xed_isa_set_enum_t isa_set = 
    xed_decoded_inst_get_isa_set(&xedd);
```

### Memory Operands
```c
// Get memory operand info
xed_bool_t mem_read = 
    xed_decoded_inst_mem_read(&xedd, 0);
xed_bool_t mem_write = 
    xed_decoded_inst_mem_written(&xedd, 0);

// Get addressing info
xed_uint_t base_reg = 
    xed_decoded_inst_get_base_reg(&xedd, 0);
xed_uint_t index_reg = 
    xed_decoded_inst_get_index_reg(&xedd, 0);
```

## Best Practices
1. Always initialize XED tables
2. Check error codes
3. Use appropriate machine mode
4. Handle memory properly
5. Validate input data
6. Clean up resources
7. Use correct width settings

## Error Handling
```c
// Check decode errors
if (xed_error_enum_t2str(err) != XED_ERROR_NONE) {
    // Handle error
}

// Check encode errors
if (err != XED_ERROR_NONE) {
    const char* error = xed_error_enum_t2str(err);
    // Handle error
}
```

## Common Patterns

### Instruction Printing
```c
// Print instruction
char buffer[200];
xed_format_context(XED_SYNTAX_INTEL,
    &xedd, buffer, 200, 0, 0, 0);

// Print bytes
xed_print_hex_line(buffer, bytes, length);
```

### Instruction Analysis
```c
// Full instruction analysis
void analyze_instruction(xed_decoded_inst_t* xedd) {
    printf("Instruction: %s\n",
        xed_iclass_enum_t2str(
            xed_decoded_inst_get_iclass(xedd)));
    
    printf("Category: %s\n",
        xed_category_enum_t2str(
            xed_decoded_inst_get_category(xedd)));
            
    printf("ISA Set: %s\n",
        xed_isa_set_enum_t2str(
            xed_decoded_inst_get_isa_set(xedd)));
}
```

## Performance Tips
1. Reuse decoder/encoder objects
2. Use appropriate buffer sizes
3. Minimize state changes
4. Cache common operations
5. Use batch processing
6. Optimize memory usage
7. Use correct alignment

## Debugging
1. Enable debug output
2. Check state initialization
3. Verify machine mode
4. Check buffer sizes
5. Monitor memory usage
6. Validate input data
7. Track error codes
