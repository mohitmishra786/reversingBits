# Spike Fuzzer Cheatsheet

## Installation Guide

### Linux Installation
```bash
# Download SPIKE
git clone https://github.com/guilhermeferreira/spikepp.git
cd spikepp

# Build from source
./configure
make
sudo make install
```

## Basic Spike Script Structure

### Basic Template
```c
// Basic spike script template
s_readline();
s_string("GET ");
s_string_variable("FUZZSTRING");
s_string(" HTTP/1.1\r\n");
s_string("Host: ");
s_string_variable("HOST");
s_string("\r\n\r\n");
```

### Data Types
| Type | Usage | Description |
|------|-------|-------------|
| `s_string()` | `s_string("test")` | Static string |
| `s_string_variable()` | `s_string_variable("FUZZ")` | Fuzzed string |
| `s_binary()` | `s_binary("\\x41\\x42")` | Binary data |
| `s_block_start()` | `s_block_start("block1")` | Start block |
| `s_block_end()` | `s_block_end("block1")` | End block |

## Common Functions

### String Manipulation
```c
// String functions
s_string("static string");         // Static string
s_string_variable("FUZZHERE");     // Fuzzable string
s_getString("string_name");        // Get string value
s_replaceString("old", "new");     // Replace string
```

### Numeric Operations
```c
// Numeric functions
s_binary_block_size_byte("block1");    // Block size (byte)
s_binary_block_size_word("block1");    // Block size (word)
s_binary_block_size_dword("block1");   // Block size (dword)
s_blocksize_string("block1", 2);       // String block size
```

### Block Operations
```c
// Block operations
s_block_start("block1");
    s_string("data");
s_block_end("block1");

// Size operations
s_sizevalue("block1");
s_blocksize_unsigned_string_variable("block1");
```

## Protocol Templates

### HTTP Template
```c
// HTTP fuzzing template
s_string("POST /");
s_string_variable("URI");
s_string(" HTTP/1.1\r\n");
s_string("Host: ");
s_string_variable("HOST");
s_string("\r\n");
s_string("Content-Length: ");
s_blocksize_string("content", 0);
s_string("\r\n\r\n");
s_block_start("content");
    s_string_variable("DATA");
s_block_end("content");
```

### FTP Template
```c
// FTP fuzzing template
s_readline();
s_string("USER ");
s_string_variable("USERNAME");
s_string("\r\n");
s_readline();
s_string("PASS ");
s_string_variable("PASSWORD");
s_string("\r\n");
```

## Command Line Usage

### Basic Commands
```bash
# Run spike
./generic_send_tcp host port spike_script.spk

# Run with debugging
./generic_send_tcp -d host port spike_script.spk

# Set timeout
./generic_send_tcp -t 5 host port spike_script.spk
```

### Common Options
```bash
-d          # Debug mode
-t seconds  # Timeout
-p port     # Port number
-h          # Help
-r          # Random fuzzing
```

## Best Practices

### Script Development
1. Start with known good values
2. Fuzz one field at a time
3. Use appropriate block sizes
4. Handle responses properly
5. Include error checking
6. Document fuzzing points
7. Test incrementally

### Fuzzing Strategy
```c
// Systematic fuzzing
s_string_variable("FUZZ1");    // Primary target
s_string("static");            // Known good value
s_string_variable("FUZZ2");    // Secondary target

// Block-based fuzzing
s_block_start("test");
    s_string_variable("FUZZ");
s_block_end("test");
s_blocksize_string("test", 0);
```

## Error Handling
```c
// Basic error handling
if (spike_send_tcp() < 0) {
    printf("Send failed\n");
    exit(1);
}

// Response checking
if (spike_connect_tcp(host, port) < 0) {
    printf("Connect failed\n");
    exit(1);
}
```

## Advanced Techniques

### Custom Fuzzing Functions
```c
// Custom string generator
void custom_string_generator() {
    s_string_variable_custom("FUZZ", generator_func);
}

// Size mutations
void size_mutations() {
    s_size_plus_one();
    s_size_minus_one();
}
```

### Protocol Specific
```c
// SSL/TLS handling
s_ssl_init();
s_ssl_connect();

// UDP specific
s_udp_connection();
```

## Debugging Tips
1. Use -d flag for debugging
2. Monitor target application
3. Log all transactions
4. Check for memory leaks
5. Verify packet structure
6. Monitor system resources
7. Use network analysis tools

## Common Issues and Solutions
```text
Issue: Connection timeouts
Solution: Increase timeout value (-t)

Issue: Memory errors
Solution: Check block sizes and boundaries

Issue: Invalid packets
Solution: Verify protocol structure

Issue: Target crashes
Solution: Log crash data and packets
```
