# PEDA: Python Exploit Development Assistance for GDB

PEDA is a Python script that enhances the GDB debugger with additional functionality for reverse engineering.

## Installation

To install PEDA, follow these steps:

1. Clone the PEDA repository:
   ```
   git clone https://github.com/longld/peda.git ~/peda
   ```
2. Add the following lines to your `.gdbinit` file:
   ```
   source ~/peda/peda.py
   ```

## Usage

PEDA provides a range of commands and features to enhance the GDB debugging experience:

| Command | Description |
| --- | --- |
| `peda`        | Toggle PEDA mode |
| `aslr`        | Toggle ASLR |
| `checksec`    | Check security measures of the binary |
| `pattern_create` | Create a unique pattern |
| `pattern_search` | Search for a pattern in memory |
| `pattern_offset` | Find the offset of a pattern |
| `dump`        | Dump memory to a file |
| `rop`         | Find ROP gadgets |
| `skeleton`    | Generate a skeleton exploit script |
| `shellcode`   | Generate shellcode for a given architecture |
| `trace`       | Trace the execution of a function |
| `dumpargs`    | Display the arguments passed to a function |
| `dumpret`     | Display the return value of a function |
| `context`     | Display context information (registers, stack, etc.) |
| `xinfo`       | Display extended information about a variable or address |

For more detailed information and usage examples, please refer to the PEDA documentation: https://github.com/longld/peda