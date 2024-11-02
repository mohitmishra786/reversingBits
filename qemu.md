# QEMU Cheatsheet for Binary Analysis & Emulation

## Installation
```bash
# Ubuntu/Debian
sudo apt install qemu-system-* qemu-user
# Arch Linux
sudo pacman -S qemu qemu-arch-extra
# macOS
brew install qemu
```

## Basic Usage
### System Emulation
```bash
# Create disk image
qemu-img create -f qcow2 disk.qcow2 20G

# Boot from ISO
qemu-system-x86_64 \
    -hda disk.qcow2 \
    -cdrom os.iso \
    -m 2048 \
    -enable-kvm \
    -boot d

# Basic system emulation
qemu-system-x86_64 \
    -hda disk.img \
    -m 2048 \
    -nographic \
    -net user \
    -net nic
```

### User-Mode Emulation
```bash
# Run ARM binary on x86
qemu-arm ./arm_binary

# Run with arguments
qemu-arm -L /path/to/arm/libs ./arm_binary arg1 arg2

# Debug with GDB
qemu-arm -g 1234 ./arm_binary
```

## Monitor Commands
### Basic Monitor
```
info cpus           # Show CPU info
info registers      # Display registers
info mem            # Memory information
info mtree          # Memory mapping
info blocks         # Show blocks
info snapshots      # List snapshots
```

### VM Control
```
stop               # Pause VM
cont               # Continue VM
system_reset       # Reset VM
quit               # Exit QEMU
savevm name        # Create snapshot
loadvm name        # Load snapshot
delvm name         # Delete snapshot
```

## Debugging Features
### GDB Integration
```bash
# Start QEMU with GDB server
qemu-system-x86_64 -s -S [other options]

# Connect with GDB
$ gdb
(gdb) target remote localhost:1234
(gdb) continue
```

### Memory Analysis
```
# Monitor commands
xp /fmt addr       # Physical memory examination
x /fmt addr        # Virtual memory examination
memsave addr size file  # Save memory to file
pmemsave addr size file # Save physical memory
```

## Network Configuration
### User Mode
```bash
# Basic NAT networking
-net user \
-net nic

# Port forwarding
-net user,hostfwd=tcp::2222-:22 \
-net nic
```

### Tap Interface
```bash
# Create tap interface
sudo tunctl -u $USER -t tap0
sudo ip link set tap0 up

# Use tap interface
-netdev tap,id=net0,ifname=tap0,script=no \
-device e1000,netdev=net0
```

## Advanced Features
### CPU/Machine Options
```bash
# Specify CPU model
-cpu model

# SMP configuration
-smp cores=4,threads=2

# Machine type
-machine type=pc,accel=kvm
```

### Disk Operations
```bash
# Convert disk formats
qemu-img convert -f raw -O qcow2 disk.img disk.qcow2

# Resize disk
qemu-img resize disk.qcow2 +10G

# Show disk info
qemu-img info disk.qcow2
```

## Binary Analysis Features
### Tracing
```bash
# Instruction tracing
-d in_asm,cpu

# Enable logging
-D trace.log

# Trace specific events
-trace events=cpu_*
```

### Record & Replay
```bash
# Record execution
-icount shift=7,rr=record,rrfile=replay.bin

# Replay execution
-icount shift=7,rr=replay,rrfile=replay.bin
```

## QEMU TCG (Tiny Code Generator)
### Custom Instructions
```c
// Define custom instruction
static void gen_custom_insn(DisasContext *ctx)
{
    TCGv temp = tcg_temp_new();
    // Generate intermediate code
    tcg_gen_movi_tl(temp, 0x1234);
    tcg_temp_free(temp);
}
```

## Device Emulation
### Custom Devices
```c
// Basic device structure
typedef struct {
    DeviceState parent_obj;
    // Device specific fields
} CustomDevice;

// Device class
static const VMStateDescription custom_vmsd = {
    .name = "custom",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_END_OF_LIST()
    }
};
```

## Performance Optimization
### KVM Acceleration
```bash
# Enable KVM
-enable-kvm

# CPU passthrough
-cpu host

# Memory optimization
-mem-path /dev/hugepages
```

## Common Analysis Tasks
### Binary Instrumentation
```python
# QEMU plugin example
def plugin_init():
    atexit(plugin_exit)
    # Register callbacks
    qemu.set_inst_callback(inst_cb)

def inst_cb(addr, size):
    # Handle instruction execution
    print(f"Executing: 0x{addr:x}")
```

### Memory Monitoring
```bash
# Track memory access
-trace events=memory_*

# Memory watchpoints
(qemu) watch 0x12345678
```

## Tips & Best Practices
### Performance
1. Use KVM when possible
```bash
-enable-kvm -cpu host
```

2. Optimize disk I/O
```bash
-drive file=disk.img,cache=writeback
```

3. Memory optimization
```bash
-mem-prealloc
-numa node,memdev=mem
```

### Debugging
1. Save/Load VM state
```
savevm checkpoint1
loadvm checkpoint1
```

2. Debug output
```bash
-d cpu_reset,in_asm,op,op_opt
-D debug.log
```

3. Network debugging
```bash
-netdump file.pcap
-object filter-dump,id=dump0,netdev=net0
```

### Security Analysis
1. Enable address sanitizer
```bash
-sanitize address
```

2. Memory checking
```bash
-trace memory=on
-trace memory_access=on
```

3. Syscall tracing
```bash
-strace
```
