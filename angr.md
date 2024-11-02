# Angr (Symbolic Execution Engine) Cheatsheet

## Installation Guide

### Using pip
```bash
# Basic installation
pip install angr

# With optional dependencies
pip install angr[doc,dev]
```

### Using Docker
```bash
# Pull official image
docker pull angr/angr

# Run container
docker run -it angr/angr
```

## Basic Commands

### Project Loading
| Command | Usage | Purpose |
|---------|--------|---------|
| `Project` | `proj = angr.Project('binary')` | Load binary |
| `factory` | `proj.factory` | Access analysis factories |
| `loader` | `proj.loader` | Access binary loader |
| `arch` | `proj.arch` | Access architecture info |

### State Operations
| Command | Usage | Purpose |
|---------|--------|---------|
| `entry_state()` | `state = proj.factory.entry_state()` | Create entry state |
| `blank_state()` | `state = proj.factory.blank_state()` | Create blank state |
| `full_init_state()` | `state = proj.factory.full_init_state()` | Create initialized state |
| `call_state()` | `state = proj.factory.call_state()` | Create call state |

### Symbolic Execution
| Command | Usage | Purpose |
|---------|--------|---------|
| `simgr` | `simgr = proj.factory.simulation_manager(state)` | Create simulation manager |
| `explore()` | `simgr.explore(find=addr, avoid=addr_list)` | Explore paths |
| `run()` | `simgr.run()` | Run until completion |
| `step()` | `simgr.step()` | Single step execution |

### Analysis Tools
| Command | Usage | Purpose |
|---------|--------|---------|
| `CFGFast` | `cfg = proj.analyses.CFGFast()` | Generate fast CFG |
| `CFGEmulated` | `cfg = proj.analyses.CFGEmulated()` | Generate precise CFG |
| `VFG` | `vfg = proj.analyses.VFG()` | Value-flow analysis |
| `DDG` | `ddg = proj.analyses.DDG()` | Data dependency graph |

### Memory Operations
| Command | Usage | Purpose |
|---------|--------|---------|
| `mem[addr]` | `state.mem[addr].int.concrete` | Read concrete value |
| `store()` | `state.memory.store(addr, value)` | Store value |
| `load()` | `state.memory.load(addr, size)` | Load value |
| `BVV()` | `state.solver.BVV(value, size)` | Create bitvector |

### Solver Operations
| Command | Usage | Purpose |
|---------|--------|---------|
| `add()` | `state.solver.add(constraint)` | Add constraint |
| `eval()` | `state.solver.eval(expr)` | Evaluate expression |
| `satisfiable()` | `state.solver.satisfiable()` | Check satisfiability |
| `constraints` | `state.solver.constraints` | Get constraints |

### Hooks and Breakpoints
| Command | Usage | Purpose |
|---------|--------|---------|
| `hook()` | `proj.hook(addr, hook_func)` | Hook address |
| `inspect` | `state.inspect` | Add breakpoints |
| `b()` | `state.inspect.b('mem_write')` | Set breakpoint |
| `remove_breakpoint()` | `state.inspect.remove_breakpoint()` | Remove breakpoint |

## Common Debugging Commands
```python
# Print memory
print(state.mem[addr].string.concrete)

# Print registers
print(state.regs.rax)

# Print constraints
print(state.solver.constraints)

# Get possible values
print(state.solver.eval_upto(expr, n))
```

## Best Practices
1. Always use `with` context for temporary hooks
2. Set memory limits for exploration
3. Use `LAZY_SOLVES` for better performance
4. Implement custom simprocedures for complex functions
5. Use `CFGFast` for initial analysis
6. Add timeout limits for explorations
7. Use `unicorn` engine for concrete execution

## Error Handling
```python
try:
    result = state.solver.eval(expr)
except angr.errors.SimError as e:
    print(f"Simulation error: {e}")
except angr.errors.SimUnsatError:
    print("Constraints unsatisfiable")
```
