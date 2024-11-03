# Diaphora Binary Diffing Cheatsheet

## Installation Guide

### IDA Pro Plugin Installation
```bash
# Clone repository
git clone https://github.com/joxeankoret/diaphora.git

# Copy to IDA plugins directory
# For IDA 7.x
cp diaphora.py %IDADIR%/plugins/
```

### Optional Dependencies
```bash
pip install pymssql
pip install mysql-python
pip install psycopg2
```

## Basic Operations

### Exporting Binary Information
| Command | Purpose |
|---------|---------|
| `File -> Script File... -> diaphora.py` | Launch Diaphora plugin |
| `Export -> Binary` | Export binary for diffing |
| `Export -> Database` | Export to SQLite database |
| `Export -> Project` | Export project settings |

### Diffing Commands

#### Basic Diffing
| Operation | Purpose |
|-----------|---------|
| `Diff -> Quick Diff` | Fast comparison |
| `Diff -> Deep Diff` | Detailed analysis |
| `Diff -> Selective Diff` | Compare specific functions |
| `Diff -> Custom Diff` | User-defined comparison |

#### Advanced Diffing
| Operation | Purpose |
|-----------|---------|
| `Analysis -> Call Graphs` | Compare call graphs |
| `Analysis -> Strings` | Compare string references |
| `Analysis -> Constants` | Compare numerical constants |
| `Analysis -> Imports` | Compare imported functions |

### Matching Options

#### Function Matching
| Option | Purpose |
|--------|---------|
| `Match -> Exact` | 100% identical matches |
| `Match -> Partial` | Similar functions |
| `Match -> Sequential` | Order-based matching |
| `Match -> Experimental` | AI-based matching |

#### Heuristic Settings
| Setting | Purpose |
|---------|---------|
| `Heuristic -> Basic Blocks` | Compare block structure |
| `Heuristic -> Instructions` | Compare instruction sequences |
| `Heuristic -> Mnemonics` | Compare assembly mnemonics |
| `Heuristic -> Names` | Compare function names |

## Results Analysis

### Viewing Results
| View | Purpose |
|------|---------|
| `Results -> Best Matches` | Show highest confidence matches |
| `Results -> Partial Matches` | Show similar functions |
| `Results -> Unmatched` | Show unique functions |
| `Results -> Statistics` | Show diffing statistics |

### Export Options
| Format | Command |
|--------|---------|
| `Export -> CSV` | Export results to CSV |
| `Export -> SQL` | Export to SQL database |
| `Export -> JSON` | Export to JSON format |
| `Export -> HTML` | Generate HTML report |

## Advanced Features

### Batch Processing
| Command | Purpose |
|---------|---------|
| `Batch -> Load Files` | Process multiple binaries |
| `Batch -> Export All` | Export batch results |
| `Batch -> Compare All` | Diff multiple files |
| `Batch -> Generate Report` | Create batch report |

### Customization
| Feature | Purpose |
|---------|---------|
| `Config -> Thresholds` | Adjust matching sensitivity |
| `Config -> Filters` | Set comparison filters |
| `Config -> Ignore Lists` | Exclude functions/areas |
| `Config -> Plugins` | Manage custom plugins |

### Debugging
| Command | Purpose |
|---------|---------|
| `Debug -> Log` | Show debug information |
| `Debug -> Profile` | Performance analysis |
| `Debug -> Validate` | Check results accuracy |
| `Debug -> Compare` | Manual result verification |