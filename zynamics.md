# Zynamics BinDiff Cheatsheet

## Installation & Setup
```bash
# Download BinDiff from Google
# Install IDA Pro plugin (if using with IDA)
# Copy bindiff.dll to IDA plugins directory
```

## Basic Usage
### Command Line Interface
```bash
# Compare two binaries
bindiff primary.exe secondary.exe

# Generate reports
bindiff --primary=file1.exe --secondary=file2.exe --output=diff.BinDiff

# Export results
bindiff --export-html report.html diff.BinDiff
```

## Analysis Features
### Function Matching
```
# Matching algorithms used:
- Hash matching
- Call reference matching
- String reference matching
- Flow graph matching
- Relaxed string reference matching
```

### Similarity Metrics
```
# Function similarities checked:
- Basic block count
- Edge count
- Instruction count
- String references
- Call references
- Control flow graph structure
```

## GUI Interface
### Navigation
| Shortcut | Action |
|----------|---------|
| Ctrl+F | Find function |
| Ctrl+G | Go to address |
| Tab | Switch views |
| Space | Toggle graph view |

### Views
```
# Available views:
1. Call Graph
2. Flow Graph
3. Function List
4. Statistics
5. Proximity Browser
```

## Diff Operations
### Basic Comparison
```
# Steps for comparison:
1. Load primary binary
2. Load secondary binary
3. Select comparison algorithm
4. Run comparison
5. Analyze results
```

### Advanced Options
```
# Comparison settings:
- Confidence threshold
- Algorithm selection
- Symbol usage
- String matching
```

## Report Generation
### HTML Reports
```
# Report contents:
- Function matches
- Similarity scores
- Statistics
- Graphs
- Call references
```

### Export Formats
```
# Available formats:
- HTML
- XML
- CSV
- SQLite database
```

## Integration
### IDA Pro Integration
```python
# IDA Python script
def export_for_bindiff():
    # Export current database
    idc.save_database("export.bio")
```

### Other Tools
```bash
# Convert formats
bindiff --convert input.exe output.bio

# Merge results
bindiff --merge result1.BinDiff result2.BinDiff
```

## Analysis Workflows
### Binary Comparison
1. Initial Analysis
```
- Load binaries
- Configure matching options
- Run initial comparison
```

2. Result Analysis
```
- Check similarity scores
- Investigate differences
- Examine call graphs
```

3. Report Generation
```
- Generate HTML report
- Export detailed results
- Document findings
```

## Advanced Features
### Custom Matching
```python
# Define custom matching rules
class CustomMatcher:
    def match_functions(self, func1, func2):
        # Custom matching logic
        return similarity_score
```

### Automation
```python
# Batch processing script
import bindiff

def batch_compare(file_list):
    for primary, secondary in file_list:
        diff = bindiff.compare(primary, secondary)
        diff.export_report()
```

## Tips & Best Practices
### Performance
1. Optimization
```
- Use appropriate algorithms
- Set reasonable thresholds
- Limit comparison scope
```

2. Memory Usage
```
- Process large binaries in chunks
- Clear unused results
- Use efficient export formats
```

### Analysis Tips
1. Function Matching
```
- Start with high confidence matches
- Investigate unmatched functions
- Use multiple algorithms
```

2. Difference Analysis
```
- Focus on security-relevant changes
- Check for pattern changes
- Analyze surrounding context
```

3. Documentation
```
- Record matching criteria
- Document false positives
- Save important findings
```

### Common Tasks
1. Patch Analysis
```
- Compare original and patched
- Identify changed functions
- Document security fixes
```

2. Malware Analysis
```
- Compare variants
- Identify shared code
- Track evolution
```

3. Version Analysis
```
- Track binary changes
- Identify new features
- Monitor security updates
```

## Troubleshooting
### Common Issues
1. Loading Problems
```
- Check file formats
- Verify export settings
- Check permissions
```

2. Matching Issues
```
- Adjust thresholds
- Try different algorithms
- Check for stripped symbols
```

3. Performance Problems
```
- Reduce comparison scope
- Use appropriate settings
- Clear temporary files
```
