# Ghidra Comprehensive Cheatsheet

## Installation Instructions

### All Platforms (Java Required)
```bash
# Install Java Development Kit (JDK) 11 or later first
# Download Ghidra from https://ghidra-sre.org/
```

### Windows
1. Download ZIP file
2. Extract to desired location
3. Run `ghidraRun.bat`

### Linux
```bash
# Download ZIP file
unzip ghidra_*.zip
cd ghidra_*
./ghidraRun
```

### macOS
```bash
# Using Homebrew
brew install --cask ghidra

# Manual Installation
# Extract ZIP and run ghidraRun
```

## Basic Operations

### Project Management

1. **Create New Project**
- File → New Project
- Select Shared or Non-Shared
- Choose Project Directory

2. **Import Files**
```
File → Import File
Dragon drop files into project
```

3. **Open Program**
```
Double-click program in project window
File → Open from project window
```

### Analysis

4. **Auto Analysis**
```
Analysis → Auto Analyze
Configure analysis options
Click 'Analyze'
```

5. **Function Analysis**
```
Right-click in Function Window
Create Function
Edit Function
```

6. **Data Type Analysis**
```
Window → Data Type Manager
Import Additional Archives
```

### Navigation

7. **Go To Address**
```
G or Ctrl+G
Enter address
```

8. **Find**
```
Search → Program Text
Search → Memory
Search → Labels
```

9. **Cross References**
```
Right-click → References
Show References to Address
Show References from Address
```

### Decompilation

10. **View Decompiler**
```
Window → Decompiler
Double-click function in listing
```

11. **Rename Variables**
```
Right-click variable
Rename Variable
```

12. **Retype Variables**
```
Right-click variable
Retype Variable
```

### Code Analysis

13. **Function Graph**
```
Window → Function Graph
Display → Layout Mode
```

14. **Data Flow Analysis**
```
Right-click → Data Flow
Forward Slice
Backward Slice
```

15. **Control Flow Analysis**
```
Right-click → Control Flow
Show Dominance Tree
```

## Scripting

### Python Scripting

16. **Basic Script Structure**
```python
#@category Analysis
#@keybinding 
#@menupath 
#@toolbar 

def run():
    program = getCurrentProgram()
    # Your code here
```

17. **Memory Access**
```python
memory = currentProgram.getMemory()
bytes = memory.getBytes(addr, length)
```

18. **Symbol Table Access**
```python
symbolTable = currentProgram.getSymbolTable()
symbols = symbolTable.getSymbols("main")
```

### Java Scripting

19. **Basic Java Script**
```java
import ghidra.app.script.GhidraScript;

public class MyScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Your code here
    }
}
```

20. **Program API**
```java
Program program = getCurrentProgram();
Memory memory = program.getMemory();
```

### Advanced Features

21. **Batch Analysis**
```python
#@category Analysis
def analyzeBatch():
    project = getProject()
    folder = project.getProjectData()
    # Process all programs
```

22. **Custom Data Types**
```java
DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
Structure struct = dtm.createStructure("MyStruct");
```

### Patch Instructions

23. **Patch Bytes**
```python
memory = currentProgram.getMemory()
memory.setBytes(addr, bytes)
```

24. **Add Comments**
```python
listing = currentProgram.getListing()
listing.setComment(addr, PLATE_COMMENT, "My comment")
```

## Advanced Usage

### Binary Diffing

25. **Version Tracking**
```
Tools → Version Tracking
Select two programs
Compare versions
```

26. **Function Matching**
```
Right-click function
Apply Function Hash
Match Functions
```

### Type Libraries

27. **Import Types**
```
File → Parse C Source
Select header files
Import into program
```

28. **Create Structures**
```
Window → Data Type Manager
Create Structure
Add fields
```

### Function Analysis

29. **Stack Frame Analysis**
```
Window → Function Stack Frame
Analyze local variables
Edit parameters
```

30. **Call Graph**
```
Window → Function Call Graph
Analyze function relationships
```

## Best Practices

### Project Organization

31. **Folder Structure**
```
Project/
  ├── Sources/
  ├── Libraries/
  └── Analysis/
```

32. **Naming Conventions**
```
Functions: verb_noun
Variables: descriptive_name
Structures: Name_t
```

### Analysis Workflow

33. **Initial Analysis**
```
1. Import file
2. Run auto-analysis
3. Check entry points
4. Analyze strings
5. Check imports/exports
```

34. **Deep Analysis**
```
1. Identify key functions
2. Analyze data structures
3. Track cross-references
4. Document findings
```

## Keyboard Shortcuts

35. **Navigation**
```
G         - Go to address
Ctrl+F    - Find
Ctrl+E    - Edit instruction
Ctrl+L    - Label
```

36. **Views**
```
Space     - Toggle listing/decompiler
Ctrl+T    - Text view
Ctrl+G    - Graph view
```

## Common Issues and Solutions

37. **Memory Issues**
```
Edit → Tool Options
Increase memory allocation
Adjust cache settings
```

38. **Analysis Problems**
```
Clear flow
Disassemble
Create function
Fix stack frame
```

## Scripting Examples

39. **Find Strings**
```python
def findStrings():
    memory = currentProgram.getMemory()
    listing = currentProgram.getListing()
    # Search for strings
```

40. **Analyze Functions**
```python
def analyzeFunctions():
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)
    # Process functions
```

## Custom Analysis

41. **Data Flow Analysis**
```java
public void analyzeDataFlow() {
    DataFlow df = new DataFlow(currentProgram);
    // Analyze data flow
}
```

42. **Control Flow Analysis**
```java
public void analyzeControlFlow() {
    ControlFlow cf = new ControlFlow(currentProgram);
    // Analyze control flow
}
```
