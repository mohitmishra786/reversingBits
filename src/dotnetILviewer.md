# Dotnet-Offline-IL-Viewer

Dotnet-Offline-IL-Viewer is a tool for analyzing .NET assemblies, allowing you to view the disassembled code and metadata.

## Installation

You can download the Dotnet-Offline-IL-Viewer from the GitHub releases page: https://github.com/0xd4d/dnSpy/releases

## Usage

1. Launch the Dotnet-Offline-IL-Viewer application.
2. Open a .NET assembly file using the "File" > "Open" menu option.
3. The tool will display the assembly's metadata, including:
   - Assembly information (version, culture, etc.)
   - Types (classes, structs, enums, etc.)
   - Methods
   - Fields
   - Properties
   - Events
4. You can navigate through the assembly's contents using the tree-view on the left side of the window.
5. Double-click on a method to view its disassembled IL (Intermediate Language) code.
6. The IL code view provides features like:
   - Syntax highlighting
   - Jump to definitions
   - Cross-references
   - Call graph visualization
7. You can also use the search functionality to find specific types, methods, or IL instructions.

Additionally, Dotnet-Offline-IL-Viewer supports the following features:

- Decompilation to C# code (requires separate decompiler plugin)
- Disassembly of native code (e.g., P/Invoke)
- .NET Core and .NET Standard assembly support
- Powerful scripting and plugin system

For more detailed information and usage examples, please refer to the Dotnet-Offline-IL-Viewer documentation: https://github.com/0xd4d/dnSpy/wiki