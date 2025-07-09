A LibAFL fuzzer implementation for Styx.

### Before Fuzzing
1. Load your program into Ghidra and run the `GetBranches.java` script.  This will output a text file listing the start addresses of all basic blocks in the program which will be used for coverage tracking.  It will also print to the console the required size of the coverage map.  Go into `./src/lib.rs` and fill in the coverage map size `const COVERAGE_MAP_SIZE: usize = 1024;` with what you got.  (You can compute this manually if you want, use the smallest power of 2 that is greater than or equal to the number of basic blocks in the program).  The coverage map needs to be a static array so the size needs to be known at compile time.
#### GetBranches.java output file format
Each address is on a separate line, in decimal format.

### UI
By default, a simple UI is enabled that simply prints log messages to the screen. An enhanced UI based on ratatui can be enabled with the `tui` feature (disabled by default).
