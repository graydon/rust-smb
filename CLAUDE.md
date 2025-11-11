# CLAUDE.md - Project Instructions and TODO List

## Project Overview
Implementing a full SMB stack (client and server) in idiomatic Rust from the ground up.

## Key Requirements
1. **No external SMB crates** - Write everything from scratch, no pre-existing SMB-protocol-suite crates
2. **Sans-IO style** - Separate protocol logic from I/O operations
3. **Extensive unit tests** - Write tests as you go, test everything
4. **Step-by-step approach** - Implement incrementally, testing each component
5. **Built on Tokio** - Use Tokio for async runtime
6. **Idiomatic Rust** - Follow Rust best practices and conventions
7. **Extract from Samba** - Use the unpacked samba-4.22.3 directory as reference for:
   - Protocol details
   - Test scenarios
   - Implementation logic
   - Convert to idiomatic Rust

## Target Capabilities
The SMB stack should ultimately support:
- Authentication (NTLM, Kerberos)
- File service
- Printing
- Standard SMB workgroup tasks
- Both SMB2 and SMB3 protocols

## Development Approach
1. MAKE A PLAN AND A DETAILED CHECKLIST
2. ASK USER FOR INPUT ON PLAN
3. Write unit tests for each component before/during implementation
4. Test each step thoroughly before moving on
5. Use sans-IO design pattern to separate protocol from transport
6. Reference Samba source for protocol details and test cases

## Implementation Principles
- Always implement real versions of the code you're writing
- Don't leave partial versions, fake data, or TODOs about "doing the real thing later"
- DO THE THING THE CODE IS SUPPOSED TO DO. NO FAKE OR HALF MEASURES.

## Coding Principles

- Try to keep each file small -- a few hundred lines or so. When a
  file gets big, split it into pieces in sub modules/files and only use
  the necessary interfaces between them.

- Put unit tests in separate file modules that are #[cfg(test)]-guarded

## CRITICAL CODING STANDARDS

### NEVER USE eprintln! IN TESTS
**ALWAYS use the logging macros (debug!, info!, warn!, error!) instead of eprintln!**
- The logging macros integrate with the test framework properly
- They can be controlled with RUST_LOG environment variable
- They provide proper formatting and context
- eprintln! bypasses the logging system and creates messy output

## Important Notes
- **CHECK FOR DUPLICATE OR REDUNDANT CODE AND CLEAN IT UP** - After each edit, ensure no duplicate implementations exist
- **Never leave duplicate code** - Having multiple implementations of the same functionality is dangerous and leads to bugs
- **Always fix all failures while implementing** - Don't leave broken code
- **Create automated tests for everything** - Every feature needs tests
- **Run tests after each change** - Ensure nothing breaks
- **Update TODO LISTS with progress** - Track what's done and what's next
- **Keep TODO list up to date as you work** - Update status immediately when completing tasks
- **Fix all warnings as you go** - Maintain clean, warning-free code
- **Test client-server communication** - Always test that the client and server can actually communicate
- **Test with smbclient** - Verify server works with standard SMB clients like smbclient
- **Create test scenarios** - Develop comprehensive test scenarios for real-world usage

## CRITICAL TESTING RULES - MUST READ

### BROKEN TESTS MUST BE FIXED IMMEDIATELY
**WHENEVER YOU BREAK A TEST, YOU MUST PRIORITIZE FIXING IT BEFORE MOVING ON TO NEW FEATURE WORK**
- If a test fails after your changes, STOP and FIX IT
- Do not leave broken tests while adding new features
- Always run tests after making changes to verify nothing is broken
- The smbclient tests are CRITICAL - they verify real protocol compatibility

## Testing Methodology

### IMPORTANT: All Tests Must Be In-Crate Unit Tests
**DO NOT create external test scripts or separate test binaries. All tests must be compiled into the crate as unit tests.**
**DO NOT create new testing directories like `src/testing/`. Use the existing `src/e2e_tests/` module.**
**DO NOT run smbclient as an external command - use the in-crate smbclient_tests module that runs smbclient as a subprocess**
**THERE ARE NO SHELL-BASED TESTS OR ANY OTHER EXTERNAL TESTS AT ALL - everything is in-crate unit tests**

### Consolidated In-Crate Testing Architecture
The project uses a unified testing infrastructure where all tests are part of the crate:

**Integration Test Organization:**
- Integration tests live in `src/e2e_tests/` as part of the crate
- No external test binaries in `tests/` directory
- No separate `src/testing/` directory - use `src/e2e_tests/`
- Two testing approaches available:
  1. **Loopback in-process tests** - Use `LoopbackTransport` for fast, in-memory testing without network I/O
  2. **Subprocess-based smbclient tests** - Use `SmbClientTestContext` to test with real smbclient as a subprocess

**Integration Test Modules:**
- `loopback.rs` - Core loopback transport framework for in-process TCP connections
- `smbclient_tests.rs` - Real smbclient subprocess tests for full protocol validation
- `delete_operations.rs` - File/directory deletion and delete-on-close tests
- `rename_operations.rs` - File/directory rename via SET_INFO tests
- `file_operations.rs` - Basic file CRUD operations (create, read, write, close)
- `protocol_tests.rs` - Protocol negotiation, session setup, and tree connect tests

**Benefits:**
- Stable, reproducible tests without network dependencies
- Fast test execution with in-process connections
- Prevention of feature regressions
- Coverage of full protocol stack
- Consistent test infrastructure across all scenarios

When adding new features:
1. Implement the feature
2. Add unit tests within the `mod tests` or `tests.rs` sub-module of the module you just added a feature to
3. Add integration tests in the appropriate `src/e2e_tests/` module
4. Test with smbclient for real-world compatibility
5. Update this documentation

## Testing Commands
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Check for compilation errors
cargo check

# Build all targets
cargo build --all-targets

# Run with all features
cargo test --all-features

# Lint check (once configured)
cargo clippy -- -D warnings

# Format check
cargo fmt -- --check

# Test our client against server
# cargo run --bin smb-client -- -H localhost -p 4445 -s public ls /
```

## Reference Materials
- Samba source in `samba-4.22.3/` directory
- MS-SMB2 protocol specification
- MS-NLMP for NTLM authentication
- MS-SPNG for SPNEGO

## Development Notes

- File redirections like "2>&1" do not currently work in the "bash"
  tool, the 2 is interpreted as an argument. You can bypass this by
  running `bash -c '... 2>&1'` i.e. wrap the command you want to run
  in _another_ layer of bash scripting. Not ideal but it works.

- **Research is encouraged**: When implementing protocol features, ground assumptions by:
  - Reading Samba source code in `samba-4.22.3/` directory
  - Loading Microsoft protocol documentation from the web
  - Examining how other implementations handle the same scenarios
  - Both code research and experimental testing are valuable approaches

- **Error handling best practices**:
  - **NEVER use `.unwrap()` or `.expect()` in production code** - always use proper error handling with `?`
  - Use `WriteBytesExt` trait from byteorder for serialization - instead of `extend_from_slice(&value.to_le_bytes())`, use `write_u32::<LittleEndian>(value)?`
  - All functions that can fail should return `Result<T>` rather than panicking
  - If you need to handle an Option or Result, use proper pattern matching or the `?` operator

- **Testing best practices**:
  - **NEVER create separate test programs** - always add unit tests to the appropriate module
  - When debugging issues, add a `#[test]` function to the module and run it with `cargo test`
  - All tests must be part of the crate, either as unit tests in modules or in `src/e2e_tests/`
