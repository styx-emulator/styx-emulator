# Template CI/CD Integration

This document describes the continuous integration setup for Styx cargo-generate templates.

## Overview

The template validation system ensures that all templates generate valid, buildable Rust crates that correctly integrate with `styx-core`.

## Components

### GitHub Actions Workflow

**File**: `.github/workflows/template-validation.yml`

**Triggers**:
- Pull requests that modify:
  - `styx/templates/**`
  - `.github/workflows/template-validation.yml`
  - `styx/templates/scripts/test-templates-local.sh`
- Pushes to `main` branch (same paths)
- Manual workflow dispatch

**What it does**:
1. Checks out the repository
2. Installs Rust toolchain and cargo-generate
3. Runs the local test script: `./styx/templates/scripts/test-templates-local.sh`
4. Creates temporary test directory
5. Generates all 4 template types
6. Updates Cargo.toml paths to point to workspace styx-core
7. Builds each template
8. Runs tests
9. Verifies trait implementations exist
10. Cleans up temporary test directories

**Runtime**: ~3-5 minutes per run

## Dependency Management

Templates use relative paths to `styx-core` that need adjustment based on location:

```toml
# Default (for peripherals/plugins in styx repo)
styx-core = { path = "../../core" }

# For processors (deeper nesting)
styx-core = { path = "../../../core" }

# For external projects
styx-core = { git = "https://github.com/styx-emulator/styx-emulator", branch = "main" }
```

The CI workflow automatically updates these paths to point to the workspace `styx-core`.

## Adding New Template Types

To add a new template type:

1. **Update `cargo-generate.toml`**:
   ```toml
   [placeholders.component_type]
   choices = ["processor", "event-controller", "peripheral", "plugin", "new-type"]
   ```

2. **Add template code in `src/lib.rs`**:
   ```liquid
   {% elsif component_type == "new-type" %}
   // Template code here
   {% endif %}
   ```

3. **Update `Cargo.toml` dependencies**:
   ```liquid
   {% elsif component_type == "new-type" %}
   styx-core = { path = "../../core" }
   # other dependencies
   {% endif %}
   ```

4. **Update test script** (`styx/templates/scripts/test-templates-local.sh`):
   ```bash
   test_template "new-type" "test-new" "styx-test-new"
   ```

5. **Update documentation** (README.md, QUICKSTART.md)

## Debugging Template Issues

**Debug steps**:
```bash
# Generate template manually
cargo generate --path styx/templates

# Navigate to generated crate
cd <generated-crate>

# Update Cargo.toml path
# Edit: styx-core = { path = "/path/to/styx/core" }

# Try building with verbose output
cargo build --verbose

# Check for specific errors
cargo check
```
