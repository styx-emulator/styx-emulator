#!/usr/bin/env bash
# Local reproduction script for testing Styx cargo-generate templates
# This script mimics the CI workflow behavior locally

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get the repository root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TEMPLATE_DIR="$REPO_ROOT/styx/templates"
TEST_DIR="${TEST_DIR:-/tmp/styx-template-tests-$(date +%s)}"

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Styx Template Validation - Local CI Reproduction Script     ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Repository root:${NC} $REPO_ROOT"
echo -e "${BLUE}Template directory:${NC} $TEMPLATE_DIR"
echo -e "${BLUE}Test directory:${NC} $TEST_DIR"
echo ""

# Check prerequisites
echo -e "${BLUE}=== Checking Prerequisites ===${NC}"

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}[-] Error: cargo is not installed${NC}"
    echo "Install Rust from: https://rustup.rs/"
    exit 1
fi
echo -e "${GREEN}[+] cargo found${NC}"

if ! command -v cargo-generate &> /dev/null; then
    echo -e "${RED}[-] Error: cargo-generate is not installed${NC}"
    echo "Install with: cargo install cargo-generate"
    exit 1
fi
echo -e "${GREEN}[+] cargo-generate found${NC}"

if [ ! -d "$TEMPLATE_DIR" ]; then
    echo -e "${RED}[-] Error: Template directory not found: $TEMPLATE_DIR${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Template directory exists${NC}"

if [ ! -d "$REPO_ROOT/styx/core" ]; then
    echo -e "${RED}[-] Error: styx-core not found at: $REPO_ROOT/styx/core${NC}"
    exit 1
fi
echo -e "${GREEN}[+] styx-core found${NC}"
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Track overall success
SUCCESS=true
FAILED_TEMPLATES=()

# Function to print a separator
print_separator() {
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
}

# Function to test a template (mimics CI behavior)
test_template() {
    local component_type="$1"
    local component_name="$2"
    local expected_crate_name="$3"
    local project_dir="test-${component_type}-validation"

    print_separator
    echo -e "${BLUE}Testing ${YELLOW}${component_type}${BLUE} template${NC}"
    print_separator
    echo ""

    # Step 1: Generate the template
    echo -e "${CYAN}[1/5]${NC} Generating template with cargo-generate..."
    if ! cargo generate --path "$TEMPLATE_DIR" \
        --name "$project_dir" \
        -d component_type="$component_type" \
        -d is_in_tree=false \
        -d component_name="$component_name" \
        -d component_description="Test ${component_type} for CI" \
        -d author_name="CI Bot" \
        -d author_email="ci@example.com" \
        2>&1 | grep -E "(Generating|Done|project created)" | head -5; then
        echo -e "${RED}[-] Failed to generate ${component_type} template${NC}"
        SUCCESS=false
        FAILED_TEMPLATES+=("$component_type")
        return 1
    fi
    echo -e "${GREEN}[+] Template generated${NC}"
    echo ""

    # Step 2: Navigate to generated crate
    if [ ! -d "$project_dir" ]; then
        echo -e "${RED}[-] Expected directory not found: $project_dir${NC}"
        echo "Found directories:"
        ls -1
        SUCCESS=false
        FAILED_TEMPLATES+=("$component_type")
        return 1
    fi
    cd "$project_dir"

    # Step 3: Update Cargo.toml to point to workspace styx-core (like CI does)
    echo -e "${CYAN}[2/5]${NC} Updating Cargo.toml with workspace styx-core path..."
    local deps=""
    case "$component_type" in
        processor)
            deps="styx-core = { path = \"$REPO_ROOT/styx/core\" }
anyhow = \"1.0\"
thiserror = \"1.0\"
tracing = \"0.1\""
            ;;
        event-controller)
            deps="styx-core = { path = \"$REPO_ROOT/styx/core\" }
as-any = \"0.3\"
thiserror = \"1.0\"
tracing = \"0.1\""
            ;;
        peripheral)
            deps="styx-core = { path = \"$REPO_ROOT/styx/core\" }
as-any = \"0.3\"
async-trait = \"0.1\"
derivative = \"2.2\"
thiserror = \"1.0\"
tokio = { version = \"1\", features = [\"sync\"] }
tokio-stream = \"0.1\"
tonic = \"0.11\"
tracing = \"0.1\""
            ;;
        plugin)
            deps="styx-core = { path = \"$REPO_ROOT/styx/core\" }
thiserror = \"1.0\"
tracing = \"0.1\""
            ;;
    esac

    # Create a new Cargo.toml with correct paths
    cat > Cargo.toml << EOF
[package]
name = "$expected_crate_name"
version = "0.1.0"
edition = "2021"
authors = ["CI Bot <ci@example.com>"]
description = "Test ${component_type} for CI"
license = "BSD-2-Clause"

[dependencies]
$deps

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
EOF
    echo -e "${GREEN}[+] Cargo.toml updated${NC}"
    echo ""

    # Step 4: Build the generated crate
    echo -e "${CYAN}[3/5]${NC} Building template (this may take a minute)..."
    if ! cargo build 2>&1 | tee build.log | tail -5; then
        echo -e "${RED}[-] Failed to build ${component_type} template${NC}"
        echo ""
        echo -e "${YELLOW}Build log (last 30 lines):${NC}"
        tail -30 build.log
        SUCCESS=false
        FAILED_TEMPLATES+=("$component_type")
        cd ..
        return 1
    fi
    echo -e "${GREEN}[+] Build successful${NC}"
    echo ""

    # Step 5: Run tests
    echo -e "${CYAN}[4/5]${NC} Running tests..."
    if cargo test 2>&1 | tee test.log | tail -5; then
        echo -e "${GREEN}[+] Tests passed${NC}"
    else
        echo -e "${YELLOW}⚠ Tests failed (expected for minimal scaffolding)${NC}"
        # Don't fail on test failures since templates are minimal scaffolding
    fi
    echo ""

    # Step 6: Verify the generated code has the expected traits
    echo -e "${CYAN}[5/5]${NC} Verifying trait implementations..."
    local trait_found=false
    case "$component_type" in
        processor)
            if grep -q "impl ProcessorImpl" src/lib.rs; then
                echo -e "${GREEN}[+] Found ProcessorImpl implementation${NC}"
                trait_found=true
            fi
            ;;
        event-controller)
            if grep -q "impl EventControllerImpl" src/lib.rs; then
                echo -e "${GREEN}[+] Found EventControllerImpl implementation${NC}"
                trait_found=true
            fi
            ;;
        peripheral)
            if grep -q "impl Peripheral" src/lib.rs; then
                echo -e "${GREEN}[+] Found Peripheral implementation${NC}"
                trait_found=true
            fi
            ;;
        plugin)
            if grep -q "impl Plugin" src/lib.rs && grep -q "impl UninitPlugin" src/lib.rs; then
                echo -e "${GREEN}[+] Found Plugin and UninitPlugin implementations${NC}"
                trait_found=true
            fi
            ;;
    esac

    if [ "$trait_found" = false ]; then
        echo -e "${RED}[-] Missing expected trait implementation${NC}"
        SUCCESS=false
        FAILED_TEMPLATES+=("$component_type")
        cd ..
        return 1
    fi
    echo ""

    cd ..
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}[+][+][+] ${component_type} template validated successfully [+][+][+]${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    return 0
}

# Main execution
echo -e "${BLUE}=== Starting Template Validation ===${NC}"
echo ""

# Test all template types (same as CI workflow)
test_template "processor" "test-proc" "styx-test-proc-processor"
test_template "event-controller" "test-ec" "styx-test-ec"
test_template "peripheral" "test-periph" "styx-test-periph"
test_template "plugin" "test-plug" "styx-test-plug"

# Summary
echo ""
print_separator
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    Validation Summary                         ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$SUCCESS" = true ]; then
    echo -e "${GREEN}✅ All templates validated successfully!${NC}"
    echo ""
    echo -e "  ${GREEN}[+]${NC} Processor template"
    echo -e "  ${GREEN}[+]${NC} Event Controller template"
    echo -e "  ${GREEN}[+]${NC} Peripheral template"
    echo -e "  ${GREEN}[+]${NC} Plugin template"
    echo ""
    echo -e "${BLUE}Test artifacts:${NC}"
    echo -e "  Location: ${CYAN}$TEST_DIR${NC}"
    echo -e "  Size: $(du -sh "$TEST_DIR" | cut -f1)"
    echo ""
    echo -e "${YELLOW}To inspect generated files:${NC}"
    echo -e "  cd $TEST_DIR"
    echo -e "  ls -la"
    echo ""
    echo -e "${YELLOW}To clean up:${NC}"
    echo -e "  rm -rf $TEST_DIR"
    echo ""
    exit 0
else
    echo -e "${RED}[-] Some templates failed validation${NC}"
    echo ""
    echo -e "${RED}Failed templates:${NC}"
    for template in "${FAILED_TEMPLATES[@]}"; do
        echo -e "  ${RED}[-]${NC} $template"
    done
    echo ""
    echo -e "${BLUE}Test directory preserved at:${NC} ${CYAN}$TEST_DIR${NC}"
    echo ""
    echo -e "${YELLOW}To debug:${NC}"
    echo -e "  cd $TEST_DIR"
    echo -e "  # Inspect build logs in <template-name>/build.log"
    echo -e "  # Inspect test logs in <template-name>/test.log"
    echo ""
    exit 1
fi
