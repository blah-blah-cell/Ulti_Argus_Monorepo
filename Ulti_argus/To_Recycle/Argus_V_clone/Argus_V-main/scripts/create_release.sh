#!/usr/bin/env bash
#
# Create a release tarball for ARGUS_V
#
# This script mimics what the GitHub Actions release workflow does.
# It creates a distributable .tar.gz package with all necessary files.
#
# Usage:
#   ./scripts/create_release.sh [VERSION]
#
# Examples:
#   ./scripts/create_release.sh v0.1.0
#   ./scripts/create_release.sh v0.1.1-rc1
#

set -e
set -u

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse version argument
if [[ $# -eq 0 ]]; then
    # Try to get version from pyproject.toml
    if command -v python3 &> /dev/null && [[ -f pyproject.toml ]]; then
        VERSION=$(python3 -c "import tomllib; print('v' + tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])" 2>/dev/null || echo "v0.1.0")
    else
        VERSION="v0.1.0"
    fi
    info "No version specified, using: $VERSION"
else
    VERSION="$1"
fi

# Validate version format
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    error "Invalid version format: $VERSION"
    error "Expected format: vX.Y.Z (e.g., v0.1.0)"
    exit 1
fi

info "Creating release for version: $VERSION"

# Define directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"
PKGNAME="argus_v-${VERSION}"
STAGING_DIR="/tmp/${PKGNAME}"

# Clean up from previous runs
info "Cleaning up previous builds..."
rm -rf "$STAGING_DIR"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Create staging directory
info "Creating staging directory..."
mkdir -p "$STAGING_DIR"

# Copy source code
info "Copying source code..."
if [[ ! -d "$PROJECT_DIR/src" ]]; then
    error "Source directory not found: $PROJECT_DIR/src"
    exit 1
fi
cp -a "$PROJECT_DIR/src" "$STAGING_DIR/"

# Copy documentation
info "Copying documentation..."
[[ -f "$PROJECT_DIR/README.md" ]] && cp "$PROJECT_DIR/README.md" "$STAGING_DIR/"
[[ -f "$PROJECT_DIR/INSTALL.md" ]] && cp "$PROJECT_DIR/INSTALL.md" "$STAGING_DIR/"
[[ -f "$PROJECT_DIR/README.COMPLIANCE.md" ]] && cp "$PROJECT_DIR/README.COMPLIANCE.md" "$STAGING_DIR/"
[[ -d "$PROJECT_DIR/README.Docs" ]] && cp -a "$PROJECT_DIR/README.Docs" "$STAGING_DIR/"

# Copy configuration examples
info "Copying configuration examples..."
[[ -f "$PROJECT_DIR/example-retina-config.yaml" ]] && cp "$PROJECT_DIR/example-retina-config.yaml" "$STAGING_DIR/"
[[ -f "$PROJECT_DIR/mnemosyne-config.example.yaml" ]] && cp "$PROJECT_DIR/mnemosyne-config.example.yaml" "$STAGING_DIR/"
[[ -f "$PROJECT_DIR/aegis-config.example.yaml" ]] && cp "$PROJECT_DIR/aegis-config.example.yaml" "$STAGING_DIR/"
[[ -d "$PROJECT_DIR/configs" ]] && cp -a "$PROJECT_DIR/configs" "$STAGING_DIR/"

# Copy packaging files
info "Copying packaging files..."
cp "$PROJECT_DIR/pyproject.toml" "$STAGING_DIR/"
cp "$PROJECT_DIR/requirements.txt" "$STAGING_DIR/"
cp "$PROJECT_DIR/LICENSE" "$STAGING_DIR/"

# Copy installation scripts
info "Copying installation scripts..."
cp "$PROJECT_DIR/install.sh" "$STAGING_DIR/"
cp "$PROJECT_DIR/uninstall.sh" "$STAGING_DIR/"

# Optional deployment helpers (auto-update)
[[ -f "$PROJECT_DIR/update.sh" ]] && cp "$PROJECT_DIR/update.sh" "$STAGING_DIR/"
[[ -f "$PROJECT_DIR/argus-rollback" ]] && cp "$PROJECT_DIR/argus-rollback" "$STAGING_DIR/"

chmod +x "$STAGING_DIR/install.sh"
chmod +x "$STAGING_DIR/uninstall.sh"
[[ -f "$STAGING_DIR/update.sh" ]] && chmod +x "$STAGING_DIR/update.sh"
[[ -f "$STAGING_DIR/argus-rollback" ]] && chmod +x "$STAGING_DIR/argus-rollback"

# Copy training utilities
info "Copying training utilities..."
[[ -f "$PROJECT_DIR/run_train.sh" ]] && cp "$PROJECT_DIR/run_train.sh" "$STAGING_DIR/"
[[ -f "$PROJECT_DIR/run_trainer.py" ]] && cp "$PROJECT_DIR/run_trainer.py" "$STAGING_DIR/"

# Create tarball
info "Creating tarball..."
TARBALL="$DIST_DIR/${PKGNAME}.tar.gz"
tar -czf "$TARBALL" -C /tmp "${PKGNAME}"

# Generate checksums
info "Generating checksums..."
cd "$DIST_DIR"
sha256sum "${PKGNAME}.tar.gz" > SHA256SUMS
cd - > /dev/null

# Clean up staging
info "Cleaning up staging directory..."
rm -rf "$STAGING_DIR"

# Show results
success "Release package created successfully!"
echo ""
echo "Package: $TARBALL"
echo "Size: $(du -h "$TARBALL" | cut -f1)"
echo "Checksums: $DIST_DIR/SHA256SUMS"
echo ""
echo "Contents:"
tar -tzf "$TARBALL" | head -20
TOTAL_FILES=$(tar -tzf "$TARBALL" | wc -l)
if [[ $TOTAL_FILES -gt 20 ]]; then
    echo "... and $((TOTAL_FILES - 20)) more files"
fi
echo ""
success "Release package is ready for distribution"
echo ""
echo "To test the installation:"
echo "  1. Extract: tar xzf $TARBALL"
echo "  2. Install: cd ${PKGNAME} && sudo ./install.sh"
