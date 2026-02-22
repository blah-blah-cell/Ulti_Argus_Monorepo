#!/usr/bin/env bash
#
# Test script to validate the install.sh package preparation
#
# This tests that all required files are present for a successful installation

set -e

echo "Testing ARGUS_V installation package..."

# Check if PyYAML is installed (required for YAML validation tests)
if ! python3 -c "import yaml" 2>/dev/null; then
    echo "✗ PyYAML is required to run this test script."
    echo "  Please install it: pip install PyYAML"
    exit 1
fi

# Test 1: Check required files exist
echo "✓ Checking required files..."
required_files=(
    "install.sh"
    "uninstall.sh"
    "requirements.txt"
    "pyproject.toml"
    "LICENSE"
    "README.md"
    "INSTALL.md"
    "src/argus_v/__init__.py"
    "example-retina-config.yaml"
    "mnemosyne-config.example.yaml"
    "aegis-config.example.yaml"
)

for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "✗ Missing required file: $file"
        exit 1
    fi
done
echo "  All required files present"

# Test 2: Check install.sh is executable
echo "✓ Checking script permissions..."
if [[ ! -x "install.sh" ]]; then
    echo "✗ install.sh is not executable"
    exit 1
fi
if [[ ! -x "uninstall.sh" ]]; then
    echo "✗ uninstall.sh is not executable"
    exit 1
fi
echo "  Scripts are executable"

# Test 3: Check bash syntax
echo "✓ Checking bash syntax..."
bash -n install.sh || { echo "✗ install.sh has syntax errors"; exit 1; }
bash -n uninstall.sh || { echo "✗ uninstall.sh has syntax errors"; exit 1; }
echo "  Scripts have valid syntax"

# Test 4: Check Python package structure
echo "✓ Checking Python package structure..."
required_modules=(
    "src/argus_v/oracle_core"
    "src/argus_v/retina"
    "src/argus_v/mnemosyne"
    "src/argus_v/aegis"
)

for module in "${required_modules[@]}"; do
    if [[ ! -d "$module" ]]; then
        echo "✗ Missing module: $module"
        exit 1
    fi
    if [[ ! -f "$module/__init__.py" ]]; then
        echo "✗ Missing __init__.py in: $module"
        exit 1
    fi
done
echo "  Package structure is valid"

# Test 5: Check requirements.txt format
echo "✓ Checking requirements.txt..."
if ! grep -q "PyYAML" requirements.txt; then
    echo "✗ requirements.txt missing PyYAML"
    exit 1
fi
if ! grep -q "scapy" requirements.txt; then
    echo "✗ requirements.txt missing scapy"
    exit 1
fi
echo "  requirements.txt looks valid"

# Test 6: Check GitHub Actions workflow
echo "✓ Checking GitHub Actions workflow..."
if [[ ! -f ".github/workflows/release.yml" ]]; then
    echo "✗ Missing .github/workflows/release.yml"
    exit 1
fi
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" || {
    echo "✗ release.yml is not valid YAML"
    exit 1
}
echo "  GitHub Actions workflow is valid"

# Test 7: Verify CLI entry points exist
echo "✓ Checking CLI entry points..."
if ! grep -q "def main" src/argus_v/retina/cli.py; then
    echo "✗ Retina CLI missing main()"
    exit 1
fi
if ! grep -q "def main" src/argus_v/mnemosyne/cli.py; then
    echo "✗ Mnemosyne CLI missing main()"
    exit 1
fi
echo "  CLI entry points found"

# Test 8: Check example configs are valid YAML
echo "✓ Checking example configurations..."
python3 -c "import yaml; yaml.safe_load(open('example-retina-config.yaml'))" || {
    echo "✗ example-retina-config.yaml is not valid YAML"
    exit 1
}
python3 -c "import yaml; yaml.safe_load(open('mnemosyne-config.example.yaml'))" || {
    echo "✗ mnemosyne-config.example.yaml is not valid YAML"
    exit 1
}
python3 -c "import yaml; yaml.safe_load(open('aegis-config.example.yaml'))" || {
    echo "✗ aegis-config.example.yaml is not valid YAML"
    exit 1
}
echo "  Example configs are valid YAML"

# Test 9: Check install script has all required functions
echo "✓ Checking install.sh functions..."
required_functions=(
    "check_root"
    "detect_os"
    "check_python"
    "install_dependencies"
    "create_user"
    "create_directories"
    "install_package"
    "generate_retina_config"
    "generate_mnemosyne_config"
    "generate_aegis_config"
    "create_retina_service"
    "create_mnemosyne_service"
    "create_aegis_service"
    "setup_logrotate"
)

for func in "${required_functions[@]}"; do
    if ! grep -q "${func}()" install.sh; then
        echo "✗ install.sh missing function: ${func}()"
        exit 1
    fi
done
echo "  All required functions present"

# Test 10: Simulate tarball creation
echo "✓ Simulating release tarball creation..."
VERSION="v0.1.0-test"
PKGNAME="argus_v-${VERSION}"
TMPDIR=$(mktemp -d)

trap "rm -rf $TMPDIR" EXIT

mkdir -p "$TMPDIR/$PKGNAME"
cp -a src "$TMPDIR/$PKGNAME/" 2>/dev/null || true
cp -a README.md README.COMPLIANCE.md README.Docs "$TMPDIR/$PKGNAME/" 2>/dev/null || true
cp -a configs "$TMPDIR/$PKGNAME/" 2>/dev/null || true
cp -a example-retina-config.yaml mnemosyne-config.example.yaml aegis-config.example.yaml "$TMPDIR/$PKGNAME/" 2>/dev/null || true
cp -a pyproject.toml requirements.txt install.sh uninstall.sh LICENSE "$TMPDIR/$PKGNAME/" 2>/dev/null || true
cp -a run_train.sh run_trainer.py "$TMPDIR/$PKGNAME/" 2>/dev/null || true

if [[ ! -f "$TMPDIR/$PKGNAME/install.sh" ]]; then
    echo "✗ Failed to stage install.sh for tarball"
    exit 1
fi

if [[ ! -d "$TMPDIR/$PKGNAME/src" ]]; then
    echo "✗ Failed to stage src/ for tarball"
    exit 1
fi

echo "  Tarball simulation successful"

echo ""
echo "================================================"
echo "✓ All tests passed!"
echo "================================================"
echo ""
echo "Package is ready for installation and release."
