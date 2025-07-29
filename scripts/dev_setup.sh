#!/bin/bash
set -e

echo "🔧 Setting up Ingressor development environment..."

# Check if Python 3.12+ is available
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.12"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✅ Python $python_version is compatible"
else
    echo "❌ Python $python_version is not compatible. Please install Python 3.12 or higher."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Install uv if not already installed
if ! command -v uv &> /dev/null; then
    echo "📦 Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

# Activate virtual environment
echo "🚀 Activating virtual environment..."
source venv/bin/activate

# Install package in development mode with uv
echo "📚 Installing ingressor in development mode..."
uv pip install -e ".[dev]"

# Install pre-commit hooks
echo "🔍 Setting up pre-commit hooks..."
pre-commit install

# Create sample config if it doesn't exist
if [ ! -f "config.yaml" ]; then
    echo "📄 Creating sample configuration file..."
    python -c "
from ingressor.cli import main
from click.testing import CliRunner
runner = CliRunner()
result = runner.invoke(main, ['init-config', '-o', 'config.yaml'])
"
    echo "✅ Sample configuration created at config.yaml"
    echo "📝 Please edit config.yaml to match your Kubernetes clusters"
fi

# Run tests to make sure everything works
echo "🧪 Running tests to verify setup..."
pytest --tb=short

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Edit config.yaml to match your clusters"
echo "3. Start the development server: ingressor serve --config config.yaml --reload"
echo "4. Open http://localhost:8000 in your browser"
echo ""
echo "Useful commands:"
echo "- Run tests: pytest"
echo "- Run linting: ruff check ."
echo "- Format code: ruff format ."
echo "- Type check: mypy ingressor"
echo "- One-time scan: ingressor scan --config config.yaml" 