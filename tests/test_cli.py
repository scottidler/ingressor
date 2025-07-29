"""Tests for ingressor CLI."""

import tempfile
from pathlib import Path
from unittest.mock import patch
import sys
from io import StringIO

import pytest
import yaml

from ingressor.cli import main


class TestCLI:
    """Tests for CLI commands."""
    
    def test_version_command(self):
        """Test version command."""
        with patch('sys.argv', ['ingressor', 'version']):
            with patch('sys.stdout', new=StringIO()) as fake_out:
                main()
                output = fake_out.getvalue()
                assert "Ingressor" in output
                assert "0.1.0" in output
    
    def test_init_config_command(self):
        """Test init-config command."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_path = f.name
        
        try:
            with patch('sys.argv', ['ingressor', 'init-config', '-o', config_path]):
                with patch('sys.stdout', new=StringIO()) as fake_out:
                    main()
                    output = fake_out.getvalue()
                    assert "Sample configuration written" in output
            
            # Verify the config file was created and is valid YAML
            config_file = Path(config_path)
            assert config_file.exists()
            
            with open(config_file) as f:
                config_data = yaml.safe_load(f)
            
            assert "clusters" in config_data
            assert "scan_interval" in config_data
            assert isinstance(config_data["clusters"], list)
            
        finally:
            Path(config_path).unlink(missing_ok=True)
    
    def test_init_config_stdout(self):
        """Test init-config command output to stdout."""
        with patch('sys.argv', ['ingressor', 'init-config']):
            with patch('sys.stdout', new=StringIO()) as fake_out:
                main()
                output = fake_out.getvalue()
                assert "Sample configuration:" in output
                assert "clusters:" in output
    
    def test_validate_config_invalid_file(self):
        """Test validate-config with non-existent file."""
        with patch('sys.argv', ['ingressor', 'validate-config', '-c', 'nonexistent.yaml']):
            with patch('sys.stderr', new=StringIO()) as fake_err:
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1
                assert "No such file" in fake_err.getvalue()
    
    def test_help_command(self):
        """Test help command."""
        with patch('sys.argv', ['ingressor', '--help']):
            with patch('sys.stdout', new=StringIO()) as fake_out:
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
                output = fake_out.getvalue()
                assert "Ingressor: Multi-cluster Kubernetes service discovery" in output
                assert "serve" in output
                assert "scan" in output
                assert "init-config" in output
                assert "validate-config" in output 