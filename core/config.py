#!/usr/bin/env python3
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class Config:
    """Configuration manager for the Offsec project."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config/settings.json"
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            config_file = Path(self.config_path)
            if config_file.exists():
                with config_file.open("r") as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
                return config
            else:
                logger.warning(f"Configuration file {self.config_path} not found, using defaults")
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "general": {
                "output_directory": "outputs",
                "log_level": "INFO",
                "log_format": "%(asctime)s - %(levelname)s - %(message)s",
                "default_timeout": None,
                "max_concurrent_processes": 4
            },
            "exploitation": {
                "default_attacker_ip": "192.168.1.16",
                "default_attacker_port": "4444",
                "metasploit_timeout": None,
                "hydra_timeout": None,
                "sqlmap_timeout": None,
                "enable_rockyou_by_default": False,
                "rockyou_path": "/usr/share/wordlists/rockyou.txt",
                "common_passwords_path": "commonpasswords.txt"
            },
            "credentials": {
                "metasploitable2": {
                    "usernames": ["msfadmin", "user", "postgres", "sys", "klog", "service", "root", "admin", "test", "ftp", "anonymous", "guest"],
                    "passwords": ["msfadmin", "user", "postgres", "batman", "123456789", "service", "root", "admin", "test", "ftp", "", "guest"]
                }
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'general.output_directory')."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_service_config(self, service: str) -> Dict[str, Any]:
        """Get configuration for a specific service."""
        return self.config.get("services", {}).get(service, {})
    
    def get_credentials(self, target_type: str = "metasploitable2") -> Dict[str, Any]:
        """Get credentials for a specific target type."""
        return self.config.get("credentials", {}).get(target_type, {})
    
    def get_wordlists(self) -> Dict[str, str]:
        """Get wordlist paths."""
        return self.config.get("wordlists", {})
    
    def is_service_enabled(self, service: str) -> bool:
        """Check if a service is enabled."""
        service_config = self.get_service_config(service)
        return service_config.get("enabled", True)
    
    def get_service_timeout(self, service: str) -> Optional[int]:
        """Get timeout for a specific service."""
        service_config = self.get_service_config(service)
        return service_config.get("timeout")
    
    def get_rockyou_path(self) -> str:
        """Get rockyou.txt path."""
        return self.config.get("exploitation", {}).get("rockyou_path", "/usr/share/wordlists/rockyou.txt")
    
    def get_common_passwords_path(self) -> str:
        """Get common passwords file path."""
        return self.config.get("exploitation", {}).get("common_passwords_path", "commonpasswords.txt")
    
    def get_output_directory(self) -> str:
        """Get output directory path."""
        return self.config.get("general", {}).get("output_directory", "outputs")
    
    def get_log_level(self) -> str:
        """Get log level."""
        return self.config.get("general", {}).get("log_level", "INFO")
    
    def get_log_format(self) -> str:
        """Get log format."""
        return self.config.get("general", {}).get("log_format", "%(asctime)s - %(levelname)s - %(message)s")
    
    def get_max_concurrent_processes(self) -> int:
        """Get maximum concurrent processes."""
        return self.config.get("general", {}).get("max_concurrent_processes", 4)
    
    def reload(self):
        """Reload configuration from file."""
        self.config = self._load_config()
        logger.info("Configuration reloaded")
    
    def save(self):
        """Save current configuration to file."""
        try:
            config_file = Path(self.config_path)
            config_file.parent.mkdir(exist_ok=True)
            with config_file.open("w") as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")

# Global configuration instance
config = Config() 