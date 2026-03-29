import yaml
import os
from typing import Dict, Any

class ConfigManager:
    """
    Universal configuration manager for all environments
    """
    
    def __init__(self, env: str = None):
        self.config_file = "config/environments.yaml"
        self.configs = self.load_configs()
        self.current_env = env or os.getenv("ZT_ENVIRONMENT", "banking")
        self.config = self.configs.get(self.current_env, {})
    
    def load_configs(self) -> Dict[str, Any]:
        """Load all environment configurations"""
        try:
            with open(self.config_file, 'r') as f:
                data = yaml.safe_load(f)
                return data.get('environments', {})
        except FileNotFoundError:
            print(f"⚠️ Config file not found: {self.config_file}")
            return {}
    
    def get_organization_name(self) -> str:
        return self.config.get('name', 'ZTForensics')
    
    def get_sector(self) -> str:
        return self.config.get('sector', 'Unknown')
    
    def get_risk_factors(self) -> Dict[str, int]:
        return self.config.get('risk_factors', {})
    
    def get_risk_threshold(self, level: str) -> int:
        thresholds = self.config.get('risk_thresholds', {})
        return thresholds.get(level, 50)
    
    def get_whitelist_locations(self) -> list:
        return self.config.get('whitelist_locations', [])
    
    def get_audit_settings(self) -> Dict[str, Any]:
        return self.config.get('audit', {})
    
    def is_hipaa_compliant(self) -> bool:
        audit = self.get_audit_settings()
        return audit.get('hipaa_compliant', False)
    
    def is_pci_compliant(self) -> bool:
        audit = self.get_audit_settings()
        return audit.get('pci_compliant', False)
    
    def requires_biometric(self) -> bool:
        audit = self.get_audit_settings()
        return audit.get('biometric_required', False)
    
    def get_audit_retention_days(self) -> int:
        audit = self.get_audit_settings()
        return audit.get('retention_days', 365)
    
    def print_settings(self):
        """Print current configuration"""
        print(f"\n{'='*70}")
        print(f"🌍 ENVIRONMENT: {self.current_env.upper()}")
        print(f"{'='*70}")
        print(f"Organization: {self.get_organization_name()}")
        print(f"Sector: {self.get_sector()}")
        print(f"Risk Thresholds:")
        print(f"  - Low: {self.get_risk_threshold('low')}/100")
        print(f"  - Medium: {self.get_risk_threshold('medium')}/100")
        print(f"  - High: {self.get_risk_threshold('high')}/100")
        print(f"  - Critical: {self.get_risk_threshold('critical')}/100")
        print(f"Audit Retention: {self.get_audit_retention_days()} days")
        print(f"HIPAA Compliant: {self.is_hipaa_compliant()}")
        print(f"PCI Compliant: {self.is_pci_compliant()}")
        print(f"Biometric Required: {self.requires_biometric()}")
        print(f"{'='*70}\n")

# Global instance
config_manager = ConfigManager()