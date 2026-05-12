from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class CredentialVault:
    aws_credentials: Dict[str, str]
    azure_credentials: Dict[str, str]
    gcp_credentials: Dict[str, str]

    def __init__(self):
        self.aws_credentials = {}
        self.azure_credentials = {}
        self.gcp_credentials = {}

    def store(self, provider: str, credentials: Dict[str, str]):
        if provider == "aws":
            self.aws_credentials = credentials
        elif provider == "azure":
            self.azure_credentials = credentials
        elif provider == "gcp":
            self.gcp_credentials = credentials

    def get(self, provider: str) -> Dict[str, str]:
        if provider == "aws":
            return self.aws_credentials
        elif provider == "azure":
            return self.azure_credentials
        elif provider == "gcp":
            return self.gcp_credentials
        return {}

    def clear(self):
        self.aws_credentials = {}
        self.azure_credentials = {}
        self.gcp_credentials = {}