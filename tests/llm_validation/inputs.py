"""
LLM Validation Suite — 20 test inputs covering all intent types
Target: >95% valid structured JSON output from Orchestrator
"""

VALIDATION_INPUTS = [
    {
        "id": 1,
        "input": "Run reconnaissance on example.com",
        "expected_intent": "reconnaissance",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Network"],
    },
    {
        "id": 2,
        "input": "Scan 192.168.1.100 for open ports",
        "expected_intent": "scan",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Network"],
    },
    {
        "id": 3,
        "input": "Find vulnerabilities in http://app.target.com",
        "expected_intent": "vulnerability_scan",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Application"],
    },
    {
        "id": 4,
        "input": "Test this API for SQL injection",
        "expected_intent": "exploitation",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Application"],
    },
    {
        "id": 5,
        "input": "Run full pentest on target.com",
        "expected_intent": "pentest",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Network", "Application"],
    },
    {
        "id": 6,
        "input": "Check my AWS environment for misconfigurations",
        "expected_intent": "cloud_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Cloud"],
    },
    {
        "id": 7,
        "input": "Audit Azure subscription for security issues",
        "expected_intent": "cloud_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Cloud"],
    },
    {
        "id": 8,
        "input": "Scan GCP project for compliance gaps",
        "expected_intent": "cloud_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Cloud"],
    },
    {
        "id": 9,
        "input": "Test JWT token for vulnerabilities",
        "expected_intent": "iam_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["IAM"],
    },
    {
        "id": 10,
        "input": "Check OAuth configuration for misconfigurations",
        "expected_intent": "iam_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["IAM"],
    },
    {
        "id": 11,
        "input": "Audit SAML setup for vulnerabilities",
        "expected_intent": "iam_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["IAM"],
    },
    {
        "id": 12,
        "input": "Find secrets in this repository",
        "expected_intent": "secrets_discovery",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Data Security"],
    },
    {
        "id": 13,
        "input": "Check TLS configuration on target.com",
        "expected_intent": "tls_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Data Security"],
    },
    {
        "id": 14,
        "input": "Scan for PII in HTTP responses",
        "expected_intent": "pii_discovery",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Data Security"],
    },
    {
        "id": 15,
        "input": "Test endpoint 10.0.0.5 for privilege escalation",
        "expected_intent": "endpoint_assessment",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["Endpoint"],
    },
    {
        "id": 16,
        "input": "Test this PyTorch model for adversarial evasion",
        "expected_intent": "model_security",
        "expected_engine": "MLAIEngine",
        "expected_fields": ["Adversarial ML"],
    },
    {
        "id": 17,
        "input": "Probe this chatbot for prompt injection",
        "expected_intent": "genai_security",
        "expected_engine": "MLAIEngine",
        "expected_fields": ["Generative AI Security"],
    },
    {
        "id": 18,
        "input": "Check this LLM for sensitive information disclosure",
        "expected_intent": "genai_security",
        "expected_engine": "MLAIEngine",
        "expected_fields": ["Generative AI Security"],
    },
    {
        "id": 19,
        "input": "Find CVEs for the Apache version detected",
        "expected_intent": "intel_gathering",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": ["All"],
    },
    {
        "id": 20,
        "input": "What's the status of the current scan?",
        "expected_intent": "status_query",
        "expected_engine": "InfrastructureEngine",
        "expected_fields": [],
    },
]


def get_orchestrator_output_schema():
    """Expected OrchestratorDecision JSON schema"""
    return {
        "required": ["intent", "engine", "target", "constraints", "phase"],
        "properties": {
            "intent": {"type": "string"},
            "engine": {"type": "string", "enum": ["InfrastructureEngine", "MLAIEngine", "ICSEngine"]},
            "target": {"type": "string"},
            "constraints": {"type": "object"},
            "phase": {"type": "string"},
            "tools": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"},
        },
    }