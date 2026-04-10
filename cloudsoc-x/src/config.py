"""
Central configuration for CloudSOC-X.

All environment variables are read here. Import this module
instead of calling os.environ directly in other files.
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # AWS
    aws_region: str = field(default_factory=lambda: os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    aws_profile: str = field(default_factory=lambda: os.environ.get("AWS_PROFILE", "default"))

    # OpenSearch
    opensearch_endpoint: str = field(default_factory=lambda: os.environ.get("OPENSEARCH_ENDPOINT", ""))
    opensearch_index: str = field(default_factory=lambda: os.environ.get("OPENSEARCH_INDEX", "cloudsoc-alerts"))

    # SNS
    sns_topic_arn: str = field(default_factory=lambda: os.environ.get("SNS_TOPIC_ARN", ""))

    # Kinesis
    kinesis_stream_name: str = field(default_factory=lambda: os.environ.get("KINESIS_STREAM_NAME", "cloudsoc-events"))

    # Enrichment
    ipinfo_token: str = field(default_factory=lambda: os.environ.get("IPINFO_TOKEN", ""))

    # API
    api_port: int = field(default_factory=lambda: int(os.environ.get("PORT", 8000)))
    flask_env: str = field(default_factory=lambda: os.environ.get("FLASK_ENV", "production"))
    api_secret_key: str = field(default_factory=lambda: os.environ.get("API_SECRET_KEY", "change-me-in-production"))

    # Detection tuning
    severity_alert_threshold: set = field(default_factory=lambda: {"critical", "high"})
    max_alerts_in_memory: int = field(default_factory=lambda: int(os.environ.get("MAX_ALERTS", 500)))

    @property
    def is_development(self) -> bool:
        return self.flask_env == "development"

    @property
    def opensearch_configured(self) -> bool:
        return bool(self.opensearch_endpoint)

    @property
    def sns_configured(self) -> bool:
        return bool(self.sns_topic_arn)


# Singleton — import this everywhere
settings = Config()
