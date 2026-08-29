"""
Configuration settings for AEGIS using Pydantic for validation.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "AEGIS"
    app_version: str = "0.1.0"
    debug: bool = False
    
    # Network Capture
    capture_interface: str = Field(
        default=r"\Device\NPF_{FC3C14A0-C35F-4038-9C6B-117B020AF461}",
        description="Network interface to capture packets from"
    )
    capture_filter: str = Field(
        default="tcp or udp",
        description="BPF filter for packet capture"
    )
    capture_promiscuous: bool = False
    
    # Flow Processing
    flow_window_seconds: int = Field(
        default=5,
        description="Time window for flow aggregation in seconds"
    )
    flow_timeout_seconds: int = Field(
        default=60,
        description="Timeout for inactive flows"
    )
    
    # Detection Thresholds
    port_scan_threshold: int = Field(
        default=20,
        description="Number of unique destination ports to flag as port scan"
    )
    port_scan_time_window: int = Field(
        default=10,
        description="Time window for port scan detection in seconds"
    )
    
    syn_rate_threshold: float = Field(
        default=10.0,
        description="SYN packets per second threshold"
    )
    syn_incomplete_ratio: float = Field(
        default=0.7,
        description="Ratio of incomplete connections to flag as SYN flood"
    )
    
    traffic_spike_multiplier: float = Field(
        default=3.0,
        description="Multiplier over baseline to flag as traffic spike"
    )
    traffic_baseline_window: int = Field(
        default=60,
        description="Window to calculate traffic baseline in seconds"
    )
    
    # Threat Scoring
    threat_score_low: int = 29
    threat_score_medium: int = 59
    threat_score_high: int = 79
    
    # Response Policy
    safe_mode: bool = Field(
        default=True,
        description="When True, simulate blocking actions instead of executing"
    )
    block_duration_seconds: int = Field(
        default=60,
        description="Duration of temporary IP blocks"
    )
    
    # Database
    database_url: str = Field(
        default="sqlite:///aegis.db",
        description="Database connection URL"
    )
    
    # API
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    
    # Logging
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()
