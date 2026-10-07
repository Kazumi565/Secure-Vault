from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./data/vault.db"
    master_key: str
    previous_master_keys: str = ""
    frontend_url: str = "http://localhost:3000"
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    cookie_secure: bool = False
    session_hours: int = Field(default=12, ge=1, le=168)
    max_storage_bytes: int = Field(default=100 * 1024 * 1024, ge=1024)
    max_upload_bytes: int = Field(default=25 * 1024 * 1024, ge=1)
    trash_days: int = Field(default=30, ge=1, le=365)
    storage_backend: str = "local"
    storage_path: Path = Path("data/objects")
    s3_bucket_name: str = ""
    aws_region: str = "eu-north-1"
    s3_endpoint_url: str | None = None
    email_provider: str = "console"
    email_from: str = "vault@localhost"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_tls: bool = True
    smtp_ssl: bool = False
    login_limit: int = 10
    testing: bool = False

    @model_validator(mode="after")
    def validate_configuration(self):
        Fernet(self.master_key.encode())
        for key in self.previous_master_keys.split(","):
            if key.strip():
                Fernet(key.strip().encode())
        if self.storage_backend not in {"local", "s3"}:
            raise ValueError("STORAGE_BACKEND must be local or s3")
        if self.storage_backend == "s3" and not self.s3_bucket_name:
            raise ValueError("S3_BUCKET_NAME is required for S3 storage")
        if self.email_provider not in {"console", "smtp"}:
            raise ValueError("EMAIL_PROVIDER must be console or smtp")
        if self.email_provider == "smtp" and not self.smtp_host:
            raise ValueError("SMTP_HOST is required for SMTP delivery")
        if self.environment == "production":
            if self.testing:
                raise ValueError("Testing mode cannot be enabled in production")
            if not self.cookie_secure or not self.frontend_url.startswith("https://"):
                raise ValueError("Production requires HTTPS and secure cookies")
            if self.email_provider != "smtp":
                raise ValueError("Production requires SMTP delivery")
            if not (self.smtp_tls or self.smtp_ssl):
                raise ValueError("Production SMTP must use TLS")
            if "*" in self.allowed_hosts:
                raise ValueError("Production requires explicit allowed hosts")
        return self

    @property
    def origins(self):
        return [self.frontend_url.rstrip("/")]
