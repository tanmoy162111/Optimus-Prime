from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    bearer_token: str = "dev-token"
    anthropic_api_key: str = ""
    ollama_host: str = "http://localhost:11434"
    claude_model: str = "claude-opus-4-7"
    mistral_model: str = "mistral:7b"
    embed_model: str = "nomic-embed-text"
    kali_host: str = "localhost"
    kali_port: int = 22
    kali_user: str = "kali"
    kali_password: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
