from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    bearer_token: str = "dev-token"
    anthropic_api_key: str = ""
    ollama_host: str = "http://localhost:11434"
    claude_model: str = "claude-sonnet-4-6"
    mistral_model: str = "mistral:7b"
    embed_model: str = "nomic-embed-text"
    kali_host: str = "localhost"
    kali_port: int = 22
    kali_user: str = "kali"
    kali_password: str = ""
    summariser_threshold: int = 60000
    qwen_model: str = "qwen2.5:7b"
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
