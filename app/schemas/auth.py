from pydantic import BaseModel, ConfigDict, Field, SecretStr


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    login: str = Field(
        strict=True, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"
    )
    password: SecretStr = Field(min_length=6, max_length=128)
