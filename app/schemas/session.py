from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.schemas.user import UserRead


class CachedSession(BaseModel):
    id: UUID
    user: UserRead
    expires_at: datetime
