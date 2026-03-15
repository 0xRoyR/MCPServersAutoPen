from abc import ABC, abstractmethod
from pydantic import BaseModel


class ToolResult(BaseModel):
    success: bool
    output: str
    db_ref: dict | None = None  # Set when tool persists data to DB: {"table": ..., "rows_saved": ...}


class BaseTool(ABC):
    """
    Every security tool must implement this contract.
    """

    name: str
    description: str
    input_model: type[BaseModel]

    @abstractmethod
    def run(self, data: BaseModel) -> ToolResult:
        pass
