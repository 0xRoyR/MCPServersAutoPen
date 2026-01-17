from abc import ABC, abstractmethod
from pydantic import BaseModel


class ToolResult(BaseModel):
    success: bool
    output: str


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
