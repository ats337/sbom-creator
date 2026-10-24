"""Base formatter interface for SBOM outputs."""
from abc import ABC, abstractmethod
from sbom_creator.models import SBOMDocument

class BaseFormatter(ABC):
    """Abstract base class for output formatters."""

    @abstractmethod
    def format(self, doc: SBOMDocument) -> str:
        """Render SBOM document as string."""
        pass
