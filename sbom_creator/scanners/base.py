"""Base scanner interface for SBOM Creator."""
from abc import ABC, abstractmethod
from typing import List
from sbom_creator.models import Component

class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    @abstractmethod
    def scan(self) -> List[Component]:
        """Perform scan and return list of discovered components."""
        pass
