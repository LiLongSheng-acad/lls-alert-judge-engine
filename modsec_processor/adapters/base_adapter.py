# adapters/base_adapter.py
from abc import ABC, abstractmethod

class BaseAdapter(ABC):
    @abstractmethod
    def match(self, raw_line: str) -> bool:
        pass
    
    @abstractmethod
    def parse(self, raw_line: str):
        pass