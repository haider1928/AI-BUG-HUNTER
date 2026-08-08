"""Simple knowledge base loader and accessor for XSS knowledge.

This module exposes `knowledge_base_handler` as a singleton with a small
API used by the offline heuristic engine and the system prompt builder.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

class KnowledgeHandler:
    def __init__(self, knowledge_file="knowledge_base/xss_knowledge_base.json"):
        self.knowledge_file = Path(knowledge_file)
        self.knowledge = self._load_knowledge()
        self.reference_map = self._create_reference_map()

    def _load_knowledge(self):
        """Load the JSON knowledge base from disk.

        Returns the parsed JSON structure (usually a dict).
        """
        if not self.knowledge_file.exists():
            raise FileNotFoundError(f"Knowledge file not found: {self.knowledge_file}")
        with self.knowledge_file.open('r', encoding='utf-8-sig') as f:
            return json.load(f)

    def _create_reference_map(self) -> Dict[str, Any]:
        """Convert nested knowledge to flat reference map.

        Returns a mapping of reference paths -> value for quick lookup.
        """
        ref_map = {}

        def traverse(path, obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    traverse(new_path, value)
            elif isinstance(obj, list):
                for index, item in enumerate(obj):
                    ref_map[f"{path}.{index}"] = item
            else:
                ref_map[path] = obj

        traverse("", self.knowledge)
        return ref_map

    def get_available_references(self) -> Dict[str, Any]:
        """Get all available knowledge references as a flat map.

        This is a read-only view of the internal reference map.
        """
        return self.reference_map

    def get_reference_keys(self) -> List[str]:
        """Get all available reference keys for system prompt."""
        return list(self.reference_map.keys())

    def get_knowledge(self, ref_path: str) -> Any:
        """Get specific knowledge by reference path.

        Returns the value or the string "Reference not found" if missing.
        """
        return self.reference_map.get(ref_path, "Reference not found")

    def search_knowledge(self, search_term: str) -> Dict[str, Any]:
        """Search for knowledge containing specific terms.

        Returns a map of matching reference keys to values.
        """
        results: Dict[str, Any] = {}
        for key, value in self.reference_map.items():
            if (search_term.lower() in key.lower() or 
                (isinstance(value, str) and search_term.lower() in value.lower())):
                results[key] = value
        return results

knowledge_base_handler = KnowledgeHandler()

if __name__ == "__main__":
    print(knowledge_base_handler.search_knowledge("reflected"))