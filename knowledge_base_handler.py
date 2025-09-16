# knowledge_handler.py
import json

class KnowledgeHandler:
    def __init__(self, knowledge_file="knowledge_base/xss_knowledge_base.json"):
        with open(knowledge_file, 'r') as f:
            self.knowledge = json.load(f)
        self.reference_map = self._create_reference_map()
    
    def _create_reference_map(self):
        """Convert nested knowledge to flat reference map"""
        ref_map = {}
        
        def traverse(path, obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    traverse(new_path, value)
            elif isinstance(obj, list):
                # Store list items with index references
                for i, item in enumerate(obj):
                    ref_map[f"{path}.{i}"] = item
            else:
                ref_map[path] = obj
        
        traverse("", self.knowledge)
        return ref_map
    
    def get_reference_keys(self):
        """Get all available reference keys for system prompt"""
        return list(self.reference_map.keys())
    
    def get_knowledge(self, ref_path):
        """Get specific knowledge by reference path"""
        return self.reference_map.get(ref_path, "Reference not found")
    
    def search_knowledge(self, search_term):
        """Search for knowledge containing specific terms"""
        results = {}
        for key, value in self.reference_map.items():
            if (search_term.lower() in key.lower() or 
                (isinstance(value, str) and search_term.lower() in value.lower())):
                results[key] = value
        return results

# Example usage
handler = KnowledgeHandler()
print(handler.search_knowledge("reflected"))