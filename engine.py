import json
import os

class ShovelEngine:
    def __init__(self, dork_file="dorks.json"):
        """Initializes the engine and loads the dork library."""
        self.dork_library = self._load_dorks(dork_file)

    def _load_dorks(self, filepath):
        """Safely loads the JSON file."""
        if not os.path.exists(filepath):
            return {"⚠️ Error": [f"Could not find {filepath}. Please ensure it exists."]}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {"⚠️ Error": ["Failed to parse dorks.json. Check formatting."]}

    def generate_queries(self, target):
        """Injects the target into the dorks and returns the formatted dictionary."""
        results = {}
        for category, queries in self.dork_library.items():
            # Replace the {target} placeholder with the actual domain
            results[category] = [q.replace("{target}", target) for q in queries]
        return results