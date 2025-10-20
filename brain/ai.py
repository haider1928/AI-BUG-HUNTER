import os
import json
import logging
import requests
from datetime import datetime
from typing import Optional, Dict, Any, List
import re
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from knowledge_base_handler import knowledge_base_handler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# =======================
# CONFIG
# =======================
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "deepseek-v3.1:671b-cloud"

# Generate reference information for the system prompt
available_refs = knowledge_base_handler.get_reference_keys()
refs_text = "\n".join([f"- {ref}" for ref in available_refs])


SYSTEM_PROMPT = """
You are a highly skilled cybersecurity assistant specialized in pentesting and bug hunting. 
type field MUST be exactly one of: "command" or "script" 
You can ONLY respond with one command/script per step. 
After executing the command/script, you will be provided the filtered output. 
Only stop when the target is compromised with a proof. 
USE SCRIPT FOR REPEATED ACTIONS LIKE SQL UNION ATTACK, ETC.
DONT GIVE SUCH AI COMMANDS WHOSE RESULTS WILL BE SAVED TO FILES
For each command, respond strictly in JSON format with the fields:

{{
  "type": "<command or script>",
  "content": "<command or script code>",
  "script_name": "<script filename if script>",
  "script_type": "<bash or python if script>",
  "reason": "<short explaination>",
  "output_name": "<filename to save raw output (this will be used only for scripts)>",
  "return_to_ai": "<command to filter/summarize output before sending back>",
  "vuln": "<the vulnerability you are testing in the target or the phase of attack>",
  "continue": "<true or false>"
}}
Example for bash script:
{{
  "type": "script",
  "script_type": "bash",
  "content": "echo 'Hello World'",
  "script_name": "hello.sh",
  "reason": "Testing bash execution",
  "output_name": "hello_output.txt",
  "return_to_ai": "cat hello_output.txt",
  "continue": true
}}

Example for single command:
{{
  "type": "command",
  "content": "curl -I https://example.com",
  "reason": "Checking HTTP headers",
  "output_name": "headers.txt",
  "return_to_ai": "grep 'Server' headers.txt",
  "continue": true
}}
The results of your commands/scripts are in commdand_outputs/<output_name>.

Rules:
- Only give ONE command/script per step.
- Never add explanations outside JSON.
- Always make sure output_name is a valid simple filename (no spaces).
- return_to_ai should be a command that processes the saved file and extracts only useful info.
- Always include #!/bin/bash at the top of bash scripts.
- Never give None output.
Treat the environment as a live pentesting lab.
"""

# =======================
# MODEL INIT
# =======================
class AICyberSecurityAssistant:
    def __init__(self):
        self.model_name = OLLAMA_MODEL
        self.base_url = OLLAMA_BASE_URL.rstrip('/')
        self.conversation_history: List[Dict[str, str]] = []
        self.history_file = "conversation_history.json"
        self.load_history()
        logger.info(f"Ollama assistant initialized with model: {self.model_name}")

    def load_history(self):
        """Load conversation history from file if exists."""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.conversation_history = data.get('history', [])
                logger.info(f"Loaded {len(self.conversation_history)} messages from memory")
        except Exception as e:
            logger.warning(f"Could not load conversation history: {e}")

    def save_history(self):
        """Save conversation history to file."""
        try:
            data = {
                'history': self.conversation_history,
                'model': self.model_name,
                'timestamp': datetime.now().isoformat()
            }
            with open(self.history_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save conversation history: {e}")
    
    
    def validate_response(self, response: str) -> bool:
        """
        Validate AI response is proper JSON with required structure.
        
        Args:
            response (str): AI response to validate
            
        Returns:
            bool: True if valid JSON with correct structure, False otherwise
        """
        if not isinstance(response, str):
            logger.error("AI response must be a string")
            return False
        
        if not response or not response.strip():
            logger.error("AI response is empty")
            return False
        
        try:
            # Clean response first (remove markdown code blocks)
            cleaned = self.clean_ai_response(response)
            
            if not cleaned:
                logger.error("AI response is empty after cleaning")
                return False
                
            # Parse JSON
            parsed = json.loads(cleaned)
            
            # Strict checks
            if parsed is None:
                logger.error("AI response is null")
                return False
                
            if not isinstance(parsed, dict):
                logger.error("AI response must be a JSON object")
                return False
                
            # Check required fields for AI command structure
            required_fields = ["type", "content", "reason", "continue"]
            for field in required_fields:
                if field not in parsed:
                    logger.error(f"Missing required field: {field}")
                    return False
                    
            # Validate type field
            if parsed["type"] not in ["command", "script", "bash", "python"]:
                logger.error(f"Invalid type field: {parsed['type']}")
                return False
                
            # Validate script-specific fields if type is script
            if parsed["type"] == "script":
                if "script_type" not in parsed or parsed["script_type"] not in ["bash", "python"]:
                    logger.error("Script type missing or invalid")
                    return False
                if "script_name" not in parsed:
                    logger.error("Script name missing for script type")
                    return False
                    
            # Validate continue field is boolean
            if not isinstance(parsed["continue"], bool):
                logger.error("Continue field must be boolean")
                return False
                
            # Validate content field is string
            if not isinstance(parsed["content"], str):
                logger.error("Content field must be string")
                return False
                
            # Validate reason field is string
            if not isinstance(parsed["reason"], str):
                logger.error("Reason field must be string")
                return False
                
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"AI response is not valid JSON: {e}")
            return False
        except Exception as e:
            logger.error(f"Error validating AI response: {e}")
            return False
        
        
        
    def add_to_history(self, role: str, content: str) -> None:
        """
        Add a message to conversation history
        
        Args:
            role (str): Either 'user' or 'assistant'
            content (str): Message content
        """
        self.conversation_history.append({
            'role': role,
            'content': content,
            'timestamp': datetime.now().isoformat()
        })
        self.save_history()

    def get_context(self, limit: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Get conversation context (recent messages)
        
        Args:
            limit (int, optional): Number of recent messages to return
            
        Returns:
            List of message dictionaries
        """
        if limit:
            return self.conversation_history[-limit:]
        return self.conversation_history

    def build_full_prompt(self, prompt: str) -> str:
        """
        Build full prompt with system instruction and conversation history
        
        Args:
            prompt (str): Current user prompt
            
        Returns:
            str: Full formatted prompt
        """
        # Prepare the full prompt with context
        context_messages = self.get_context(20)  # Last 20 messages for context
        
        # Build context string
        context_text = ""
        for msg in context_messages:
            if msg['role'] == 'user':
                context_text += f"Human: {msg['content']}\n"
            elif msg['role'] == 'assistant':
                context_text += f"Assistant: {msg['content']}\n"
        
        # Add current prompt
        full_prompt = f"{context_text}Human: {prompt}\nAssistant:"
        
        # Add system prompt at the beginning
        return f"{SYSTEM_PROMPT}\n\n{full_prompt}"

    def chat(self, prompt: str) -> Optional[str]:
        """Send message to Ollama and get response."""
        try:
            # Add user message to history
            self.add_to_history('user', prompt)
            
            # Build full prompt with context
            full_prompt = self.build_full_prompt(prompt)
            
            # Prepare API request
            url = f"{self.base_url}/api/generate"
            payload = {
                'model': self.model_name,
                'prompt': full_prompt,
                'stream': False,
                'options': {
                    'temperature': 0.7,
                    'num_predict': 1500
                }
            }
            
            # Make API call
            response = requests.post(url, json=payload, timeout=300)
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            assistant_response = result.get('response', '').strip()
            
            # Add assistant response to history
            if assistant_response:
                self.add_to_history('assistant', assistant_response)
            
            return assistant_response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response content: {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"Error in chat(): {e}")
            return None

    def validate_response(self, response: str) -> bool:
        """Validate AI response is proper JSON with required fields."""
        try:
            # Clean response first
            cleaned = self.clean_ai_response(response)
            data = json.loads(cleaned)
            
            # Check required fields
            required = ["type", "content", "reason", "continue"]
            for field in required:
                if field not in data:
                    logger.error(f"Missing required field: {field}")
                    return False
                    
            # Validate type
            if data["type"] not in ["command", "script"]:
                logger.error(f"Invalid type: {data['type']}")
                return False
                
            # Validate script fields if type is script
            if data["type"] == "script":
                if "script_type" not in data or data["script_type"] not in ["bash", "python"]:
                    logger.error("Script type missing or invalid")
                    return False
                if "script_name" not in data:
                    logger.error("Script name missing for script type")
                    return False
                    
            # Validate knowledge_ref if provided
            if "knowledge_ref" in data and data["knowledge_ref"]:
                knowledge = knowledge_base_handler.get_knowledge(data["knowledge_ref"])
                if not knowledge:
                    logger.warning(f"Invalid knowledge reference: {data['knowledge_ref']}")
                    # Don't fail validation for invalid knowledge ref, just warn
                    
            return True
            
        except json.JSONDecodeError:
            logger.error("AI response is not valid JSON")
            return False
        except Exception as e:
            logger.error(f"Error validating AI response: {e}")
            return False

    @staticmethod
    def clean_ai_response(raw: str) -> str:
        """Clean AI response by removing code block markers."""
        if not raw:
            return ""
        return re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()


# Global instance
ai_assistant = AICyberSecurityAssistant()

# =======================
# TESTING MODE
# =======================
if __name__ == "__main__":
    print("CyberSec AI Chat (type 'exit' to quit)")
    ai_assistant.chat("Hello, I am ready to start. The target is an internal network.")

    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            print("Exiting CyberSec AI Chat.")
            break
            
        response = ai_assistant.chat(user_input)
        if response:
            print("AI:", response)
            
            # Validate the response
            if ai_assistant.validate_response(response):
                print("✓ Response is valid")
                
                # Extract knowledge reference if present
                try:
                    cleaned = ai_assistant.clean_ai_response(response)
                    data = json.loads(cleaned)
                    if "knowledge_ref" in data and data["knowledge_ref"]:
                        knowledge = knowledge_base_handler.get_knowledge(data["knowledge_ref"])
                        if knowledge:
                            print(f"📚 Knowledge reference: {data['knowledge_ref']}")
                            # You could log or display the knowledge here
                except:
                    pass  # Don't break if we can't parse the knowledge ref
            else:
                print("✗ Response validation failed")
        else:
            print("No response from AI.")
