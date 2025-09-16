import os
import json
import logging
import google.generativeai as genai
from datetime import datetime
from typing import Optional, Dict, Any
import re
from knowledge_base_handler import knowledge_base_handler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# =======================
# CONFIG
# =======================
API_KEY = os.getenv("GENAI_API_KEY")  # Always use environment variables for secrets
if not API_KEY:
    logger.error("GENAI_API_KEY environment variable not set")
    exit(1)

genai.configure(api_key=API_KEY)

# Generate reference information for the system prompt
available_refs = knowledge_base_handler.get_available_references()
refs_text = "\n".join([f"- {ref}: {desc}" for ref, desc in available_refs.items()])

SYSTEM_PROMPT = f"""
You are a highly skilled cybersecurity assistant specialized in pentesting and bug hunting. 
You have access to a comprehensive XSS knowledge base that you can reference using the knowledge_ref field.

You can ONLY respond with one command/script per step. 
After executing the command/script, you will be provided the filtered output. 
Only stop when the target is compromised with a proof. 
USE SCRIPT FOR REPEATED ACTIONS LIKE SQL UNION ATTACK, ETC.

For each command, respond strictly in JSON format with the fields:

{{
  "type": "<command or script>",
  "content": "<command or script code>",
  "script_name": "<script filename if script>",
  "script_type": "<bash or python if script>",
  "reason": "<short explanation>",
  "output_name": "<filename to save raw output>",
  "return_to_ai": "<command to filter/summarize output before sending back>",
  "vuln": "<the vulnerability you are testing in the target or the phase of attack>",
  "knowledge_ref": "<reference to knowledge base section (e.g., xss.type.reflected)>",
  "continue": "<true or false>"
}}

Rules:
- Only give ONE command/script per step.
- Never add explanations outside JSON.
- Always make sure output_name is a valid simple filename (no spaces).
- return_to_ai should be a command that processes the saved file and extracts only useful info.
- Always include #!/bin/bash at the top of bash scripts.
- Never give None output.
- Use the knowledge_ref field to reference specific knowledge from the XSS knowledge base.

Available knowledge base references:
{refs_text}

Treat the environment as a live pentesting lab.
"""

# =======================
# MODEL INIT
# =======================
class AICyberSecurityAssistant:
    def __init__(self):
        self.model = genai.GenerativeModel(
            model_name="gemini-2.5-flash",
            system_instruction=SYSTEM_PROMPT
        )
        self.conversation = self.model.start_chat(history=[])
        self.history_file = "conversation_history.json"
        self.load_history()

    def load_history(self):
        """Load conversation history from file if exists."""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    history_data = json.load(f)
                    # Reconstruct conversation history
                    for msg in history_data:
                        if msg['role'] == 'user':
                            self.conversation.history.append(
                                genai.types.Content(role="user", parts=[genai.types.Part(text=msg['content'])])
                            )
                        else:
                            self.conversation.history.append(
                                genai.types.Content(role="model", parts=[genai.types.Part(text=msg['content'])])
                            )
        except Exception as e:
            logger.warning(f"Could not load conversation history: {e}")

    def save_history(self):
        """Save conversation history to file."""
        try:
            history_data = []
            for msg in self.conversation.history:
                history_data.append({
                    'role': msg.role,
                    'content': msg.parts[0].text if msg.parts else '',
                    'timestamp': datetime.now().isoformat()
                })
            
            with open(self.history_file, 'w') as f:
                json.dump(history_data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save conversation history: {e}")

    def chat(self, prompt: str) -> Optional[str]:
        """Send message to AI and get response."""
        try:
            response = self.conversation.send_message(
                prompt,
                generation_config={
                    "max_output_tokens": 1500,
                    "temperature": 0.7
                }
            )
            
            if response.candidates and response.candidates[0].content.parts:
                result = response.candidates[0].content.parts[0].text.strip()
                self.save_history()
                return result
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