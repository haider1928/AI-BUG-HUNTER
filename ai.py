import os
import json
import logging
import warnings
from datetime import datetime
from typing import Optional
import re
from knowledge_base_handler import knowledge_base_handler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', FutureWarning)
        import google.generativeai as genai
except ImportError:
    genai = None
    logger.warning('google.generativeai is not installed, using offline fallback mode.')

API_KEY = os.getenv("GENAI_API_KEY")
USE_OFFLINE_FALLBACK = genai is None or not API_KEY

if genai and API_KEY:
    try:
        genai.configure(api_key=API_KEY)
    except Exception as exc:
        logger.warning(f"Could not configure Google Generative AI client: {exc}")
        USE_OFFLINE_FALLBACK = True

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

class AICyberSecurityAssistant:
    def __init__(self):
        self.history_file = "conversation_history.json"
        self.history = []
        self.running_offline = USE_OFFLINE_FALLBACK

        if not self.running_offline:
            self.model = genai.GenerativeModel(
                model_name="gemini-2.5-flash",
                system_instruction=SYSTEM_PROMPT
            )
            self.conversation = self.model.start_chat(history=[])
        else:
            self.model = None
            self.conversation = None

        self.load_history()

    def load_history(self):
        """Load conversation history from file if it exists."""
        self.history = []
        if not os.path.exists(self.history_file):
            return

        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                history_data = json.load(f)
                self.history = history_data

                if self.conversation is not None:
                    for msg in history_data:
                        if msg['role'] in ('user', 'model'):
                            self.conversation.history.append(
                                genai.types.Content(role=msg['role'], parts=[genai.types.Part(text=msg['content'])])
                            )
        except Exception as e:
            logger.warning(f"Could not load conversation history: {e}")

    def save_history(self):
        """Save conversation history to file."""
        try:
            history_data = []
            if self.conversation is not None:
                for msg in self.conversation.history:
                    history_data.append({
                        'role': msg.role,
                        'content': msg.parts[0].text if msg.parts else '',
                        'timestamp': datetime.now().isoformat()
                    })
            else:
                history_data = self.history

            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save conversation history: {e}")

    def chat(self, prompt: str) -> Optional[str]:
        """Send message to AI and get response."""
        if self.running_offline:
            response = self.offline_response(prompt)
            self.history.append({'role': 'user', 'content': prompt, 'timestamp': datetime.now().isoformat()})
            self.history.append({'role': 'model', 'content': response, 'timestamp': datetime.now().isoformat()})
            self.save_history()
            return response

        try:
            response = self.conversation.send_message(
                prompt,
                generation_config={
                    'max_output_tokens': 1500,
                    'temperature': 0.7
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

    def offline_response(self, prompt: str) -> str:
        """Return a fixed AI-like response when no API is available."""
        response = {
            'type': 'command',
            'content': 'python -c "print(\'offline AI response\')"',
            'reason': 'Offline fallback response for testing the command execution flow.',
            'output_name': 'offline_output.txt',
            'return_to_ai': 'python -c "print(open(\'offline_output.txt\').read())"',
            'vuln': 'offline-test',
            'continue': False
        }
        return json.dumps(response)

    def validate_response(self, response: str) -> bool:
        """Validate AI response is proper JSON with required fields."""
        try:
            cleaned = self.clean_ai_response(response)
            data = json.loads(cleaned)

            required = ['type', 'content', 'reason', 'continue']
            for field in required:
                if field not in data:
                    logger.error(f"Missing required field: {field}")
                    return False

            if data['type'] not in ['command', 'script']:
                logger.error(f"Invalid type: {data['type']}")
                return False

            if data['type'] == 'script':
                if data.get('script_type') not in ['bash', 'python']:
                    logger.error('Script type missing or invalid')
                    return False
                if 'script_name' not in data:
                    logger.error('Script name missing for script type')
                    return False

            if data.get('knowledge_ref'):
                knowledge = knowledge_base_handler.get_knowledge(data['knowledge_ref'])
                if knowledge == 'Reference not found':
                    logger.warning(f"Invalid knowledge reference: {data['knowledge_ref']}")

            return True
        except json.JSONDecodeError:
            logger.error('AI response is not valid JSON')
            return False
        except Exception as e:
            logger.error(f"Error validating AI response: {e}")
            return False

    @staticmethod
    def clean_ai_response(raw: str) -> str:
        """Clean AI response by removing code block markers."""
        if not raw:
            return ''
        return re.sub(r'^```(?:json)?|```$', '', raw.strip(), flags=re.MULTILINE).strip()


ai_assistant = AICyberSecurityAssistant()

if __name__ == '__main__':
    print('CyberSec AI Chat (type "exit" to quit)')
    while True:
        user_input = input('You: ')
        if user_input.lower() in ['exit', 'quit']:
            print('Exiting CyberSec AI Chat.')
            break

        response = ai_assistant.chat(user_input)
        if response:
            print('AI:', response)
            if ai_assistant.validate_response(response):
                print('✓ Response is valid')
                try:
                    cleaned = ai_assistant.clean_ai_response(response)
                    data = json.loads(cleaned)
                    if data.get('knowledge_ref'):
                        knowledge = knowledge_base_handler.get_knowledge(data['knowledge_ref'])
                        if knowledge:
                            print(f"Knowledge reference: {data['knowledge_ref']}")
                except Exception:
                    pass
            else:
                print('✗ Response validation failed')
        else:
            print('No response from AI.')