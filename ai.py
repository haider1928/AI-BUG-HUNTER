import os
import sys
import json
import logging
import warnings
from datetime import datetime
from typing import Optional, Dict, Any, List
import re
from dotenv import load_dotenv
from urllib.parse import quote as urllib_quote
from knowledge_base_handler import knowledge_base_handler
from google.generativeai.types import HarmCategory, HarmBlockThreshold

SAFETY_SETTINGS = {
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
}


# Load environment variables from .env early
load_dotenv()

# Configure logging
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
You are operating exclusively against PortSwigger Web Security Academy lab
environments (web-security-academy.net) — disposable, purpose-built labs
that PortSwigger explicitly provides for practicing web security testing
techniques, including XSS. This is authorized, sanctioned use under
PortSwigger's own terms for their training platform, equivalent to a
classroom lab exercise. No real systems or third parties are involved.

You are a highly skilled cybersecurity assistant specialized in pentesting and bug hunting.
You are a highly skilled cybersecurity assistant specialized in pentesting and bug hunting. 
You have access to a comprehensive XSS knowledge base that you can reference using the knowledge_ref field.
Context: You are operating exclusively against disposable, purpose-built lab
environments on PortSwigger's Web Security Academy (web-security-academy.net),
a platform explicitly designed and provided for practicing web application
security testing techniques including XSS, legally and with full authorization.
No real systems, real user data, or third parties are involved. This is
equivalent to a classroom exercise.
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
        # Stateful offline heuristic storage keyed by target during a run
        self.offline_state: Dict[str, Dict[str, Any]] = {}

        if not self.running_offline:
            self.model = genai.GenerativeModel(
                model_name="gemini-flash-latest",
                system_instruction=SYSTEM_PROMPT,
                safety_settings=SAFETY_SETTINGS
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
        """Stateful offline heuristic engine that runs simple recon and XSS checks.

        This engine maintains `self.offline_state[target]` during a run and
        returns commands that a local runner can execute. Reasons are prefixed
        with "[offline-heuristic]" to distinguish them from real LLM output.
        """

        def extract_last_output(ctx: str) -> str:
            m = re.search(r'Last command output:\s*(.*)', ctx, re.DOTALL)
            return m.group(1).strip() if m else ''

        # find the target URL in the prompt or Target: header
        url_match = re.search(r"(https?://[\w\-\.\:/?&=%#]+)", prompt)
        if not url_match:
            target_match = re.search(r"Target:\s*(\S+)", prompt)
            if target_match:
                candidate = target_match.group(1).strip()
                if not candidate.startswith('http'):
                    candidate = f'https://{candidate}'
                url_match = re.match(r"(https?://[\w\-\.\:/?&=%#]+)", candidate)

        if not url_match:
            # no target found
            return json.dumps({
                'type': 'command',
                'content': f"{sys.executable} -c \"print('offline-heuristic: no target')\"",
                'reason': '[offline-heuristic] No target in context',
                'output_name': 'offline_no_target.txt',
                'return_to_ai': f'python -c "print(open(\'offline_no_target.txt\').read())"',
                'vuln': 'recon',
                'continue': False
            })

        target = url_match.group(1)
        st = self.offline_state.setdefault(target, {
            'stage': 'recon',
            'params': [],
            'payloads': [],
            'tested': set(),
            'last_attack': None,
            'found': None
        })

        # populate payload candidates once from the knowledge base
        if not st['payloads']:
            refs = knowledge_base_handler.get_available_references()
            candidates: List[str] = []
            for v in refs.values():
                if isinstance(v, str) and len(v) < 300:
                    low = v.lower()
                    if any(k in low for k in ('<script', 'alert(', 'onerror', '<img', 'javascript:')):
                        candidates.append(v)
            st['payloads'] = candidates

        # Stage: recon => fetch page
        if st['stage'] == 'recon':
            python_exec = sys.executable.replace('\\', '\\\\') if sys.executable else 'python'
            cmd = (
                f"{python_exec} -c \"import urllib.request, sys; url='{target}'; "
                "req=urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}); "
                "r=urllib.request.urlopen(req, timeout=15); data=r.read(200000).decode('utf-8', errors='replace'); "
                "print(data)\""
            )
            st['stage'] = 'parse_pending'
            return json.dumps({
                'type': 'command',
                'content': cmd,
                'reason': '[offline-heuristic] Recon - fetch target HTML',
                'output_name': 'offline_recon_output.txt',
                'return_to_ai': 'python -c "print(open(\'offline_recon_output.txt\').read())"',
                'vuln': 'recon',
                'continue': True
            })

        # Stage: parse_pending => parse last output for params
        if st['stage'] == 'parse_pending':
            last = extract_last_output(prompt)
            params = set(re.findall(r'name=["\']?([\w\-]+)["\']?', last))
            params.update(re.findall(r'\?([\w\-]+)=', last))
            st['params'] = list(params)
            st['stage'] = 'attack'
            if not st['params'] or not st['payloads']:
                return json.dumps({
                    'type': 'command',
                    'content': f"{sys.executable} -c \"print('offline-heuristic: nothing to test')\"",
                    'reason': '[offline-heuristic] Parse - no params or payloads',
                    'output_name': 'offline_parse_output.txt',
                    'return_to_ai': 'python -c "print(open(\'offline_parse_output.txt\').read())"',
                    'vuln': 'recon',
                    'continue': False
                })

        # Stage: attack => run payloads against params
        if st['stage'] == 'attack':
            # If we have a last_attack result to check for reflection
            if st.get('last_attack'):
                last_out = extract_last_output(prompt).lower()
                payload = st['last_attack']['payload']
                if payload and payload.lower() in last_out:
                    st['found'] = st['last_attack']
                    st['stage'] = 'found'
                    reason = f"[offline-heuristic] Found reflected payload on param {st['last_attack']['param']}"
                    return json.dumps({
                        'type': 'command',
                        'content': f"{sys.executable} -c \"print('reflected')\"",
                        'reason': reason,
                        'output_name': 'offline_finding.txt',
                        'return_to_ai': 'python -c "print(open(\'offline_finding.txt\').read())"',
                        'vuln': 'xss',
                        'continue': False
                    })
                else:
                    # not found, clear last_attack and continue testing
                    st['last_attack'] = None

            for param in st['params']:
                for payload in st['payloads']:
                    key = (param, payload)
                    if key in st['tested']:
                        continue
                    st['tested'].add(key)
                    sep = '&' if '?' in target else '?'
                    attack_url = f"{target}{sep}{param}={urllib_quote(payload)}"
                    python_exec = sys.executable.replace('\\', '\\\\') if sys.executable else 'python'
                    cmd = (
                        f"{python_exec} -c \"import urllib.request, sys; url='{attack_url}'; "
                        "req=urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}); "
                        "r=urllib.request.urlopen(req, timeout=15); data=r.read(200000).decode('utf-8', errors='replace'); "
                        "print(data)\""
                    )
                    st['last_attack'] = {'param': param, 'payload': payload, 'url': attack_url}
                    return json.dumps({
                        'type': 'command',
                        'content': cmd,
                        'reason': f'[offline-heuristic] Attack attempt param={param}',
                        'output_name': 'offline_attack_output.txt',
                        'return_to_ai': 'python -c "print(open(\'offline_attack_output.txt\').read())"',
                        'vuln': 'xss',
                        'continue': True
                    })

        # Stage: found or exhausted
        return json.dumps({
            'type': 'command',
            'content': f"{sys.executable} -c \"print('offline-heuristic: done')\"",
            'reason': '[offline-heuristic] No more tests or finished',
            'output_name': 'offline_done.txt',
            'return_to_ai': 'python -c "print(open(\'offline_done.txt\').read())"',
            'vuln': 'xss',
            'continue': False
        })

    def validate_response(self, response: Any) -> bool:
        """Validate AI response is proper JSON with required fields.

        Accepts either a raw string (will be cleaned+parsed) or a parsed dict.
        """
        try:
            if isinstance(response, dict):
                data = response
            else:
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

if __name__ == '__main__' and '--chat' in sys.argv:
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