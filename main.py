from ai import ai_assistant, AICyberSecurityAssistant
from command_executer import CommandExecutor
from time import sleep
import random
import json
import logging
import re
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pentest_automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PentestAutomation:
    def __init__(self):
        self.executor = CommandExecutor()
        self.ai = ai_assistant
        self.context = ""
        self.iteration = 0
        self.max_iterations = 50  # Safety limit

    def get_target_info(self) -> bool:
        """Get target information from user."""
        target = input("Enter target (URL/IP): ").strip()
        if not target:
            logger.error("No target provided")
            return False
            
        guide = input("Anything Else? (e.g., specific vulnerabilities to test): ").strip()
        
        # Validate target format
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
        if not re.match(r'^([\w.-]+\.[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}|localhost|[\w.-]+)$', clean_target):
            logger.warning(f"Target format '{target}' may be invalid. Proceeding anyway.")
            
        self.context = f"Target: {target}\nAdditional context: {guide or 'No additional guidance'}"
        logger.info(f"Starting pentest on: {target}")
        return True

    def execute_ai_command(self, ai_response: str) -> str:
        """Execute AI command and return output."""
        try:
            cleaned_response = AICyberSecurityAssistant.clean_ai_response(ai_response)
            
            if not self.ai.validate_response(cleaned_response):
                logger.error("AI response validation failed")
                return "Error: AI response validation failed. Ensure your output is a valid JSON action block."
                
            data = json.loads(cleaned_response)
            action_type = data.get("type", "unknown")
            
            logger.info(f"Executing {action_type}: {data.get('reason', 'No reason provided')}")
            vuln = data.get("vuln")
            if vuln:
                logger.info(f"Testing vulnerability: {vuln}")
            
            output = None
            if action_type == "command":
                output = self.executor.run_ai_command(cleaned_response)
            elif action_type in ["script", "bash", "python"]:
                output = self.executor.run_script(cleaned_response)
            else:
                logger.error(f"Unknown action type: {action_type}")
                return f"Error: Unknown action type '{action_type}'. Valid types are 'command', 'script', 'bash', 'python'."
                
            return str(output) if output else "Command executed successfully but produced no output."
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            return f"Error: Invalid JSON format provided. {e}"
        except Exception as e:
            logger.error(f"Error executing AI command: {e}")
            return f"Error executing command: {e}"

    def run(self):
        """Main pentest automation loop."""
        if not self.get_target_info():
            return
            
        logger.info("🚀 Starting automated penetration testing")
        
        # Initialize conversation with AI
        prompt = f"Let's start pentesting. {self.context}"
        
        while self.iteration < self.max_iterations:
            self.iteration += 1
            logger.info(f"🔁 Iteration {self.iteration}/{self.max_iterations}")
            
            # Get AI response
            logger.info("🤖 Analyzing context and waiting for AI response...")
            ai_response = self.ai.chat(prompt)
            if not ai_response:
                logger.warning("No response from AI, retrying...")
                sleep(random.randint(1, 5))
                continue
                
            # Execute command
            output = self.execute_ai_command(ai_response)
            
            out_str = str(output).strip()
            logger.info(f"📤 Command output: {out_str[:200]}..." if len(out_str) > 200 else f"📤 Command output: {out_str}")
            
            # Check if we should continue by passively checking the response
            try:
                cleaned = AICyberSecurityAssistant.clean_ai_response(ai_response)
                data = json.loads(cleaned)
                if not data.get("continue", True):
                    logger.info("🛑 AI indicated the process should stop.")
                    break
            except Exception:
                pass  # Ignore invalid json for continue check, we already fed back the error to AI
                
            # Update context for next iteration
            self.context = f"{self.context}\nLast operation result: {out_str}"
            
            # Safety check - don't let context grow too large, truncate early history if needed
            if len(self.context) > 4000:
                self.context = "..." + self.context[-3997:]
                
            prompt = self.context
            
            # Random delay to avoid detection
            sleep_time = random.randint(1, 5)
            logger.info(f"⏳ Waiting {sleep_time} seconds before next operation...")
            sleep(sleep_time)
                
        logger.info(f"🏁 Pentest automation completed after {self.iteration} iterations")


def main():
    """Main entry point."""
    try:
        automation = PentestAutomation()
        automation.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        logger.info("Pentest automation finished")


if __name__ == "__main__":
    main()