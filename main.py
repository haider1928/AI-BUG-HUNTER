from brain.ai import ai_assistant  # Import the instance, not the class
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
        self.ai = ai_assistant  # Use the pre-configured instance
        self.context = ""  # Initialize as empty string
        self.iteration = 0
        self.max_iterations = 100  # Safety limit

    def get_target_info(self) -> bool:
        """Get target information from user."""
        target = input("Enter target (URL/IP): ").strip()
        if not target:
            logger.error("No target provided")
            return False
            
        guide = input("Anything Else? (e.g., specific vulnerabilities to test): ").strip()
        
        # Validate target format
        if not re.match(r'^((https?://)?[\w.-]+\.[a-z]{2,}|(\d{1,3}\.){3}\d{1,3})', target, re.IGNORECASE):
            logger.warning("Target format may be invalid")
            
        self.context = f"Target: {target}\nAdditional context: {guide or 'No additional guidance'}"
        logger.info(f"Starting pentest on: {target}")
        return True

    def execute_ai_command(self, ai_response: str) -> Optional[str]:
        """Execute AI command and return output."""
        try:
            cleaned_response = self.ai.clean_ai_response(ai_response)  # Use self.ai
            
            if not self.ai.validate_response(cleaned_response):
                logger.error("AI response validation failed")
                return None
                
            data = json.loads(cleaned_response)
            action_type = data.get("type")
            
            logger.info(f"Executing {action_type}: {data.get('reason', 'No reason provided')}")
            logger.info(f"Testing vulnerability: {data.get('vuln', 'Not specified')}")
            
            if action_type == "command":
                return self.executor.run_ai_command(cleaned_response)
            elif action_type in ["script", "bash", "python"]:
                return self.executor.run_script(cleaned_response)
            else:
                logger.error(f"Unknown action type: {action_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error executing AI command: {e}")
            return None

    def run(self):
        """Main pentest automation loop."""
        if not self.get_target_info():
            return
            
        logger.info("🚀 Starting automated penetration testing")
        
        # Initialize conversation with AI
        initial_prompt = f"Let's start pentesting. {self.context}"
        ai_response = self.ai.chat(initial_prompt)
        
        if not ai_response:
            logger.error("Failed to initialize AI conversation")
            return
            
        while self.iteration < self.max_iterations:
            self.iteration += 1
            logger.info(f"🔁 Iteration {self.iteration}/{self.max_iterations}")
            
            # Random delay to avoid detection
            sleep_time = random.randint(1, 5)
            logger.info(f"⏳ Waiting {sleep_time} seconds...")
            sleep(sleep_time)
            
            # Get AI response
            ai_response = self.ai.chat(self.context)
            if not ai_response:
                logger.warning("No response from AI, retrying...")
                continue
                
            # Execute command
            output = self.execute_ai_command(ai_response)
            if output is None:
                logger.error("Command execution failed, stopping")
                break
                
            logger.info(f"📤 Command output: {output[:200]}..." if len(output) > 200 else f"📤 Command output: {output}")
            
            # Check if we should continue
            try:
                cleaned = self.ai.clean_ai_response(ai_response)  # Use self.ai
                data = json.loads(cleaned)
                if not data.get("continue", True):
                    logger.info("🛑 AI indicated the process should stop")
                    break
            except:
                pass  # Continue anyway if we can't parse the response
                
            # Update context for next iteration
            self.context = f"{self.context}\nLast command output: {output}"
            
            # Safety check - don't let context grow too large
            if len(self.context) > 4000:
                self.context = self.context[-4000:]
                
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
