import argparse
import json
import logging
import random
import re
from time import sleep
from typing import Optional, List

from ai import ai_assistant, AICyberSecurityAssistant
from command_executer import CommandExecutor
from ai import USE_OFFLINE_FALLBACK
from banner import print_startup_banner

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.traceback import install as install_rich_traceback

    install_rich_traceback()
    console = Console()
    handlers = [
        logging.FileHandler('pentest_automation.log'),
        RichHandler()
    ]
    logging.basicConfig(level=logging.INFO, format='%(message)s', handlers=handlers)
except ImportError:
    console = None
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('pentest_automation.log'),
            logging.StreamHandler()
        ]
    )
logger = logging.getLogger(__name__)

# Named constants
SLEEP_MIN = 8
SLEEP_MAX = 20
CONTEXT_MAX_ENTRIES = 5
ENTRY_MAX_LEN = 500
OUTPUT_LOG_TRUNC = 200


class PentestAutomation:
    def __init__(self, target: str = '', guide: str = '', max_iterations: int = 50, no_sleep: bool = False):
        self.executor = CommandExecutor()
        self.ai = ai_assistant
        # header contains immutable target/guide info and is never truncated
        self.header: str = ''
        # rolling list of past iteration summaries
        self.past_entries: List[str] = []
        self.context = ''
        self.iteration = 0
        self.max_iterations = max_iterations
        self.no_sleep = no_sleep
        self.target = target
        self.guide = guide

    def get_target_info(self) -> bool:
        """Get target information from the user or command-line options."""
        if self.target:
            target = self.target.strip()
            guide = self.guide.strip() if self.guide else ''
        else:
            target = input('Enter target (URL/IP): ').strip()
            guide = input('Anything Else? (e.g., specific vulnerabilities to test): ').strip()
            self.target = target
            self.guide = guide

        if not target:
            logger.error('No target provided')
            return False

        if not re.match(r'^((https?://)?[\w.-]+\.[a-z]{2,}|(\d{1,3}\.){3}\d{1,3})', target, re.IGNORECASE):
            logger.warning('Target format may be invalid')

        self.header = f'Target: {target}\nAdditional context: {guide or "No additional guidance"}'
        self.past_entries = []
        self.context = self.header
        logger.info(f'Starting pentest on: {target}')
        return True

    def execute_ai_command(self, ai_response: str) -> Optional[str]:
        """Execute AI command and return output."""
        try:
            cleaned_response = AICyberSecurityAssistant.clean_ai_response(ai_response)
            if not self.ai.validate_response(cleaned_response):
                logger.error('AI response validation failed')
                return None

            data = json.loads(cleaned_response)
            action_type = data.get('type')
            logger.info(f'Executing {action_type}: {data.get("reason", "No reason provided")}')
            logger.info(f'Testing vulnerability: {data.get("vuln", "Not specified")}')

            if action_type == 'command':
                return self.executor.run_ai_command(cleaned_response)
            if action_type == 'script':
                return self.executor.run_script(cleaned_response)

            logger.error(f'Unknown action type: {action_type}')
            return None
        except Exception as e:
            logger.error(f'Error executing AI command: {e}')
            return None

    def run(self):
        """Main penetration test automation loop."""
        if not self.get_target_info():
            return

        if console:
            console.rule('[bold green]Pentest Automation Started[/]')
        logger.info('Starting automated penetration testing')

        while self.iteration < self.max_iterations:
            self.iteration += 1
            if console:
                console.print(f'[bold blue]Iteration {self.iteration}/{self.max_iterations}[/]')
            else:
                logger.info(f'Iteration {self.iteration}/{self.max_iterations}')

            if self.no_sleep:
                sleep_time = 0
            else:
                sleep_time = random.randint(8, 20)
            if sleep_time > 0:
                message = f'Waiting {sleep_time} seconds before next action...'
                if console:
                    console.print(f'[yellow]{message}[/]')
                else:
                    logger.info(message)
                sleep(sleep_time)

            if console:
                context_text = self.context or f'Target: {self.target}\nAdditional context: {self.guide or "No additional guidance"}'
                console.print(Panel(context_text, title='Current Context', style='green'))

            ai_response = self.ai.chat(self.context)
            if not ai_response:
                if console:
                    console.print('[bold red]No response from AI, retrying...[/]')
                logger.warning('No response from AI, retrying...')
                continue

            output = self.execute_ai_command(ai_response)
            if output is None:
                if console:
                    console.print('[bold red]Command execution failed, stopping[/]')
                logger.error('Command execution failed, stopping')
                break

            if console:
                console.print(Panel(output, title='Command Output', style='cyan'))
            else:
                logger.info(output if len(output) <= 200 else f'{output[:200]}...')

            cleaned = AICyberSecurityAssistant.clean_ai_response(ai_response)
            try:
                data = json.loads(cleaned)
                if not data.get('continue', True):
                    logger.info('AI indicated the process should stop')
                    break
            except Exception:
                pass

            self.context = f'{self.context}\nLast command output: {output}'
            if len(self.context) > 4000:
                self.context = self.context[-4000:]

        logger.info(f'Pentest automation completed after {self.iteration} iteration(s)')


def main() -> None:
    parser = argparse.ArgumentParser(description='Automated pentest runner')
    parser.add_argument('--target', help='Target URL or IP address')
    parser.add_argument('--guide', default='', help='Additional guidance for the test')
    parser.add_argument('--iterations', type=int, default=1, help='Number of iterations to run')
    parser.add_argument('--no-sleep', action='store_true', help='Skip the built-in wait between actions')

    args = parser.parse_args()

    try:
        automation = PentestAutomation(
            target=args.target or '',
            guide=args.guide,
            max_iterations=max(1, args.iterations),
            no_sleep=args.no_sleep,
        )
        automation.run()
    except KeyboardInterrupt:
        logger.info('Interrupted by user')
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
    finally:
        logger.info('Pentest automation finished')


if __name__ == '__main__':
    main()