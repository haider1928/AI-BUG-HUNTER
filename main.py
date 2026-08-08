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

    def execute_ai_command(self, data: dict, raw_json: str) -> Optional[str]:
        """Execute AI command described by parsed `data` and return filtered output.

        `raw_json` should be the cleaned JSON string used by the executor.
        """
        try:
            action_type = data.get('type')
            logger.info(f'Executing {action_type}: {data.get("reason", "No reason provided")}')
            logger.info(f'Testing vulnerability: {data.get("vuln", "Not specified")}')

            if action_type == 'command':
                return self.executor.run_ai_command(raw_json)
            if action_type == 'script':
                return self.executor.run_script(raw_json)

            logger.error(f'Unknown action type: {action_type}')
            return None
        except Exception as e:
            logger.error(f'Error executing AI command: {e}')
            return None

    def run(self):
        """Main penetration test automation loop."""
        if not self.get_target_info():
            return

        # Startup banner
        print_startup_banner(live=not USE_OFFLINE_FALLBACK, target=self.target, guide=self.guide, iterations=self.max_iterations)
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
                sleep_time = random.randint(SLEEP_MIN, SLEEP_MAX)
            if sleep_time > 0:
                message = f'Waiting {sleep_time} seconds before next action...'
                if console:
                    console.print(f'[yellow]{message}[/]')
                else:
                    logger.info(message)
                sleep(sleep_time)

            if console:
                context_text = self.header + "\n\n" + "\n\n".join(self.past_entries[-CONTEXT_MAX_ENTRIES:])
                console.print(Panel(context_text, title='Current Context', style='green'))

            # Build the prompt from header + recent summaries
            prompt = self.header + "\n\n" + "\n\n".join(self.past_entries[-CONTEXT_MAX_ENTRIES:])
            ai_response = self.ai.chat(prompt)
            if not ai_response:
                if console:
                    console.print('[bold red]No response from AI, retrying...[/]')
                logger.warning('No response from AI, retrying...')
                continue

            cleaned = AICyberSecurityAssistant.clean_ai_response(ai_response)
            try:
                data = json.loads(cleaned)
            except Exception:
                logger.error('AI response JSON parse failed')
                break

            if not self.ai.validate_response(data):
                logger.error('AI response validation failed')
                break

            output = self.execute_ai_command(data, cleaned)
            if output is None:
                if console:
                    console.print('[bold red]Command execution failed, stopping[/]')
                logger.error('Command execution failed, stopping')
                break

            # append a trimmed summary to history
            summary = output if isinstance(output, str) else str(output)
            if len(summary) > ENTRY_MAX_LEN:
                summary = summary[:ENTRY_MAX_LEN] + '...'
            self.past_entries.append(f'Iteration {self.iteration}: {summary}')

            if console:
                console.print(Panel(output, title='Command Output', style='cyan'))
            else:
                logger.info(output if len(output) <= OUTPUT_LOG_TRUNC else f'{output[:OUTPUT_LOG_TRUNC]}...')

            if not data.get('continue', True):
                logger.info('AI indicated the process should stop')
                break

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