import json
import subprocess
import shlex
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create necessary directories
Path("command_outputs").mkdir(exist_ok=True)
Path("scripts").mkdir(exist_ok=True)


class CommandExecutor:
    """Safe command and script execution with proper sanitization and error handling."""
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal and other attacks."""
        # Remove any path components and keep only the base name
        base_name = os.path.basename(filename)
        # Replace any non-alphanumeric characters (except ._-) with underscore
        safe_name = re.sub(r'[^\w\.\-_]', '_', base_name)
        return safe_name[:100]  # Limit filename length

    @staticmethod
    def validate_command(command: str) -> bool:
        """Validate command for potentially dangerous operations."""
        dangerous_patterns = [
            r'rm\s+-rf', r':\(\)\{', r'chmod\s+[0-7]{3,4}\s+', 
            r'wget\s+.*\|', r'curl\s+.*\|', r'mkfs', r'dd\s+.*=',
            r'>/dev/sd', r'mount\s+', r'umount\s+'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        return True

    @staticmethod
    def run_command(command: str, output_path: str, cwd: str = None) -> bool:
        """Safely execute a command and capture output."""
        try:
            if not CommandExecutor.validate_command(command):
                logger.error(f"Potentially dangerous command blocked: {command}")
                return False
                
            with open(output_path, 'w') as outfile:
                process = subprocess.Popen(
                    shlex.split(command),
                    stdout=outfile,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=cwd
                )
                process.wait(timeout=300)  # 5-minute timeout
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return False
        except Exception as e:
            logger.error(f"Error executing command {command}: {e}")
            return False

    @staticmethod
    def filter_output(filter_command: str, working_dir: str = None) -> str:
        """Apply filtering command to output."""
        try:
            result = subprocess.run(
                filter_command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=working_dir,
                timeout=60
            )
            return result.stdout if result.returncode == 0 else f"Filter error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Filter command timed out"
        except Exception as e:
            return f"Filter error: {e}"

    @staticmethod
    def run_ai_command(ai_response_json: str) -> str:
        """Execute a single command from AI JSON response."""
        try:
            data = json.loads(ai_response_json)
        except json.JSONDecodeError as e:
            return f"Error: Invalid JSON from AI - {e}"

        # Extract and validate parameters
        reason = data.get("reason", "No reason provided")
        command = data.get("content", "").strip("`")
        output_name = CommandExecutor.sanitize_filename(data.get("output_name", "output.txt"))
        return_to_ai = data.get("return_to_ai", "")
        should_continue = data.get("continue", True)

        logger.info(f"Reason: {reason}")
        if not command:
            return "No command to execute."

        # Execute command
        output_path = f"command_outputs/{output_name}"
        logger.info(f"Executing: {command} -> {output_path}")
        
        success = CommandExecutor.run_command(command, output_path)
        if not success:
            return f"Error executing command: {command}"

        # Apply filtering if requested
        filtered_output = ""
        if return_to_ai:
            logger.info(f"Filtering output with: {return_to_ai}")
            filtered_output = CommandExecutor.filter_output(return_to_ai, 'command_outputs')

        if not should_continue:
            logger.info("AI indicated the process should stop.")
            return "Stopping as requested."

        return filtered_output or f"(Raw output saved to {output_name})"

    @staticmethod
    def run_script(ai_response_json: str) -> str:
        """Execute a script from AI JSON response."""
        try:
            data = json.loads(ai_response_json)
        except json.JSONDecodeError as e:
            return f"Error: Invalid JSON from AI - {e}"

        # Extract and validate parameters
        reason = data.get("reason", "No reason provided")
        script_content = data.get("content", "").strip("`")
        output_name = CommandExecutor.sanitize_filename(data.get("output_name", "output.txt"))
        return_to_ai = data.get("return_to_ai", "")
        should_continue = data.get("continue", True)
        script_name = CommandExecutor.sanitize_filename(data.get("script_name", "ai_script"))
        script_type = data.get("script_type", "").strip().lower()

        logger.info(f"Running {script_type} script: {reason}")

        # Save script to file
        script_path = f"scripts/{script_name}"
        with open(script_path, "w") as script_file:
            script_file.write(script_content)

        # Make executable if bash script
        if script_type == "bash":
            os.chmod(script_path, 0o755)

        # Execute script
        output_path = f"command_outputs/{output_name}"
        logger.info(f"Executing script: {script_name} -> {output_path}")
        
        if script_type == "python":
            cmd = f"python3 {script_path}"
        elif script_type == "bash":
            cmd = f"bash {script_path}"
        else:
            return f"Error: Unsupported script type {script_type}"

        success = CommandExecutor.run_command(cmd, output_path, 'scripts')
        if not success:
            return f"Error executing script: {script_name}"

        # Apply filtering
        filtered_output = ""
        if return_to_ai:
            logger.info(f"Filtering output with: {return_to_ai}")
            filtered_output = CommandExecutor.filter_output(return_to_ai, 'command_outputs')

        if not should_continue:
            logger.info("AI indicated the process should stop.")
            return "Stopping as requested."

        return filtered_output or f"(Raw output saved to {output_name})"


# Example usage
if __name__ == "__main__":
    ai_response = '''
    {
        "type": "command",
        "content": "ping -c 2 google.com",
        "reason": "Check connectivity.",
        "output_name": "ping_google.txt",
        "return_to_ai": "grep 'time=' ping_google.txt",
        "continue": true
    }
    '''
    result = CommandExecutor.run_ai_command(ai_response)
    print("\nFiltered Output for AI:\n", result)