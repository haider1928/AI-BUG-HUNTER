import json
import subprocess
import shlex
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import re
import platform

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Check if running on Windows
IS_WINDOWS = platform.system().lower() == 'windows'

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
        
        # Windows specific dangerous commands
        if IS_WINDOWS:
            dangerous_patterns.extend([
                r'del\s+/s\s+/q', r'rmdir\s+/s\s+/q', r'format\s+', 
                r'diskpart', r'reg\s+delete', r'taskkill\s+/f'
            ])
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        return True

    @staticmethod
    def execute_command_with_filter_in_wsl(command: str, filter_command: str = None) -> str:
        """Execute command with optional filter in WSL and return filtered output directly."""
        try:
            if not CommandExecutor.validate_command(command):
                return f"Error: Potentially dangerous command blocked: {command}"
            
            # Combine command with filter using pipe if filter provided
            if filter_command:
                if not CommandExecutor.validate_command(filter_command):
                    return f"Error: Potentially dangerous filter command blocked: {filter_command}"
                full_command = f"{command} | {filter_command}"
            else:
                full_command = command
            
            # Prepare WSL command
            wsl_command = f"wsl -u root --cd /tmp -- bash -c \"{full_command}\""
            
            # Execute and capture output directly
            result = subprocess.run(
                wsl_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5-minute timeout
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Command error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error executing command in WSL: {e}"

    @staticmethod
    def execute_command_with_filter(command: str, filter_command: str = None, cwd: str = None) -> str:
        """Execute command with optional filter and return filtered output directly."""
        try:
            # Always use WSL for Linux commands when on Windows
            if IS_WINDOWS:
                return CommandExecutor.execute_command_with_filter_in_wsl(command, filter_command)
            
            # Native Linux execution
            if not CommandExecutor.validate_command(command):
                return f"Error: Potentially dangerous command blocked: {command}"
            
            # Combine command with filter using pipe if filter provided
            if filter_command:
                if not CommandExecutor.validate_command(filter_command):
                    return f"Error: Potentially dangerous filter command blocked: {filter_command}"
                full_command = f"{command} | {filter_command}"
            else:
                full_command = command
            
            # Execute and capture output directly
            result = subprocess.run(
                full_command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=300  # 5-minute timeout
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Command error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error executing command: {e}"

    @staticmethod
    def run_ai_command(ai_response_json: str) -> str:
        """Execute a single command from AI JSON response with integrated filtering."""
        try:
            data = json.loads(ai_response_json)
        except json.JSONDecodeError as e:
            return f"Error: Invalid JSON from AI - {e}"

        # Extract and validate parameters
        reason = data.get("reason", "No reason provided")
        command = data.get("content", "").strip("`")
        return_to_ai = data.get("return_to_ai", "")
        should_continue = data.get("continue", True)

        logger.info(f"Reason: {reason}")
        if not command:
            return "No command to execute."

        # Execute command with filter in one step
        logger.info(f"Executing: {command}" + (f" | {return_to_ai}" if return_to_ai else ""))
        
        output = CommandExecutor.execute_command_with_filter(command, return_to_ai)
        
        if "Error:" in output:
            return f"Error executing command: {output}"

        if not should_continue:
            logger.info("AI indicated the process should stop.")
            return f"{output}\nStopping as requested."

        return output or "Command executed successfully (no output)"

    @staticmethod
    def execute_script_in_wsl(script_path: str, script_type: str, filter_command: str = None) -> str:
        """Execute script in WSL/Kali Linux environment with optional filtering."""
        try:
            # Convert Windows path to WSL path
            wsl_script_path = f"/mnt/{script_path[0].lower()}{script_path[2:].replace(chr(92), '/')}"
            
            # Prepare execution command based on script type
            if script_type == "bash":
                exec_command = f"bash {wsl_script_path}"
            elif script_type == "python":
                exec_command = f"python3 {wsl_script_path}"
            else:
                return f"Error: Unsupported script type for WSL: {script_type}"
            
            # Combine with filter if provided
            if filter_command:
                if not CommandExecutor.validate_command(filter_command):
                    return f"Error: Potentially dangerous filter command blocked: {filter_command}"
                full_command = f"{exec_command} | {filter_command}"
            else:
                full_command = exec_command
            
            # Execute in WSL
            wsl_command = f"wsl -u root --cd /tmp -- bash -c \"{full_command}\""
            
            # Execute and capture output directly
            result = subprocess.run(
                wsl_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5-minute timeout
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Script error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Error: Script execution timed out"
        except Exception as e:
            return f"Error executing script in WSL: {e}"

    @staticmethod
    def execute_script(script_path: str, script_type: str, filter_command: str = None, cwd: str = None) -> str:
        """Execute script with optional filtering and return filtered output directly."""
        try:
            # Use WSL for script execution on Windows
            if IS_WINDOWS:
                return CommandExecutor.execute_script_in_wsl(script_path, script_type, filter_command)
            
            # Native Linux execution
            if script_type == "python":
                exec_command = f"python3 {script_path}"
            elif script_type == "bash":
                exec_command = f"bash {script_path}"
            else:
                return f"Error: Unsupported script type {script_type}"
            
            # Combine with filter if provided
            if filter_command:
                if not CommandExecutor.validate_command(filter_command):
                    return f"Error: Potentially dangerous filter command blocked: {filter_command}"
                full_command = f"{exec_command} | {filter_command}"
            else:
                full_command = exec_command
            
            # Execute and capture output directly
            result = subprocess.run(
                full_command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=300  # 5-minute timeout
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Script error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Error: Script execution timed out"
        except Exception as e:
            return f"Error executing script: {e}"

    @staticmethod
    def run_script(ai_response_json: str) -> str:
        """Execute a script from AI JSON response with integrated filtering."""
        try:
            data = json.loads(ai_response_json)
        except json.JSONDecodeError as e:
            return f"Error: Invalid JSON from AI - {e}"

        # Extract and validate parameters
        reason = data.get("reason", "No reason provided")
        script_content = data.get("content", "").strip("`")
        return_to_ai = data.get("return_to_ai", "")
        should_continue = data.get("continue", True)
        script_name = CommandExecutor.sanitize_filename(data.get("script_name", "ai_script"))
        script_type = data.get("script_type", "").strip().lower()

        # Handle case where type is "bash" directly
        if data.get("type") == "bash" and not script_type:
            script_type = "bash"

        logger.info(f"Running {script_type} script: {reason}")

        # Save script to file
        script_path = f"scripts/{script_name}"
        with open(script_path, "w") as script_file:
            script_file.write(script_content)

        # Make executable if bash script (Unix only)
        if not IS_WINDOWS and script_type == "bash":
            os.chmod(script_path, 0o755)

        # Execute script with filter in one step
        logger.info(f"Executing script: {script_name}" + (f" | {return_to_ai}" if return_to_ai else ""))
        
        output = CommandExecutor.execute_script(script_path, script_type, return_to_ai)
        
        if "Error:" in output:
            return f"Error executing script: {output}"

        if not should_continue:
            logger.info("AI indicated the process should stop.")
            return f"{output}\nStopping as requested."

        return output or "Script executed successfully (no output)"
