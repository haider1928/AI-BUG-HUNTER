import json
import requests
import os
from typing import List, Dict, Optional, Generator
from datetime import datetime

class OllamaMemory:
    def __init__(self, model_name: str = "llama2", base_url: str = "http://localhost:11434"):
        """
        Initialize Ollama memory manager
        
        Args:
            model_name (str): Name of the Ollama model to use
            base_url (str): Base URL for Ollama API
        """
        self.model_name = model_name
        self.base_url = base_url.rstrip('/')  # Remove trailing slash
        self.conversation_history: List[Dict[str, str]] = []
        self.memory_file = "ollama_memory.json"
        self.load_memory()
    
    def load_memory(self) -> None:
        """Load conversation history from file"""
        try:
            if os.path.exists(self.memory_file):
                with open(self.memory_file, 'r') as f:
                    data = json.load(f)
                    self.conversation_history = data.get('history', [])
                print(f"Loaded {len(self.conversation_history)} messages from memory")
        except Exception as e:
            print(f"Could not load memory: {e}")
    
    def save_memory(self) -> None:
        """Save conversation history to file"""
        try:
            data = {
                'history': self.conversation_history,
                'model': self.model_name,
                'timestamp': datetime.now().isoformat()
            }
            with open(self.memory_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Could not save memory: {e}")
    
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
        self.save_memory()
    
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
    
    def clear_memory(self) -> None:
        """Clear conversation history"""
        self.conversation_history = []
        self.save_memory()
        print("Memory cleared")
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None, 
                 context_limit: Optional[int] = 10, stream: bool = False) -> Optional[str]:
        """
        Generate response using Ollama model (corrected API usage)
        
        Args:
            prompt (str): User's message
            system_prompt (str, optional): System instruction
            context_limit (int, optional): Number of recent messages to include
            stream (bool): Whether to stream response
            
        Returns:
            Model's response or None if error
        """
        # Add user message to history
        self.add_to_history('user', prompt)
        
        # Prepare the full prompt with context
        context_messages = self.get_context(context_limit)
        
        # Build context string
        context_text = ""
        for msg in context_messages:
            if msg['role'] == 'user':
                context_text += f"User: {msg['content']}\n"
            elif msg['role'] == 'assistant':
                context_text += f"Assistant: {msg['content']}\n"
        
        # Add current prompt
        full_prompt = f"{context_text}User: {prompt}\nAssistant:"
        
        # Add system prompt if provided
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{full_prompt}"
        
        # Prepare API request
        url = f"{self.base_url}/api/generate"
        payload = {
            'model': self.model_name,
            'prompt': full_prompt,
            'stream': stream
        }
        
        try:
            # Make API call
            response = requests.post(url, json=payload)
            response.raise_for_status()
            
            if stream:
                # Handle streaming response
                full_response = ""
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line.decode('utf-8'))
                        if 'response' in data:
                            full_response += data['response']
                        if data.get('done', False):
                            break
                assistant_response = full_response
            else:
                # Handle non-streaming response
                result = response.json()
                assistant_response = result.get('response', '')
            
            # Add assistant response to history
            if assistant_response:
                self.add_to_history('assistant', assistant_response)
            
            return assistant_response
            
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response content: {e.response.text}")
            return None
        except KeyError as e:
            print(f"Unexpected response format: {e}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
    
    def chat(self, prompt: str, system_prompt: Optional[str] = None, 
             context_limit: Optional[int] = 10) -> Optional[str]:
        """
        Chat with Ollama model using conversation history
        (Wrapper for generate method)
        """
        return self.generate(prompt, system_prompt, context_limit, stream=False)
    
    def stream_chat(self, prompt: str, system_prompt: Optional[str] = None, 
                    context_limit: Optional[int] = 10) -> Generator[str, None, None]:
        """
        Stream chat with Ollama model using conversation history
        
        Args:
            prompt (str): User's message
            system_prompt (str, optional): System instruction
            context_limit (int, optional): Number of recent messages to include
            
        Yields:
            Chunks of the response
        """
        # Add user message to history
        self.add_to_history('user', prompt)
        
        # Prepare the full prompt with context
        context_messages = self.get_context(context_limit)
        
        # Build context string
        context_text = ""
        for msg in context_messages:
            if msg['role'] == 'user':
                context_text += f"User: {msg['content']}\n"
            elif msg['role'] == 'assistant':
                context_text += f"Assistant: {msg['content']}\n"
        
        # Add current prompt
        full_prompt = f"{context_text}User: {prompt}\nAssistant:"
        
        # Add system prompt if provided
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{full_prompt}"
        
        # Prepare API request
        url = f"{self.base_url}/api/generate"
        payload = {
            'model': self.model_name,
            'prompt': full_prompt,
            'stream': True
        }
        
        try:
            # Make API call
            response = requests.post(url, json=payload, stream=True)
            response.raise_for_status()
            
            full_response = ""
            for line in response.iter_lines():
                if line:
                    data = json.loads(line.decode('utf-8'))
                    if 'response' in data:
                        chunk = data['response']
                        full_response += chunk
                        yield chunk
                    if data.get('done', False):
                        break
            
            # Add complete response to history
            if full_response:
                self.add_to_history('assistant', full_response)
                
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response content: {e.response.text}")
            yield f"Error: {e}"
        except Exception as e:
            print(f"An error occurred: {e}")
            yield f"Error: {e}"
    
    def get_memory_info(self) -> Dict[str, any]:
        """Get information about current memory state"""
        return {
            'total_messages': len(self.conversation_history),
            'user_messages': len([m for m in self.conversation_history if m['role'] == 'user']),
            'assistant_messages': len([m for m in self.conversation_history if m['role'] == 'assistant']),
            'model': self.model_name,
            'memory_file': self.memory_file
        }

# Example usage
if __name__ == "__main__":
    # Initialize Ollama memory manager
    ollama = OllamaMemory(model_name="gpt-oss:120b-cloud")
    
    # Print memory info
    print("Memory Info:", ollama.get_memory_info())
    
    # Example conversation
    print("\n=== Ollama Chat with Memory ===")
    print("Type 'exit' to quit, 'clear' to clear memory, 'info' for memory info, 'stream' to toggle streaming")
    
    streaming = False
    
    while True:
        try:
            user_input = input("\nYou: ").strip()
            
            if user_input.lower() == 'exit':
                break
            elif user_input.lower() == 'clear':
                ollama.clear_memory()
                continue
            elif user_input.lower() == 'info':
                info = ollama.get_memory_info()
                print(f"Memory Info: {json.dumps(info, indent=2)}")
                continue
            elif user_input.lower() == 'stream':
                streaming = not streaming
                print(f"Streaming {'enabled' if streaming else 'disabled'}")
                continue
            elif not user_input:
                continue
            
            # Get response from Ollama
            if streaming:
                print("Assistant: ", end="", flush=True)
                full_response = ""
                for chunk in ollama.stream_chat(user_input):
                    print(chunk, end="", flush=True)
                    full_response += chunk
                print()  # New line after streaming
            else:
                response = ollama.chat(user_input)
                if response:
                    print(f"Assistant: {response}")
                else:
                    print("Sorry, I couldn't get a response.")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
