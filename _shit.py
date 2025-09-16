import requests

# System prompt for the AI assistant
SYSTEM_PROMPT = (
    "You are a highly skilled cybersecurity assistant specialized in pentesting and bug hunting. "
    "You can ONLY respond with one command per step. "
    "After executing the command, you will be provided the output. Based on the output, generate the next single command. "
    "For each command, also provide a short explanation of why you chose it in a JSON-like field named 'reason'. "
    "Also include a 'continue' field with a value of true if you want the process to continue, or false if you believe the task is complete. "
    "Your response format must be strictly:\n"
    "{\n"
    "  \"command\": \"<command>\",\n"
    "  \"reason\": \"<short explanation>\",\n"
    "  \"continue\": \"<true or false>\"\n"
    "}\n"
    "Never give multiple commands or any extra text outside this format. "
    "Treat the environment as a live pentesting lab. You are given a target and context; respond only with the next actionable command, its reason, and whether to continue."
)

# Global conversation history and summary text
conversation = [
    {
        "role": "system",
        "content": SYSTEM_PROMPT
    }
]
summary_text = ""


def summarize_conversation(conv, max_messages=6):
    """
    Summarize older messages in the conversation to keep context concise.
    Only the latest max_messages are kept, others are summarized.
    """
    global summary_text
    if len(conv) <= max_messages + 1:
        return conv

    # Messages to summarize (excluding system prompt and latest messages)
    to_summarize = conv[1:-max_messages]
    text = "\n".join([f"{m['role']}: {m['content']}" for m in to_summarize])

    if text.strip():
        # Just append text as raw summary (no AI summarization here since ApiFreeLLM has no memory)
        summary_text += "\n(Summary) " + text[:300] + "..."

    summary_message = {"role": "system", "content": "Summary of previous conversation: " + summary_text}
    return [conv[0], summary_message] + conv[-max_messages:]


def chat(prompt: str, max_tokens: int = 500) -> str:
    """
    Send a prompt to ApiFreeLLM, manage conversation history and memory, and return the AI's response.
    """
    global conversation
    conversation.append({"role": "user", "content": prompt})

    # Summarize older messages
    conversation = summarize_conversation(conversation, max_messages=6)

    # Build plain-text prompt (ApiFreeLLM doesn’t support role structure)
    context_prompt = "\n".join([f"{m['role'].capitalize()}: {m['content']}" for m in conversation])

    try:
        response = requests.post(
            "https://apifreellm.com/api/chat",
            json={"prompt": context_prompt, "max_tokens": max_tokens},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        ai_reply = data.get("response", "").strip()
    except Exception as e:
        ai_reply = f"⚠️ Error: {e}"

    conversation.append({"role": "assistant", "content": ai_reply})
    return ai_reply


def interactive_chat():
    """
    Interactive command-line chat loop for the CyberSec AI assistant.
    """
    print("CyberSec AI Chat (type 'exit' to quit)")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            print("Exiting CyberSec AI Chat.")
            break
        response = chat(user_input)
        print("AI:", response)


if __name__ == "__main__":
    interactive_chat()
