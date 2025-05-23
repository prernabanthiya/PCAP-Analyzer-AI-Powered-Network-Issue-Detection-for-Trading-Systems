import os
import requests
from dotenv import load_dotenv

# Load the API key from .env
load_dotenv()
API_KEY = os.getenv("OPENROUTER_API_KEY")

def ask_llm(prompt):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer": "http://localhost",  # required by OpenRouter
        "Content-Type": "application/json"
    }

    payload = {
        "model": "mistralai/mistral-7b-instruct",
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    response = requests.post("https://openrouter.ai/api/v1/chat/completions", json=payload, headers=headers)

    if response.status_code == 200:
        return response.json()['choices'][0]['message']['content']
    else:
        return f"Error: {response.status_code}, {response.text}"

# Example usage
if __name__ == "__main__":
    prompt = "Explain what TCP retransmissions are in simple terms."
    answer = ask_llm(prompt)
    print("Answer:", answer)


