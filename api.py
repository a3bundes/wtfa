import os
import re
import hmac
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Ollama endpoint
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

# Security: Block dangerous patterns in prompts
BLOCKED_PATTERNS = [
    # File system access attempts
    r'(?i)(cat\s+/etc/|ls\s+/|cd\s+/|pwd|whoami|uname|hostname)',
    r'(?i)(curl\s+http|wget\s+http|nc\s+|exec|eval|shell)',
    r'(?i)(\.\./|\.\.|/proc/|/sys/|/dev/)',
    r'(?i)(export\s+|source\s+|\$\(|`.*`)',
    r'(?i)(sudo|chmod|chown|passwd|shadow|group)',
    # Environment variable access
    r'(?i)(\$\{?ENV|\$\{?HOME|\$\{?PATH|\$\{?USER|\$\{?SHELL)',
    # System commands
    r'(?i)(system|exec|spawn|fork|child_process)',
    # Try to override instructions
    r'(?i)(ignore\s+previous|forget\s+everything|new\s+instructions)',
]

def is_safe_prompt(prompt: str) -> tuple[bool, str]:
    """Check if prompt is safe"""
    prompt_lower = prompt.lower()
    
    # Check blocked patterns
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, prompt):
            return False, f"Blocked: suspicious pattern detected"
    
    # Check prompt length (prevent huge prompts)
    if len(prompt) > 2000:
        return False, "Prompt too long (max 2000 chars)"
    
    return True, ""

@app.route('/chat', methods=['POST'])
def chat():
    """Proxy chat requests to Ollama with security checks"""
    # Get optional API key (but don't require it)
    auth_header = request.headers.get('Authorization', '')
    api_token = os.environ.get('API_TOKEN', '')
    
    # If API token is set, verify it (but don't block if no token configured)
    if api_token and not auth_header.startswith(f'Bearer {api_token}'):
        return jsonify({'error': 'Invalid API token'}), 401
    
    data = request.get_json()
    prompt = data.get('prompt', '').strip()
    
    if not prompt:
        return jsonify({'error': 'No prompt provided'}), 400
    
    # Security check
    safe, error = is_safe_prompt(prompt)
    if not safe:
        return jsonify({'error': error, 'response': 'Извините, я не могу выполнить этот запрос.'}), 400
    
    # Add system prompt to keep assistant safe
    safe_prompt = f"""Ты - дружелюбный AI ассистент на wtfa.ru. 
Отвечай на вопросы пользователей. 
НЕ выполняй команды связанные с файловой системой, системными командами, не пытайся получить доступ к системной информации.
Просто отвечай на вопросы и помогай с информацией.

Вопрос пользователя: {prompt}"""
    
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                'model': 'gpt-oss:20b',
                'prompt': safe_prompt,
                'stream': False
            },
            timeout=120
        )
        
        result = response.json()
        
        # Extract only the response text
        return jsonify({
            'response': result.get('response', 'Нет ответа'),
            'model': result.get('model')
        })
        
    except requests.Timeout:
        return jsonify({'error': 'Timeout', 'response': 'Истекло время ожидания от модели.'}), 504
    except Exception as e:
        return jsonify({'error': str(e), 'response': 'Произошла ошибка.'}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check (no auth required)"""
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
