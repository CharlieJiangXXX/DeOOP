# DeObfuscator + Optimized Perfecter
PRETTY_NAME = "DeOOP"
PLUGIN_NAME = "de-oop"

# support a few models for ablation studies (raw codellama, fine-tuned codellama, chatgpt, gpt4, dirty, etc.)

# verify when setting!
# also, simply set openai.api_key

# Set your API key here, or put it in the OPENAI_API_KEY environment variable.
OPENAI_API_KEY = ""

# Set your OpenAI Proxy here, or put it in the HTTPS_PROXY environment variable.
# Such as: OPENAI_PROXY = http://127.0.0.1:7890
OPENAI_PROXY = ""

llm = None
