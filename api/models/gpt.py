import re

from openai import OpenAI, BadRequestError, RateLimitError
import tiktoken
from .base_model import *


class OpenAIGPT(LLM):
    gpt_models = {
        "gpt-4-1106-preview": 32768,
        "gpt-4-vision-preview": 32768,
        "gpt-4": 32768,
        "gpt-4-0314": 32768,
        "gpt-4-0613": 32768,
        "gpt-4-32k": 32768,
        "gpt-4-32k-0314": 32768,
        "gpt-4-32k-0613": 32768,
        "gpt-3.5-turbo-1106": 4096,
        "gpt-3.5-turbo": 4096,
        "gpt-3.5-turbo-16k": 32768,
        "gpt-3.5-turbo-0301": 32768,
        "gpt-3.5-turbo-0613": 32768,
        "gpt-3.5-turbo-16k-0613": 32768
    }

    def __init__(self, model: str, api_key: str):
        super().__init__()
        self._modelName = ""
        self.name = model
        self._client = OpenAI(api_key=api_key)
        self._encoding = tiktoken.get_encoding("cl100k_base")

    @property
    def name(self) -> str:
        return self._modelName

    @name.setter
    def name(self, name: str) -> None:
        if name not in self.gpt_models:
            raise Exception(f"{name} is not a supported OpenAI model!")
        self._modelName = name

    @property
    def max_tokens_supported(self) -> int:
        return self.gpt_models[self.name]

    @property
    def max_concurrent_queries(self) -> int:
        # This must be limited lest we be banned
        return 3

    def num_tokens(self, query: str) -> int:
        return len(self._encoding.encode(query))

    def _query(self, system: List[str], prompt: str, data: str, top_p: float, temperature: float) -> str:
        max_new = int(len(data) * self.DATA_SCALE_FACTOR)

        message = [{"role": "system", "content": prompt} for prompt in system]
        message.append({"role": "user", "content": f"{prompt}{data}"})

        try:
            response = self._client.chat.completions.create(model=self.name,
                                                            messages=message,
                                                            temperature=temperature,
                                                            top_p=top_p,
                                                            max_tokens=max_new)
            return response.choices[0].message.content
        except BadRequestError as e:
            # Context length exceeded. Determine the max number of tokens we can ask for and retry.
            m = re.search(r'maximum context length is \d+ tokens, however you requested \d+ tokens', str(e))
            if m:
                print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")
            else:
                print("General exception encountered while running the query: {error}".format(error=str(e)))
        except RateLimitError as e:
            print("{model} could not complete the request: {error}".format(model=self._modelName, error=str(e)))
        except Exception as e:
            print(f"{type(e)}: {str(e)}")
        return ""
