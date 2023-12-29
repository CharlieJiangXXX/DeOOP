import openai
import tiktoken
from base_model import *


class OpenAIGPT(BaseModel):
    def __init__(self, model: str):
        super().__init__()
        self._modelName = ""
        self.name = model
        if not openai.api_key:
            raise Exception("OpenAI API missing!")
        self._encoding = tiktoken.get_encoding("cl100k_base")

    @property
    def name(self) -> str:
        return self._modelName

    @name.setter
    def name(self, name: str) -> None:
        if name not in ["gpt-4-32k", "gpt-3.5-turbo-1106"]:
            raise Exception(f"{name} is not a supported OpenAI model!")
        self._modelName = name

    @property
    def max_tokens_supported(self) -> int:
        match self.name:
            case "gpt-4-32k":
                return 32768
            case "gpt-3.5-turbo-1106":
                return 4096

    @property
    def max_concurrent_queries(self) -> int:
        # This must be limited lest we be banned
        return 3

    @abstractmethod
    def num_tokens(self, query: str) -> int:
        return len(self._encoding.encode(query))

    def __query(self, system: List[str], prompt: str, data: str, top_p: float, temperature: float) -> str:
        max_new = len(data) * self.DATA_SCALE_FACTOR

        message = [{"role": "system", "content": prompt} for prompt in system]
        message.append({"role": "user", "content": prompt})

        response = openai.ChatCompletion.create(
            model=self.name,
            messages=message,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_new
        )
        return response.choices[0]["message"]["content"]
