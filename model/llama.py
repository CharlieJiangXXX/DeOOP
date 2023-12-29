from base_model import *
from typing import List, Literal, TypedDict

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

Role = Literal["system", "user"]


class Message(TypedDict):
    role: Role
    content: str


Dialog = List[Message]

B_INST, E_INST = "[INST]", "[/INST]"
B_SYS, E_SYS = "<<SYS>>\n", "\n<</SYS>>\n\n"

SPECIAL_TAGS = [B_INST, E_INST, "<<SYS>>", "<</SYS>>"]


class CodeLlama(BaseModel):
    def __init__(self, model_dir: str, model_size: int = 34) -> None:
        super().__init__()
        self._modelSize = 0
        self.model_size = model_size
        if not self.model_size:
            return

        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16
        )
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir, truncation_side="left", padding_side="right")
        if not self.tokenizer.eos_token:
            self.tokenizer.eos_token = self.tokenizer.bos_token
        self.tokenizer.pad_token = self.tokenizer.eos_token
        # experiment with max_memory (e.g. {0: "600MB", 1: "1GB"})
        self.model = AutoModelForCausalLM.from_pretrained(model_dir, device_map="auto",
                                                          quantization_config=quantization_config,
                                                          torch_dtype=torch.float16).to("cuda").to_bettertransformer()

    @property
    def model_size(self) -> int:
        return self._modelSize

    @model_size.setter
    def model_size(self, size: int) -> None:
        if size not in [7, 13, 34]:
            print(f"Local CodeLlama model cannot have size {size}!")
            return
        self._modelSize = size

    @property
    def max_tokens_supported(self) -> int:
        """
        While CodeLlama technically supports up to 100k tokens, we pick a value reasonably large while
        utilizing moderate memory.
        """
        return 8092

    @property
    def max_concurrent_queries(self) -> int:
        return 10

    @property
    def name(self):
        return f"CodeLlama-{self.model_size}B"

    def num_tokens(self, query: str) -> int:
        input_ids = self.tokenizer(query, return_tensors="pt", add_special_tokens=False).to("cuda")["input_ids"]
        return len(input_ids[0])

    def __query(self, system: List[str], prompt: str, data: str, top_p: float, temperature: float) -> str:
        sys = "".join([B_SYS + text + E_SYS for text in system])
        full_prompt = f"<s> {(B_INST + sys + prompt + data + E_INST).strip()}"

        input_ids = self.tokenizer(full_prompt, return_tensors="pt", add_special_tokens=False).to("cuda")["input_ids"]
        max_new = len(input_ids[0]) * self.DATA_SCALE_FACTOR
        outputs = self.model.generate(input_ids, do_sample=True,
                                      top_p=top_p, max_new_tokens=max_new,
                                      temperature=temperature)[0].to("cpu")
        return self.tokenizer.decode(outputs)
