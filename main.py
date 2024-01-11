from model.llama import CodeLlama
from model.model import *

def receiver(results: List[str]) -> None:
    print(results)

def main():
    model = LanguageModel([CodeLlama("/data/codellama/CodeLlama-34b-Instruct-hf/")])
    model.query(receiver, Query())


if __name__ == '__main__':
    main()
