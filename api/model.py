import itertools
from typing import Dict, Optional

from api.artifacts.function import Function
from api.models.base_model import *

QueryCompleteCallback = Callable[[List[str]], None]


class LLMController:
    """
    Note that all feature functions could be called concurrently with the ____ decorator, and the best result among
    a few would be selected.

    techniques to be used here:
        1. chain of thought (intraprocedural analysis)
        2. divine intellect; you are an expert ..
        3. separate into cases (e.g. if i ask it to rank on a scale from 1 to 5, give example for each), few-shot in-context learning
        4. thinking in english, then convert to json, etc.
        5. self-critique + similarity criterion
        5. temperature & top_p tweaking
        6. eliminate shittalk with single token
        7. block-chain-esque critique
        8. best out of n (parallel)
        To help clarify that the example messages are not part of a real conversation, and shouldn't be referred back
        to by the model, you can try setting the name field of system messages to example_user and example_assistant.
    """

    # laconic
    # "Great job so far, these have been perfect" after examples


    # preprocessing is super important
    # graph of thought
    # if we are to train it, supervise with other models
    # gotta implement (with decorators?) running every method multiple times and picking the best result


    async def resolve_errors(self, errs: str, defs: str, func: Function) -> bool:
        # make sure to filter out the externs before
        # asm is not invovled here, which is good. just give the compiler defs and the current func,
        # which would be updated iteratively
        pass



    # give naming convention from the outside
    # ChatGPT often refuses to generate new names if variables
    # already have non-trivial names in the code.

    # ask for confidence (already expanded upon in self-critique)
    """
    Idea: instead of brute-forcing rename & refine recursively all the way through, the search could be optimized
    by designing a criterion to determine if each place currently serves as a context (gives information), or
    receiver (receives information); idea still under development 
    """
    def rename(self, function: str) -> [str, Dict[str, str]]:
        """
        Renames function and its variables. Should the function contain any callee, its `refine` would be invoked
        with this function as the context. This allows for continuous propagation.
        :param function: the function whose body is to be processed
        :return: The processed function and a JSON dictionary containing with the original names as keys and new
        names as values.
        """

        # prompts are to be improved
        system = ["You are an expert static analyst who analyzes C/C++ functions, thinking according to context and step-by-step."]
        # give a bunch of examples
        # list all the variables

        # utilizes the "think in English" technique to solicit better outcomes
        queries = [
            "Analyze the function and suggest better names for the it and each variable. Feel free to convey your thoughts in a paragraph, and if a name is good already, don't change it.",
            "Now incorporate your insights into code! Suggest more readable names for the function, arguments and temporary variables inline, and output the generated code with comments"
            "explaining each naming decision (at the declaration or first usage of the variable).",
        ]
        queries[0] += f"The function to be modified: {function}"

        # find the best temp and top_p
        results = self.query(system, queries)
        print(results)

        # parse out json

        # permute through functions in the text, feed to refine, but we do this from the outside
        return results

    def refine(self, function: str, context: str):
        """
            Refine decompilation of a function based on the context of its callers.
            TO-DO: design weight mechanism, we don't want names refined every time. Confidence level, don't call rename
            if no need. Also decide how far we should go in terms of recursion.
            "refine":
    {
        "system": "You are a code editor who reinterprets functions based on contexts, that is, code segments where they are invoked.",
        "user": {
            "rename": "Rename the function and its arguments based on the contexts showing how it is called. Remember, do this only when applicable: no need to change anything if the name and parameters work as is!"
        }
    },
        """
        # opname = "refine"
        # return self.query_model([self.prompt(opname, "rename", function)])
        pass

    def summarize(self):
        """
        "summary":
    {
        "system": "You are a powerful AI model specializing in code summary who always outputs a confidence metric out of 10 at the end.",
        "user": {
            "function": "Provide your response in three parts: 1. A brief overview of the function, preferably within 50 words; 2. An in-depth discussion of the procedures taken by the function in one paragraph, preferably within 200 words; 3. Description of every input parameter and return value, including type and functionality.",
            "function_name": "Output a name for the function based on what it does. Note that if the current name works, there's no need to change it: simply output it as is.",
            "segment_long": "Provide an in-depth discussion of the procedures taken by the shown code in one paragraph, preferably within 200 words.",
            "segment_short": "Provide a brief overview of the shown code, preferably within 50 words."
        }
    },
        :return:
        """
        pass

    def recover(self, struct: str):
        """
        We want to find out what's the best way to integrate it with the renaming. Like they are supposed to be
        concurrent, but which one first?
        :return:

        "infer":
    {
        "user": {
            "general": "Based on the provided code segment, in which some variables are of the given type, rename each field in the type that has been used. Return the modified structure. Note that there is no need to change a field is there is not sufficient information!",
            "detail": "For each field that has been used, give an overview of the way it was used expressed as a comment above the field's declaration. Return the modified structure."
        }
    },
        """
        pass

