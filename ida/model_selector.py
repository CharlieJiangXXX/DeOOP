import functools
import re
import threading

import ida_kernwin
import openai


"""
Abstraction layer that provides interfaces to various models. Picks model based on global variable.
"""

# this one focuses on model selection, basically static (singleton)


class ModelSelector:
    model = None

    # so, we set a query_model function as a member var, and here we simply call that!
    def query_model_async(self, query, cb):
        """
        Function which sends a query to {model} and calls a callback when the response is available.
        :param query: The request to send to {model}
        :param cb: Tu function to which the response will be passed to.
        """
        print(f"Request to {self.model} sent...")
        t = threading.Thread(target=self.query_func, args=[query, cb])
        t.start()


    # i think we should get rid of the cb here
    def _query_gpt(self, query, cb, max_tokens=6500):
        # TO-DO: move this thing to the model folder, use our prompts instead; do a little interface
        # that takes all "generation" callbacks of models

        """
        Function which sends a query to gpt-3.5-turbo or gpt-4 and calls a callback when the response is available.
        Blocks until the response is received
        :param query: The request to send to gpt-3.5-turbo or gpt-4
        :param cb: Tu function to which the response will be passed to.
        """
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0]["message"]["content"]),
                                     ida_kernwin.MFF_WRITE)

    @classmethod
    def select_model(cls, vendor: str, model: str, size: int) -> bool:
        match vendor:
            case "openai":
                # check for api key, etc.
                """
                # Get OPENAPI PROXY
                if not config.get('OpenAI', 'OPENAI_PROXY'):
                    openai.proxy = None
                else:
                    openai.proxy = config.get('OpenAI', 'OPENAI_PROXY')
                    print(f"OpenAI Proxy set to {openai.proxy}")
                    
                # Select model
                    requested_model = config.get('Gepetto', 'MODEL')
                    model = get_model(requested_model)
                """
                return False

            case "meta":
                match model:
                    case "code-llama":
                        # for now, load from local; in the future, ask for proxy / provide local model path
                        return True
                    case "dirty-llama":
                        # hosted on server, require api key in the future
                        return False

            # maybe support dirty
