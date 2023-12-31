import dataclasses
from abc import ABC, abstractmethod
from typing import List, Callable, Optional
from pydispatch import dispatcher
import asyncio
from concurrent.futures import ThreadPoolExecutor

FunctionSegmenter = Callable[[str], List[str]]
SegmentMerger = Callable[[List[str]], str]
OutputVerifier = Callable[[str], (bool, str)]


def default_function_segmenter(function: str) -> List[str]:
    return [function]


def default_segment_merger(segments: List[str]) -> str:
    return "".join(segments)


def default_output_verifier(output: str) -> (bool, str):
    return True, output


@dataclasses.dataclass
class Query:
    """
    :var id: Unique identifier of the query, to be managed by the caller
    :var system: The system prompt providing identity, overall instructions, and examples.
    :var prompt: The instruction part of the user prompt. Note that external references (e.g. global
    variables, function declarations) should be added here, as they must be retained even when
    the data is too long.
    :var data: Data of the query, including function pseudocode and types to be augmented. While
    this would be processed as a user prompt, it differs in that it may be segmented in case of
    length excess.
    """
    id: int
    system: List[str]
    prompt: str
    data: str
    top_p: float = 0.1
    temperature: float = 0.2
    parallel_cnt: int = 1
    function_segmenter: FunctionSegmenter = default_function_segmenter
    segment_merger: SegmentMerger = default_segment_merger
    output_verifier: OutputVerifier = default_output_verifier


class BaseModel(ABC):
    """
    Base class for all language models supported. Subclasses must implement ``query``, define
    the max number of tokens supported by the model represented, the maximum concurrent queries
    supported, and the name of the model. Concrete functionality should be implemented in the
    ``LanguageModel`` class.
    """

    # Output length allowed in relation to the query
    DATA_SCALE_FACTOR = 1.2

    def __init__(self) -> None:
        self._processQueue = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(self.max_concurrent_queries)
        self._tempResponses = {}
        loop = asyncio.get_event_loop()
        workers = [self.worker() for _ in range(self.max_concurrent_queries)]
        loop.run_until_complete(asyncio.gather(*workers))

    @property
    def max_tokens_supported(self) -> int:
        return 0

    @property
    def max_concurrent_queries(self) -> int:
        return 1

    @property
    def name(self):
        return "Generic"

    @abstractmethod
    def num_tokens(self, query: str) -> int:
        return len(query)

    def _query(self, query: Query) -> str:
        while True:
            # In addition to the length of the prompts, we predict those of outputs and aggregate them
            max_tokens_for_func = self.max_tokens_supported - (sum(self.num_tokens(s) for s in query.system)
                                                               - self.num_tokens(query.prompt))

            def over(dat: str) -> bool:
                return max_tokens_for_func > self.num_tokens(dat) * (1 + self.DATA_SCALE_FACTOR)

            segs = []

            def split(dat: str) -> None:
                if over(dat):
                    for d in query.function_segmenter(dat):
                        split(d)
                else:
                    segs.append(dat)

            split(query.data)
            res, out = query.output_verifier(
                query.segment_merger([self.__query(query.system, query.prompt, d, query.top_p,
                                                   query.temperature) for d in segs]))
            if res:
                return out

    @abstractmethod
    def __query(self, system: List[str], prompt: str, data: str, top_p: float, temperature: float) -> str:
        """
        Sends generic queries to the current model, returning a tuple of the prompts and results.
        :returns: The model's response to the queries.
        """
        raise NotImplementedError

    def enqueue_query(self, query: Query) -> None:
        """
        Enqueues queries to be run concurrently.
        :param query: A list of queries, each with unique IDs. Set ``parallel_cnt`` should a query
         be run more than once.
        :param function_segmenter: A callable to break a function into segments. Must support recursive
        segmentation, as a segment that is still exceeds the token limit will be processed by this same
        callback.
        :param segment_merger: A callable to merge the segments back together.
        :param output_verifier: A callable to verify that the output is of the correct format and contents.
        If so, return True, as well as the output with minor modifications if needed.
        :return:
        """
        for _ in range(query.parallel_cnt):
            query.parallel_cnt -= 1
            self._processQueue.put_nowait(query)

    def process_query(self, query: Query) -> None:
        if query.id not in self._tempResponses:
            self._tempResponses[query.id] = []
        else:
            self._tempResponses[query.id].append(self._query(query))
        if not query.parallel_cnt:
            dispatcher.send(signal=query.id, sender=self.name, data=self._tempResponses[query.id])
            self._tempResponses.pop(query.id)

    async def worker(self):
        while True:
            async with self._semaphore:
                query = await self._processQueue.get()
                self.process_query(query)
                self._processQueue.task_done()
