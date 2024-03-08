import copy
import time
from typing import Dict, Tuple, Any, List, Optional

import networkx as nx

score_same_inst = 1.00  # debin previously has 0.9
score_same_stp = 0.85
score_timeout = 0.5
score_same_name = 0.0
score_empty = 1.00  # debin previously had 0.4
score_diff = 0.0
score_empty_and_same_name = 1.00

max_size_step = 0.001

connectivity_factor1 = 0.1
connectivity_factor2 = 0.8
connectivity_factor3 = 0.6
connectivity_factor4 = 0.2
use_connectivity_factors = False  # peng,prefer false, true for testing connectivity

init_max_size_ratio_cg = 0.999
init_max_score_ratio_cg = 0.999

timeout_length_cg1 = 1000.0
timeout_length_cg2 = 1000.0

timeout_count_cg1 = 100000
timeout_count_cg2 = 100000

skip_blk_diff_test_length = 50
skip_init_d_filter = 50

# BB pairs :: score
Matches = Dict[Tuple[Any, Any], float]


class IsoTimeout(Exception):
    pass


def get_max_score(max_size: int, max_score_ratio: float) -> float:
    return float(max_size) * max_score_ratio * score_same_inst


def get_match(id: Any, tbl: Matches, pos: int) -> Optional[Tuple[Any, float]]:
    for ids, score in tbl.items():
        if ids[pos] == id:
            return ids[1 - pos], score
    return None


def print_matched(matched):
    print("Matched pairs\n----------")
    for (id1, id2), score in matched.items():
        print(f"({id1},{id2}): {score}")
    print("----------\n")


class SubgraphIsomorphismFinder:
    def __init__(self, source: nx.DiGraph, target: nx.DiGraph, source_size: int,
                 pairwise_scores: Dict[Tuple[Any, Any], float], max_size_ratio: float, max_score_ratio: float,
                 timeout: int, max_queries: int):
        self.source_graph = source
        self.target_graph = target
        self.source_size = source_size
        self.max_size_ratio = max_size_ratio
        self.max_score_ratio = max_score_ratio
        self.pairwise_scores = pairwise_scores

        self.timeout = False
        self.timeout_value = timeout
        self.max_queries = max_queries
        self.result = {}
        self.current_best_score = 0.0
        self.max_subgraph_size = 0

    def weighted_score(self, node1, node2, score):
        if use_connectivity_factors:
            self.source_graph.predecessors(node1)

            pred1 = len(list(self.source_graph.predecessors(node1)))
            succ1 = len(list(self.source_graph.successors(node1)))
            pred2 = len(list(self.target_graph.predecessors(node2)))
            succ2 = len(list(self.target_graph.successors(node2)))
            mul = float(min(pred1, pred2) + min(succ1, succ2))
            if score > 0.0:
                if mul > 0.0:
                    return score * (mul ** connectivity_factor1)
                else:
                    return score * connectivity_factor2
            else:
                return (connectivity_factor3 ** (1.0 / mul)) * connectivity_factor4
        else:
            return score

    # weight-sorted target candidates for each unmatched source node
    # scores corresponds to iso's score parameter
    @property
    def unmatched(self) -> Dict[Any, List[Tuple[Any, float]]]:
        # all remaining unmatched target nodes
        possible = [id for id in self.target_graph.nodes if not get_match(id, self.result, 1)]
        print(f"Number of remaining unmatched nodes: {len(possible)}")
        ret = {}

        for source in self.source_graph.nodes:
            if match := get_match(source, self.result, 0):
                ret[source] = [match]
                continue

            candidates = [(candidate, self.pairwise_scores.get((source, candidate), 0.0)) for candidate in possible]
            # filter when source size exceeds threshold
            if self.source_size > skip_init_d_filter:
                filtered = [c for c in candidates if c[1] > 0.0]
                if filtered:
                    candidates = filtered
            # weight score
            candidates_weighted = [(candidate, self.weighted_score(source, candidate, score)) for
                                   candidate, score
                                   in candidates]
            # sort by score
            candidates_weighted_sorted = sorted(candidates_weighted, key=lambda x: x[1], reverse=True)
            ret[source] = candidates_weighted_sorted

        return ret

    @staticmethod
    def pick_any(unmatched):
        # obtain high score and number of candidates with that score
        def count_candidate(candidates):
            if not candidates:
                return 0.0, 0

            high_score = candidates[0][1]
            if high_score == 0.0:
                return 0.0, len(candidates)

            count = 1
            for _, score in candidates[1:]:
                if score != high_score:
                    break
                count += 1
            return high_score, count

        best_source = None
        best_score = 0.0
        min_count = 99999

        # pick id with smallest number of best candidates
        for source, candidates in unmatched.items():
            score, count = count_candidate(candidates)
            if count < min_count or (count >= min_count and score > best_score):
                best_source = source
                best_score = score
                min_count = count

        return best_source

    def refine(self, unmatched, source, target):
        assert source
        pred1 = self.source_graph.predecessors(source)
        succ1 = self.source_graph.successors(source)
        pred2 = self.target_graph.predecessors(target) if target else []
        succ2 = self.target_graph.successors(target) if target else []

        refined_unmatched = {}
        for id1, candidates in unmatched.items():
            # filter out the matched one
            if id1 != source:
                # the matched points must both precede or succeed any remaining possible matches
                # if new2 is null, then both any(test2) and any(test4) would be false. Hence
                # all pairs that have new1 as a predecessor or successor would be excluded
                candidates = [
                    (id2, id_score) for id2, id_score in candidates
                    if id2 != target and
                       (any(test1 == id1 for test1 in pred1) ==
                        any(test2 == id2 for test2 in pred2)) and
                       (any(test3 == id1 for test3 in succ1) ==
                        any(test4 == id2 for test4 in succ2))
                ]
                if candidates:
                    refined_unmatched[id1] = candidates

        return refined_unmatched

    def extendable(self, unmatched, matched: Matches, ideal_score):
        if not unmatched:
            return False

        matched_size = len(matched)
        matched_score_sum, candidates_score_sum = 0.0, 0.0

        for node in self.source_graph.nodes:
            if len(unmatched.get(node, [])) == 1:  # matched
                matched_score_sum += unmatched[node][0][1]
            else:
                candidates_score_sum += unmatched.get(node, [(None, 0.0)])[0][1]  # highest candidate score

        if matched_score_sum > self.current_best_score and matched_size > self.max_subgraph_size:
            self.result = matched
            self.max_subgraph_size = matched_size
            self.current_best_score = matched_score_sum

        return matched_score_sum + candidates_score_sum < ideal_score

    def _search(self, unmatched, matched, start_time, query_cnt, init_size, ideal_score):
        query_cnt = query_cnt + 1
        end_time = time.time()
        if (end_time - start_time) > self.timeout_value:
            print(
                f"timeout({end_time} - {start_time} > {self.timeout_value}): init_size={init_size} ret_size={self.max_subgraph_size}")
            raise IsoTimeout()

        if self.extendable(unmatched, matched, ideal_score):
            if source := self.pick_any(unmatched):
                print(f"Picking {source}")
                for candidate, score in unmatched[source]:
                    matched1 = copy.deepcopy(matched)
                    matched1[(source, candidate)] = score
                    print(f"[{query_cnt}] Adding ({source}, {candidate}) to matched")
                    print_matched(matched1)  # Assuming `print_matched` is defined elsewhere
                    query_cnt = self._search(self.refine(unmatched, source, candidate), matched1, start_time, query_cnt, init_size, ideal_score)
                matched2 = copy.deepcopy(matched)
                print(f"[{query_cnt}] Removing {source} from d")
                query_cnt = self._search(self.refine(unmatched, source, None), matched2, start_time, query_cnt, init_size, ideal_score)

        if query_cnt > self.max_queries:
            print(
                f"[!] Max query exceeded ({query_cnt} > {self.max_queries}): init_size={init_size} ret_size={self.max_subgraph_size}")
            raise IsoTimeout()

        return query_cnt

    def run(self):
        init_size = int(self.max_size_ratio * self.source_size)
        ideal_score = get_max_score(init_size, self.max_score_ratio)  # Assuming get_max_score is defined elsewhere

        print_matched(self.result)
        unmatched = self.unmatched
        to_start = time.time()

        try:
            self._search(unmatched, {}, to_start, 0, init_size, ideal_score)
            if self.max_subgraph_size > 0:
                print("[*] MCISI found!\n")
                print_matched(self.result)
                return True
            print("[!] Retrying MCISI with lowered size ratio\n")
            self.result = {}
            self.max_size_ratio -= max_size_step
            return self.run()
        except IsoTimeout:
            if not self.timeout:
                print("[!] Timeout -- retrying once\n")
                self.timeout = True
                self.max_size_ratio = 0.0
                self.max_score_ratio = 0.0
                return self.run()
        return False


# Maximum Common Induced Subgraph Isomorphism

def mcisi(source: nx.DiGraph, target: nx.DiGraph, source_size: int,
          pairwise_scores: Dict[Tuple[Any, Any], float]):
    finder = SubgraphIsomorphismFinder(source, target, source_size, pairwise_scores, init_max_size_ratio_cg,
                                       init_max_score_ratio_cg,
                                       timeout_count_cg1, timeout_count_cg1)
    return finder.run(), finder.result, finder.current_best_score, finder.max_subgraph_size
