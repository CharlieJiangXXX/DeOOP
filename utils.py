from typing import List


def jaccard_similarity(l1: List, l2: List):
    """Define Jaccard Similarity function for two sets"""
    intersection = len(list(set(l1).intersection(l2)))
    union = (len(l2) + len(l2)) - intersection
    return float(intersection) / union
