"""
Aho-Corasick multi-pattern string matching algorithm.

Builds a finite automaton from a set of patterns and runs text matching
in O(N + M + Z) time where:
  N = length of input text
  M = total length of all patterns
  Z = number of matches found

Used by Aegis to detect PII and secret tokens in a single linear pass.
"""

from collections import deque
from typing import List, Tuple


class AhoCorasick:
    def __init__(self):
        # Each node: dict of char -> child node index
        self.goto: List[dict] = [{}]
        # Failure links (like KMP failure function, but for trie)
        self.fail: List[int] = [0]
        # Output: patterns that end at this node
        self.output: List[List[str]] = [[]]
        self._built = False

    def add_pattern(self, pattern: str) -> None:
        """Insert a pattern into the trie."""
        if self._built:
            raise RuntimeError("Cannot add patterns after automaton is built.")
        node = 0
        for ch in pattern:
            if ch not in self.goto[node]:
                self.goto[node][ch] = len(self.goto)
                self.goto.append({})
                self.fail.append(0)
                self.output.append([])
            node = self.goto[node][ch]
        self.output[node].append(pattern)

    def build(self) -> None:
        """
        Construct failure links via BFS (breadth-first) over the trie.
        This is the key step that makes Aho-Corasick O(N) at search time.
        """
        queue = deque()

        # All depth-1 nodes fail back to root (node 0)
        for ch, child in self.goto[0].items():
            self.fail[child] = 0
            queue.append(child)

        while queue:
            node = queue.popleft()
            for ch, child in self.goto[node].items():
                # Follow failure links to find longest proper suffix
                # that is also a prefix of some pattern
                f = self.fail[node]
                while f != 0 and ch not in self.goto[f]:
                    f = self.fail[f]
                self.fail[child] = self.goto[f].get(ch, 0)
                if self.fail[child] == child:
                    self.fail[child] = 0
                # Merge outputs: if fail node has matches, inherit them
                self.output[child] = (
                    self.output[child] + self.output[self.fail[child]]
                )
                queue.append(child)

        self._built = True

    def search(self, text: str) -> List[Tuple[int, str]]:
        """
        Search text for all pattern occurrences.
        Returns list of (end_index, pattern) tuples.
        Time complexity: O(N + Z) where Z = number of matches.
        """
        if not self._built:
            self.build()

        results = []
        node = 0

        for i, ch in enumerate(text):
            # Follow failure links until we find a valid transition or reach root
            while node != 0 and ch not in self.goto[node]:
                node = self.fail[node]
            node = self.goto[node].get(ch, 0)

            if self.output[node]:
                for pattern in self.output[node]:
                    start = i - len(pattern) + 1
                    results.append((start, pattern))

        return results
