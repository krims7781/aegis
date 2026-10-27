import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from core.aho_corasick import AhoCorasick
from core.db import fetch_all_tenant_patterns


class PersistentTrieRegistry:
    def __init__(self):
        self._registry: Dict[str, AhoCorasick] = {}
        self._executor = ThreadPoolExecutor(max_workers=2)

    def get_trie(self, tenant_id: str) -> Optional[AhoCorasick]:
        """O(1) RAM lookup. Falls back to default base rules if tenant not found."""
        return self._registry.get(tenant_id) or self._registry.get("_default_")

    def _compile_trie(self, patterns: List[Tuple[str, str]]) -> AhoCorasick:
        ac = AhoCorasick()
        for pattern, _ in patterns:
            ac.add_pattern(pattern.lower())
        if patterns:
            ac.build()
        return ac

    async def hot_swap_tenant(self, tenant_id: str, patterns: List[Tuple[str, str]]) -> None:
        """Compiles in thread pool, then atomically swaps pointer in RAM."""
        loop = asyncio.get_running_loop()
        new_automaton = await loop.run_in_executor(
            self._executor, self._compile_trie, patterns
        )
        self._registry[tenant_id] = new_automaton

    async def hydrate_from_db(self) -> None:
        """Loads persistent rules into RAM at server startup."""
        all_rules = fetch_all_tenant_patterns()
        for tenant_id, patterns in all_rules.items():
            await self.hot_swap_tenant(tenant_id, patterns)
