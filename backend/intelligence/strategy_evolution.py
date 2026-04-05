"""StrategyEvolutionEngine — Research-backed exploit chain enrichment (Section 15.3).

Queries ResearchKB for relevant PoCs and SmartMemory for historical
success rates, enriching each exploit chain node with intelligence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.intelligence.research_kb import ResearchKB
from backend.memory.smart_memory import SmartMemory

logger = logging.getLogger(__name__)


@dataclass
class ChainNode:
    """A single step in an exploit chain."""

    step_id: str
    technique: str
    cve_id: str | None = None
    tool: str | None = None
    description: str = ""
    # Enrichment fields (set by StrategyEvolutionEngine)
    poc_urls: list[str] = field(default_factory=list)
    attack_technique_id: str | None = None
    historical_success_rate: float | None = None


@dataclass
class AttackChain:
    """A sequence of exploit steps."""

    chain_id: str
    nodes: list[ChainNode] = field(default_factory=list)
    target: str = ""


@dataclass
class EnrichedAttackChain:
    """An attack chain enriched with research intelligence."""

    chain: AttackChain
    enrichment_count: int = 0
    research_sources: list[str] = field(default_factory=list)


class StrategyEvolutionEngine:
    """Enriches exploit chains with ResearchKB intelligence and SmartMemory history.

    Queries ResearchKB when ExploitChainer builds attack graphs.
    Enriches each chain step with relevant PoCs, ATT&CK techniques,
    and historical success rates from SmartMemory.
    """

    def __init__(
        self,
        research_kb: ResearchKB,
        smart_memory: SmartMemory,
    ) -> None:
        self._kb = research_kb
        self._memory = smart_memory

    async def enrich_chain(self, chain: AttackChain) -> EnrichedAttackChain:
        """Enrich all nodes in an attack chain with research intelligence."""
        enrichment_count = 0
        sources: set[str] = set()

        for node in chain.nodes:
            enriched = await self._enrich_node(node)
            if enriched:
                enrichment_count += 1

            # Gather sources from PoCs
            if node.cve_id:
                entries = await self._kb.query(cve_id=node.cve_id)
                for e in entries:
                    for s in e.sources_merged:
                        sources.add(s)

        return EnrichedAttackChain(
            chain=chain,
            enrichment_count=enrichment_count,
            research_sources=list(sources),
        )

    async def _enrich_node(self, node: ChainNode) -> bool:
        """Enrich a single chain node. Returns True if any enrichment occurred."""
        enriched = False

        # Query ResearchKB for PoCs by CVE
        if node.cve_id:
            pocs = await self._kb.query(cve_id=node.cve_id)
            if pocs:
                node.poc_urls = [p.poc_url for p in pocs if p.poc_url]
                if pocs[0].technique_id:
                    node.attack_technique_id = pocs[0].technique_id
                enriched = True

        # Query ResearchKB by technique
        if node.technique and not node.attack_technique_id:
            technique_entries = await self._kb.query(keyword=node.technique, limit=3)
            if technique_entries:
                for te in technique_entries:
                    if te.technique_id:
                        node.attack_technique_id = te.technique_id
                        break
                    if te.poc_url and te.poc_url not in node.poc_urls:
                        node.poc_urls.append(te.poc_url)
                enriched = True

        # Query SmartMemory for historical success rate
        if node.tool:
            tools = await self._memory.get_best_tools(
                target_type=node.technique or "general", top_k=10,
            )
            for t in tools:
                if t["tool"] == node.tool:
                    node.historical_success_rate = t["avg_success_rate"]
                    enriched = True
                    break

        return enriched
