from typing import List, Tuple
from fastapi import APIRouter, Request
from pydantic import BaseModel

from core.db import save_tenant_patterns
from core.trie_registry import PersistentTrieRegistry

router = APIRouter(prefix="/admin", tags=["admin"])


class RuleUpdatePayload(BaseModel):
    patterns: List[Tuple[str, str]]  # e.g., [("project-titan", "PROPRIETARY")]


@router.post("/tenants/{tenant_id}/rules")
async def update_tenant_rules(
    tenant_id: str,
    payload: RuleUpdatePayload,
    request: Request
):
    # 1. Save to DB (Source of truth)
    save_tenant_patterns(tenant_id, payload.patterns)
    
    # 2. Hot-swap RAM Trie in background
    registry: PersistentTrieRegistry = request.app.state.trie_registry
    await registry.hot_swap_tenant(tenant_id, payload.patterns)
    
    return {
        "status": "success",
        "tenant_id": tenant_id,
        "active_rules_count": len(payload.patterns)
    }
