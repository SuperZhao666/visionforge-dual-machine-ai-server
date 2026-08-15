#!/usr/bin/env python3
"""Probe Xianyu publish capabilities without exposing account credentials."""
from __future__ import annotations

import asyncio

from db_manager import db_manager
from utils.item_publisher import ItemPublisher


async def probe_publish_capabilities() -> None:
    accounts = db_manager.get_all_cookies()
    if len(accounts) != 1:
        raise RuntimeError("publish capability probe requires exactly one configured account")

    account_id, cookie_value = next(iter(accounts.items()))
    proxy_config = db_manager.get_cookie_proxy_config(account_id)
    async with ItemPublisher(cookie_value, account_id, proxy_config=proxy_config) as publisher:
        response = await publisher._post_mtop(
            api_name="mtop.idle.pc.idleitem.preget",
            version="1.0",
            payload={},
            spm_cnt="a21ybx.publish.0.0",
            spm_pre="a21ybx.home.sidebar.1",
        )

    if not publisher.is_success_response(response):
        raise RuntimeError("Xianyu publish capability probe failed")
    response_data = response.get("data") if isinstance(response, dict) else None
    response_data = response_data if isinstance(response_data, dict) else {}
    print("publish_preget=ok")
    print(
        "multi_sku_supported="
        + ("yes" if response_data.get("supportSkuOrInventory") is True else "no")
    )


if __name__ == "__main__":
    asyncio.run(probe_publish_capabilities())
