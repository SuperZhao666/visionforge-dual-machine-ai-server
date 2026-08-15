"""Offline contracts for the pinned upstream multi-SKU publishing extension.

These tests intentionally load the ignored ``upstream`` checkout when it is
present.  A source checkout is created by ``prepare.sh``; environments that
only contain the deployment wrapper skip this suite with an explicit reason.
No test performs network or production database access.
"""
from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock


UPSTREAM_ROOT = Path(__file__).resolve().parents[1] / "upstream"
PUBLISHER_PATH = UPSTREAM_ROOT / "utils" / "item_publisher.py"
CATALOG_PATH = UPSTREAM_ROOT / "domain" / "visionforge_catalog.py"


def _load_item_publisher_class():
    if not PUBLISHER_PATH.is_file():
        return None, "pinned upstream checkout is absent; run prepare.sh source checkout first"

    fake_package = types.ModuleType("utils")
    fake_package.__path__ = [str(UPSTREAM_ROOT / "utils")]
    fake_xianyu_utils = types.ModuleType("utils.xianyu_utils")
    fake_xianyu_utils.generate_sign = lambda *_args, **_kwargs: "offline-signature"
    fake_xianyu_utils.trans_cookies = lambda _value: {}
    previous_modules = {
        name: sys.modules.get(name)
        for name in ("utils", "utils.xianyu_utils")
    }
    try:
        sys.path.insert(0, str(UPSTREAM_ROOT))
        sys.modules["utils"] = fake_package
        sys.modules["utils.xianyu_utils"] = fake_xianyu_utils
        spec = importlib.util.spec_from_file_location(
            "visionforge_multisku_contract_item_publisher",
            PUBLISHER_PATH,
        )
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module.ItemPublisher, ""
    finally:
        if sys.path and sys.path[0] == str(UPSTREAM_ROOT):
            sys.path.pop(0)
        for name, previous in previous_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


ItemPublisher, SKIP_REASON = _load_item_publisher_class()


def _load_catalog_module():
    if not CATALOG_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "visionforge_multisku_contract_catalog",
        CATALOG_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


catalog = _load_catalog_module()


@unittest.skipUnless(ItemPublisher is not None, SKIP_REASON)
class MultiSkuPublisherContractTests(unittest.IsolatedAsyncioTestCase):
    def test_five_packages_follow_official_item_sku_list_shape(self) -> None:
        variants = [
            {"spec_value": "1小时", "price": 9.9, "quantity": 5},
            {"spec_value": "5小时", "price": 39, "quantity": 1},
            {"spec_value": "10小时", "price": 69, "quantity": 1},
            {"spec_value": "50小时", "price": 299, "quantity": 1},
            {"spec_value": "100小时", "price": 499, "quantity": 1},
        ]

        result = ItemPublisher.build_item_sku_list("套餐", variants)

        self.assertEqual(
            result,
            [
                {
                    "priceInCent": "990",
                    "quantity": 5,
                    "propertyList": [{"propertyText": "套餐", "valueText": "1小时"}],
                },
                {
                    "priceInCent": "3900",
                    "quantity": 1,
                    "propertyList": [{"propertyText": "套餐", "valueText": "5小时"}],
                },
                {
                    "priceInCent": "6900",
                    "quantity": 1,
                    "propertyList": [{"propertyText": "套餐", "valueText": "10小时"}],
                },
                {
                    "priceInCent": "29900",
                    "quantity": 1,
                    "propertyList": [{"propertyText": "套餐", "valueText": "50小时"}],
                },
                {
                    "priceInCent": "49900",
                    "quantity": 1,
                    "propertyList": [{"propertyText": "套餐", "valueText": "100小时"}],
                },
            ],
        )

    def test_legacy_single_item_payload_remains_unchanged(self) -> None:
        publisher = ItemPublisher.__new__(ItemPublisher)
        publisher._build_unique_code = lambda: "fixed-code"

        payload = publisher._build_publish_payload(
            title="Legacy item",
            description="Legacy description",
            uploaded_images=[
                {"url": "https://img.example.test/a.jpg", "width": 800, "height": 600}
            ],
            channel_res={"data": {"cardList": []}},
            location={
                "area": "A",
                "city": "C",
                "divisionId": 11,
                "longitude": 120.1,
                "latitude": 30.2,
                "poiId": "P",
                "poi": "Place",
                "prov": "Province",
            },
            current_price=12.34,
            original_price=20.0,
            delivery_choice="无需邮寄",
            post_price=None,
            can_self_pickup=False,
            category_result={
                "catId": "1",
                "catName": "Category",
                "channelCatId": "2",
                "tbCatId": "3",
            },
        )

        self.assertEqual(
            {
                "freebies": False,
                "itemTypeStr": "b",
                "quantity": "1",
                "simpleItem": "true",
                "imageInfoDOList": [
                    {
                        "extraInfo": {"isH": "false", "isT": "false", "raw": "false"},
                        "isQrCode": False,
                        "url": "https://img.example.test/a.jpg",
                        "heightSize": 600,
                        "widthSize": 800,
                        "major": True,
                        "type": 0,
                        "status": "done",
                    }
                ],
                "itemTextDTO": {
                    "desc": "Legacy description",
                    "title": "Legacy item",
                    "titleDescSeparate": True,
                },
                "itemLabelExtList": [],
                "itemPriceDTO": {"priceInCent": "1234", "origPriceInCent": "2000"},
                "userRightsProtocols": [
                    {"enable": False, "serviceCode": "SKILL_PLAY_NO_MIND"}
                ],
                "itemPostFeeDTO": {
                    "canFreeShipping": False,
                    "supportFreight": False,
                    "onlyTakeSelf": False,
                    "templateId": "0",
                },
                "itemAddrDTO": {
                    "area": "A",
                    "city": "C",
                    "divisionId": 11,
                    "gps": "120.1,30.2",
                    "poiId": "P",
                    "poiName": "Place",
                    "prov": "Province",
                },
                "defaultPrice": False,
                "itemCatDTO": {
                    "catId": "1",
                    "catName": "Category",
                    "channelCatId": "2",
                    "tbCatId": "3",
                },
                "uniqueCode": "fixed-code",
                "sourceId": "pcMainPublish",
                "bizcode": "pcMainPublish",
                "publishScene": "pcMainPublish",
            },
            payload,
        )

    async def test_capability_false_blocks_before_upload_or_publish(self) -> None:
        publisher = ItemPublisher.__new__(ItemPublisher)
        publisher.get_publish_capabilities = AsyncMock(
            return_value={"multi_sku_supported": False}
        )
        publisher.prepare_image_for_publish = AsyncMock(
            side_effect=AssertionError("image upload must not start")
        )
        publisher.get_public_channel = AsyncMock(
            side_effect=AssertionError("publish preparation must not start")
        )
        publisher._post_mtop = AsyncMock(
            side_effect=AssertionError("publish API must not be called")
        )

        with self.assertRaisesRegex(ValueError, "PUBLISH_MULTI_SKU_UNSUPPORTED"):
            await publisher.publish_item(
                title="VisionForge",
                description="Five packages",
                images=[{"url": "https://img.example.test/a.jpg"}],
                current_price=None,
                original_price=None,
                delivery_choice="无需邮寄",
                post_price=None,
                can_self_pickup=False,
                spec_name="套餐",
                variants=[
                    {"spec_value": "1小时", "price": 9.9, "quantity": 1},
                    {"spec_value": "5小时", "price": 39, "quantity": 1},
                ],
            )

        publisher.get_publish_capabilities.assert_awaited_once_with()
        publisher.prepare_image_for_publish.assert_not_awaited()
        publisher.get_public_channel.assert_not_awaited()
        publisher._post_mtop.assert_not_awaited()

    def test_duplicate_or_missing_spec_fails_closed(self) -> None:
        invalid_variants = [
            {"spec_value": "10 小时", "price": 69, "quantity": 1},
            {"spec_value": "10小时", "price": 69, "quantity": 1},
        ]
        with self.assertRaisesRegex(ValueError, "规格值不能重复"):
            ItemPublisher.build_item_sku_list("套餐", invalid_variants)

        with self.assertRaisesRegex(ValueError, "规格名称长度必须为 1-20"):
            ItemPublisher.build_item_sku_list(
                "",
                [
                    {"spec_value": "1小时", "price": 9.9, "quantity": 1},
                    {"spec_value": "5小时", "price": 39, "quantity": 1},
                ],
            )

    def test_variant_quantity_is_inventory_and_can_exceed_one(self) -> None:
        result = ItemPublisher.build_item_sku_list(
            "套餐",
            [
                {"spec_value": "1小时", "price": 9.9, "quantity": 5},
                {"spec_value": "5小时", "price": 39, "quantity": 8},
            ],
        )

        self.assertEqual([sku["quantity"] for sku in result], [5, 8])

    def test_variant_without_inventory_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "必须填写库存"):
            ItemPublisher.build_item_sku_list(
                "套餐",
                [
                    {"spec_value": "1小时", "price": 9.9},
                    {"spec_value": "5小时", "price": 39, "inventory": 8},
                ],
            )

    def test_order_purchase_quantity_above_one_fails_closed(self) -> None:
        self.assertIsNotNone(catalog)
        self.assertEqual(catalog.validate_single_unit_order_quantity(1), 1)
        with self.assertRaisesRegex(ValueError, "FULFILLMENT_SINGLE_UNIT_REQUIRED"):
            catalog.validate_single_unit_order_quantity(2)

    def test_missing_order_purchase_quantity_fails_closed(self) -> None:
        self.assertIsNotNone(catalog)
        for missing_quantity in (None, ""):
            with self.subTest(missing_quantity=missing_quantity):
                with self.assertRaisesRegex(ValueError, "FULFILLMENT_SINGLE_UNIT_REQUIRED"):
                    catalog.validate_single_unit_order_quantity(missing_quantity)

    def test_missing_or_partial_order_spec_fails_closed(self) -> None:
        self.assertIsNotNone(catalog)
        with self.assertRaisesRegex(ValueError, "RULE_MATCH_SPEC_INVALID"):
            catalog.build_order_spec_key("套餐", "")
        with self.assertRaisesRegex(ValueError, "RULE_MATCH_SPEC_INVALID"):
            catalog.build_order_spec_key("套餐", "10小时", "颜色", "")


if __name__ == "__main__":
    unittest.main()
