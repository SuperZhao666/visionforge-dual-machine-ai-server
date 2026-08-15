package com.visionforge.inferencebenchmark;

/** Dependency-free contract for fail-closed MAKCU CDC interface selection. */
final class MakcuUsbInterfaceSelectorSelfTest {
    static void run() {
        selectsTheOnlyInterfaceWithBothBulkDirections();
        rejectsDirectionsSplitAcrossInterfaces();
        rejectsMultipleCompleteInterfaces();
        rejectsMissingAndInvalidSummaries();
    }

    private static void selectsTheOnlyInterfaceWithBothBulkDirections() {
        MakcuUsbInterfaceSelector.Result result =
                MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                new int[] {2, 10, 0},
                new int[] {0, 1, 0},
                new int[] {1, 1, 0});
        require(result.succeeded);
        require(result.interfaceIndex == 1);
        require("none".equals(result.failureToken));
    }

    private static void rejectsDirectionsSplitAcrossInterfaces() {
        MakcuUsbInterfaceSelector.Result result =
                MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                new int[] {10, 10},
                new int[] {1, 0},
                new int[] {0, 1});
        require(!result.succeeded);
        require(result.interfaceIndex == -1);
        require("no_cdc_data_interface_with_bulk_in_and_out".equals(result.failureToken));
    }

    private static void rejectsMultipleCompleteInterfaces() {
        MakcuUsbInterfaceSelector.Result result =
                MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                new int[] {10, 10},
                new int[] {1, 1},
                new int[] {1, 1});
        require(!result.succeeded);
        require("multiple_cdc_data_interfaces_with_bulk_in_and_out_count_2"
                .equals(result.failureToken));
    }

    private static void rejectsMissingAndInvalidSummaries() {
        require(!MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                new int[] {10}, new int[] {0}, new int[] {0}).succeeded);
        require(!MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                new int[0], new int[0], new int[0]).succeeded);
        require(!MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                new int[] {10}, new int[] {1}, new int[] {1, 0}).succeeded);
        require(!MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                null, null, null).succeeded);

        MakcuUsbInterfaceSelector.Result ambiguousEndpoints =
                MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                        new int[] {10}, new int[] {2}, new int[] {1});
        require(!ambiguousEndpoints.succeeded);
        require("ambiguous_bulk_endpoints_interface_0"
                .equals(ambiguousEndpoints.failureToken));

        require(!MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                new int[] {0}, new int[] {1}, new int[] {1}).succeeded);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU USB interface selection failed");
    }
}
