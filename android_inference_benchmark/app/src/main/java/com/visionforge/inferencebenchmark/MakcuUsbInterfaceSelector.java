package com.visionforge.inferencebenchmark;

/** Selects exactly one USB interface that owns both bulk directions. */
final class MakcuUsbInterfaceSelector {
    private MakcuUsbInterfaceSelector() {}

    static Result selectUniqueDataInterface(
            int[] interfaceClasses, int[] bulkInCounts, int[] bulkOutCounts) {
        if (interfaceClasses == null || bulkInCounts == null || bulkOutCounts == null
                || interfaceClasses.length == 0
                || interfaceClasses.length != bulkInCounts.length
                || interfaceClasses.length != bulkOutCounts.length) {
            return Result.failure("invalid_usb_interface_summary");
        }
        int selectedIndex = -1;
        int candidateCount = 0;
        for (int index = 0; index < bulkInCounts.length; index++) {
            if (interfaceClasses[index] != 10) continue;
            if (bulkInCounts[index] < 0 || bulkOutCounts[index] < 0) {
                return Result.failure("invalid_bulk_endpoint_count_interface_" + index);
            }
            if (bulkInCounts[index] > 1 || bulkOutCounts[index] > 1) {
                return Result.failure("ambiguous_bulk_endpoints_interface_" + index);
            }
            if (bulkInCounts[index] != 1 || bulkOutCounts[index] != 1) continue;
            selectedIndex = index;
            candidateCount++;
        }
        if (candidateCount == 0) {
            return Result.failure("no_cdc_data_interface_with_bulk_in_and_out");
        }
        if (candidateCount != 1) {
            return Result.failure("multiple_cdc_data_interfaces_with_bulk_in_and_out_count_"
                    + candidateCount);
        }
        return Result.success(selectedIndex);
    }

    static final class Result {
        final boolean succeeded;
        final int interfaceIndex;
        final String failureToken;

        private Result(boolean succeeded, int interfaceIndex, String failureToken) {
            this.succeeded = succeeded;
            this.interfaceIndex = interfaceIndex;
            this.failureToken = failureToken;
        }

        private static Result success(int interfaceIndex) {
            return new Result(true, interfaceIndex, "none");
        }

        private static Result failure(String failureToken) {
            return new Result(false, -1, failureToken);
        }
    }
}
