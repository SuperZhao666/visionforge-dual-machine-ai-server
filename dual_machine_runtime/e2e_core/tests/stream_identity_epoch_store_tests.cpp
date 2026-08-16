#include "test_support.hpp"
#include "vf/host/domain/stream_identity_generator.hpp"
#include "vf/host/infrastructure/file_epoch_reservation_store.hpp"

#include <algorithm>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <thread>
#include <vector>

namespace {
using vf::host::domain::StreamIdentityGenerator;
using vf::host::infrastructure::FileEpochReservationStore;
using vf::test::expect;

void run() {
    const auto root = std::filesystem::temp_directory_path() /
        "visionforge_epoch_store_contract_test";
    std::error_code error;
    std::filesystem::remove_all(root, error);
    std::filesystem::create_directories(root);
    const auto state = root / "stream_epoch.state";

    FileEpochReservationStore first(state);
    FileEpochReservationStore second(state);
    expect(first.reserve_next() == 1, "first persisted epoch is not one");
    expect(second.reserve_next() == 2, "second store reused an epoch");

    std::mutex values_mutex;
    std::vector<std::uint64_t> values;
    auto reserve_many = [&](FileEpochReservationStore& store) {
        for (int index = 0; index < 20; ++index) {
            const auto value = store.reserve_next();
            std::scoped_lock lock(values_mutex);
            values.push_back(value);
        }
    };
    std::thread left(reserve_many, std::ref(first));
    std::thread right(reserve_many, std::ref(second));
    left.join();
    right.join();
    std::sort(values.begin(), values.end());
    expect(values.size() == 40, "concurrent reservations were lost");
    for (std::size_t index = 0; index < values.size(); ++index) {
        expect(values[index] == index + 3, "concurrent reservation was duplicated or skipped");
    }

    StreamIdentityGenerator generator(values.back(),
                                      std::numeric_limits<std::uint32_t>::max());
    const auto terminal = generator.next();
    expect(terminal.stream_epoch == values.back(), "generator ignored persisted epoch");
    expect(generator.rotation_required(), "terminal sequence did not require persisted rotation");
    const auto next_epoch = first.reserve_next();
    generator.rotate_to(next_epoch);
    expect(generator.next().stream_epoch == next_epoch,
           "generator did not accept newly persisted epoch");

    {
        std::ofstream corrupt(state, std::ios::binary | std::ios::trunc);
        corrupt << "not-an-epoch\n";
    }
    bool rejected = false;
    try {
        static_cast<void>(first.reserve_next());
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    expect(rejected, "corrupt epoch state was silently reset");
    std::filesystem::remove_all(root, error);
}
}  // namespace

int main() {
    try {
        run();
        std::cout << "STREAM_IDENTITY_EPOCH_STORE_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "STREAM_IDENTITY_EPOCH_STORE_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
