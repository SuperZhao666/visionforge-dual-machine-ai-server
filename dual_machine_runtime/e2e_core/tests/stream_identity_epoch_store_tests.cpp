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

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
using vf::host::domain::StreamIdentityGenerator;
using vf::host::infrastructure::FileEpochReservationStore;
using vf::test::expect;

#ifndef _WIN32
void verify_cross_process_reservations(
    const std::filesystem::path& root,
    const std::filesystem::path& state,
    std::uint64_t first_expected) {
    constexpr int kChildren = 4;
    constexpr int kPerChild = 25;
    std::vector<pid_t> children;
    children.reserve(kChildren);
    for (int child_index = 0; child_index < kChildren; ++child_index) {
        const pid_t child = ::fork();
        expect(child >= 0, "fork failed during epoch store process test");
        if (child == 0) {
            try {
                FileEpochReservationStore store(state);
                std::ofstream output(
                    root / ("child-" + std::to_string(child_index) + ".txt"),
                    std::ios::binary | std::ios::trunc);
                if (!output) ::_exit(21);
                for (int index = 0; index < kPerChild; ++index) {
                    output << store.reserve_next() << '\n';
                }
                output.flush();
                ::_exit(output ? 0 : 22);
            } catch (...) {
                ::_exit(23);
            }
        }
        children.push_back(child);
    }

    for (pid_t child : children) {
        int status{};
        expect(::waitpid(child, &status, 0) == child,
               "waitpid failed during epoch store process test");
        expect(WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "child process failed while reserving epochs");
    }

    std::vector<std::uint64_t> values;
    values.reserve(kChildren * kPerChild);
    for (int child_index = 0; child_index < kChildren; ++child_index) {
        std::ifstream input(root / ("child-" + std::to_string(child_index) + ".txt"));
        std::uint64_t value{};
        while (input >> value) values.push_back(value);
    }
    std::sort(values.begin(), values.end());
    expect(values.size() == static_cast<std::size_t>(kChildren * kPerChild),
           "cross-process reservations were lost");
    for (std::size_t index = 0; index < values.size(); ++index) {
        expect(values[index] == first_expected + index,
               "cross-process reservation was duplicated or skipped");
    }
}
#endif

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

#ifndef _WIN32
    verify_cross_process_reservations(root, state, 43U);
    const std::uint64_t highest_reserved = 142U;
#else
    const std::uint64_t highest_reserved = values.back();
#endif

    StreamIdentityGenerator generator(highest_reserved,
                                      std::numeric_limits<std::uint32_t>::max());
    const auto terminal = generator.next();
    expect(terminal.stream_epoch == highest_reserved, "generator ignored persisted epoch");
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
