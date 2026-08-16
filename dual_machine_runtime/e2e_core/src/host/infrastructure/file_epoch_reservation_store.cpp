#include "vf/host/infrastructure/file_epoch_reservation_store.hpp"

#include <charconv>
#include <cerrno>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace vf::host::infrastructure {
namespace {

std::uint64_t parse_epoch_file(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return 0;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot read persisted stream epoch state");
    }
    std::string text((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
        text.pop_back();
    }
    if (text.empty()) {
        throw std::runtime_error("persisted stream epoch state is empty");
    }
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) {
        throw std::runtime_error("persisted stream epoch state is malformed");
    }
    return value;
}

#ifdef _WIN32

class InterprocessLock {
public:
    explicit InterprocessLock(const std::filesystem::path& path) {
        handle_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                    "cannot open epoch lock file");
        }
        OVERLAPPED overlapped{};
        if (!LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped)) {
            const auto error = GetLastError();
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            throw std::system_error(static_cast<int>(error), std::system_category(),
                                    "cannot lock epoch state");
        }
    }

    ~InterprocessLock() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            OVERLAPPED overlapped{};
            UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &overlapped);
            CloseHandle(handle_);
        }
    }

    InterprocessLock(const InterprocessLock&) = delete;
    InterprocessLock& operator=(const InterprocessLock&) = delete;

private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

void persist_atomically(const std::filesystem::path& path, std::string_view content) {
    auto temporary = path;
    temporary += L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                "cannot create temporary epoch state");
    }
    DWORD written{};
    if (content.size() > static_cast<std::size_t>(MAXDWORD)) {
        CloseHandle(file);
        DeleteFileW(temporary.c_str());
        throw std::length_error("epoch state exceeds the Windows write limit");
    }
    const auto expected = static_cast<DWORD>(content.size());
    const bool write_ok = WriteFile(file, content.data(), expected,
                                    &written, nullptr) && written == expected;
    const bool flush_ok = write_ok && FlushFileBuffers(file);
    const auto write_error = flush_ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    if (!flush_ok) {
        DeleteFileW(temporary.c_str());
        throw std::system_error(static_cast<int>(write_error), std::system_category(),
                                "cannot persist temporary epoch state");
    }
    if (!MoveFileExW(temporary.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        DeleteFileW(temporary.c_str());
        throw std::system_error(static_cast<int>(error), std::system_category(),
                                "cannot atomically replace epoch state");
    }
}

#else

class InterprocessLock {
public:
    explicit InterprocessLock(const std::filesystem::path& path) {
        descriptor_ = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
        if (descriptor_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "cannot open epoch lock file");
        }
        if (::flock(descriptor_, LOCK_EX) != 0) {
            const auto error = errno;
            ::close(descriptor_);
            descriptor_ = -1;
            throw std::system_error(error, std::generic_category(),
                                    "cannot lock epoch state");
        }
    }

    ~InterprocessLock() {
        if (descriptor_ >= 0) {
            static_cast<void>(::flock(descriptor_, LOCK_UN));
            static_cast<void>(::close(descriptor_));
        }
    }

    InterprocessLock(const InterprocessLock&) = delete;
    InterprocessLock& operator=(const InterprocessLock&) = delete;

private:
    int descriptor_{-1};
};

void write_all(int descriptor, std::string_view content) {
    std::size_t offset{};
    while (offset < content.size()) {
        const auto written = ::write(descriptor, content.data() + offset, content.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(),
                                    "cannot write epoch state");
        }
        if (written == 0) {
            throw std::runtime_error("zero-length write while persisting epoch state");
        }
        offset += static_cast<std::size_t>(written);
    }
}

void persist_atomically(const std::filesystem::path& path, std::string_view content) {
    auto temporary = path;
    temporary += ".tmp." + std::to_string(static_cast<long long>(::getpid()));
    const int descriptor = ::open(temporary.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
                                  S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot create temporary epoch state");
    }
    bool descriptor_open = true;
    try {
        write_all(descriptor, content);
        if (::fsync(descriptor) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "cannot fsync epoch state");
        }
        if (::close(descriptor) != 0) {
            descriptor_open = false;
            throw std::system_error(errno, std::generic_category(),
                                    "cannot close epoch state");
        }
        descriptor_open = false;
    } catch (...) {
        if (descriptor_open) {
            static_cast<void>(::close(descriptor));
        }
        static_cast<void>(::unlink(temporary.c_str()));
        throw;
    }
    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        const auto error = errno;
        static_cast<void>(::unlink(temporary.c_str()));
        throw std::system_error(error, std::generic_category(),
                                "cannot atomically replace epoch state");
    }
    const auto parent = path.parent_path().empty() ? std::filesystem::path{"."}
                                                   : path.parent_path();
    const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot open epoch state directory for durability sync");
    }
    if (::fsync(directory) != 0) {
        const auto error = errno;
        static_cast<void>(::close(directory));
        throw std::system_error(error, std::generic_category(),
                                "cannot fsync epoch state directory");
    }
    if (::close(directory) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "cannot close epoch state directory");
    }
}

#endif

}  // namespace

FileEpochReservationStore::FileEpochReservationStore(
    std::filesystem::path state_file,
    std::uint64_t maximum_epoch)
    : state_file_(std::move(state_file)), maximum_epoch_(maximum_epoch) {
    if (state_file_.empty() || maximum_epoch_ == 0 || maximum_epoch_ > kMaxStreamEpoch) {
        throw std::invalid_argument("epoch state path/maximum is invalid");
    }
    lock_file_ = state_file_;
    lock_file_ += ".lock";
}

std::uint64_t FileEpochReservationStore::reserve_next() {
    std::scoped_lock process_lock(process_mutex_);
    const auto parent = state_file_.parent_path();
    if (!parent.empty()) {
        std::error_code error;
        std::filesystem::create_directories(parent, error);
        if (error) {
            throw std::system_error(error, "cannot create epoch state directory");
        }
    }
    InterprocessLock interprocess_lock(lock_file_);
    const auto current = parse_epoch_file(state_file_);
    if (current >= maximum_epoch_) {
        throw std::overflow_error("stream epoch space is exhausted");
    }
    const auto next = current + 1;
    persist_atomically(state_file_, std::to_string(next) + "\n");
    return next;
}

}  // namespace vf::host::infrastructure
