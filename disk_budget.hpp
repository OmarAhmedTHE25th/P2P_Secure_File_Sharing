#pragma once
// Keeps simultaneous uploads from filling the disk together.
//
// The problem: if every upload only asks "is there room for ME?", two 600 MB uploads onto a disk
// with 1 GB free both get a yes, and then they run out of space together. Here every upload must
// first RESERVE its bytes from one shared budget, so the next upload sees what the earlier ones
// still need. No sockets and no disk access in here, so it can be unit tested with made-up numbers.

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

// Space that must always stay free, so a remote peer can never use up the very last bytes.
// Can be overridden at build time with -DP2P_MIN_FREE_BYTES=<bytes> (the tests do this).
#ifndef P2P_MIN_FREE_BYTES
#define P2P_MIN_FREE_BYTES (100ULL * 1024 * 1024)   // 100 MiB
#endif

// Must be created with std::make_shared (reservations hold a shared_ptr back to it).
class DiskBudget : public std::enable_shared_from_this<DiskBudget> {
public:
    static constexpr uint64_t DEFAULT_MIN_FREE_BYTES = P2P_MIN_FREE_BYTES;

    // A promise of space. Gives back whatever is still unused when it is destroyed,
    // so every way an upload can end (success, error, disconnect) releases it.
    class Reservation {
    public:
        Reservation() = default;                       // an empty one promises nothing
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        Reservation(Reservation&& other) noexcept
            : budget_(std::move(other.budget_)), remaining_(other.remaining_) { other.remaining_ = 0; }
        Reservation& operator=(Reservation&& other) noexcept {
            if (this != &other) {
                release();
                budget_ = std::move(other.budget_);
                remaining_ = other.remaining_;
                other.remaining_ = 0;
            }
            return *this;
        }
        ~Reservation() { release(); }

        // `bytes` of the promise are now really on the disk, so they stop counting as "still to come"
        void written(uint64_t bytes) {
            if (!budget_) return;
            const uint64_t done = std::min(bytes, remaining_);
            remaining_ -= done;
            budget_->give_back(done);
        }

        uint64_t remaining() const { return remaining_; }

    private:
        friend class DiskBudget;
        Reservation(std::shared_ptr<DiskBudget> budget, uint64_t bytes)
            : budget_(std::move(budget)), remaining_(bytes) {}
        void release() {
            if (budget_) budget_->give_back(remaining_);
            budget_.reset();
            remaining_ = 0;
        }

        std::shared_ptr<DiskBudget> budget_;
        uint64_t remaining_ = 0;
    };

    explicit DiskBudget(uint64_t min_free_bytes = DEFAULT_MIN_FREE_BYTES)
        : min_free_bytes_(min_free_bytes) {}

    // Try to promise `bytes` of space. `available_now` is how much free space the disk reports
    // right now. Succeeds only if, after this promise AND every earlier promise is kept, at least
    // min_free_bytes would still be free.
    std::optional<Reservation> try_reserve(uint64_t bytes, uint64_t available_now) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (bytes > 0) {   // an empty file needs no space
            if (bytes > available_now) return std::nullopt;
            const uint64_t after_this = available_now - bytes;
            if (promised_ > after_this) return std::nullopt;
            if (after_this - promised_ < min_free_bytes_) return std::nullopt;
        }
        promised_ += bytes;
        return Reservation(shared_from_this(), bytes);
    }

    // Total bytes currently promised to uploads in progress
    uint64_t promised() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return promised_;
    }

private:
    void give_back(uint64_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        promised_ -= std::min(bytes, promised_);
    }

    mutable std::mutex mutex_;
    uint64_t promised_ = 0;
    const uint64_t min_free_bytes_;
};
