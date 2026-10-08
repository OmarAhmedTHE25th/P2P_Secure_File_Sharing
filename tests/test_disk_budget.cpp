#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <utility>
#include "disk_budget.hpp"

namespace {
constexpr uint64_t MB = 1000 * 1000;
std::shared_ptr<DiskBudget> make_budget(uint64_t min_free = 0) {
    return std::make_shared<DiskBudget>(min_free);
}
}

TEST(DiskBudget, SingleUploadThatFitsIsAccepted) {
    auto budget = make_budget();
    EXPECT_TRUE(budget->try_reserve(800 * MB, 1000 * MB).has_value());
}

TEST(DiskBudget, SingleUploadBiggerThanTheFreeSpaceIsRefused) {
    auto budget = make_budget();
    EXPECT_FALSE(budget->try_reserve(1001 * MB, 1000 * MB).has_value());
    EXPECT_EQ(budget->promised(), 0u);
}

TEST(DiskBudget, UploadExactlyTheSizeOfTheFreeSpaceIsAccepted) {
    auto budget = make_budget();
    EXPECT_TRUE(budget->try_reserve(1000 * MB, 1000 * MB).has_value());
}

// The bug this class exists to fix: each upload alone fits, both together do not
TEST(DiskBudget, TwoUploadsThatFitSeparatelyButNotTogetherAreNotBothAccepted) {
    auto budget = make_budget();
    auto first = budget->try_reserve(600 * MB, 1000 * MB);
    ASSERT_TRUE(first.has_value());
    EXPECT_FALSE(budget->try_reserve(600 * MB, 1000 * MB).has_value());
    EXPECT_TRUE(budget->try_reserve(400 * MB, 1000 * MB).has_value());   // but this one still fits
}

TEST(DiskBudget, FinishingAnUploadFreesItsPromise) {
    auto budget = make_budget();
    {
        auto first = budget->try_reserve(600 * MB, 1000 * MB);
        ASSERT_TRUE(first.has_value());
        EXPECT_EQ(budget->promised(), 600 * MB);
    }   // first goes out of scope here: the upload ended
    EXPECT_EQ(budget->promised(), 0u);
    EXPECT_TRUE(budget->try_reserve(600 * MB, 1000 * MB).has_value());
}

TEST(DiskBudget, BytesAlreadyWrittenStopCountingAsPromised) {
    auto budget = make_budget();
    auto first = budget->try_reserve(600 * MB, 1000 * MB);
    ASSERT_TRUE(first.has_value());
    first->written(500 * MB);                       // the disk now really has 500 MB less free
    EXPECT_EQ(budget->promised(), 100 * MB);
    EXPECT_EQ(first->remaining(), 100 * MB);
    // real free space is now 500 MB; 100 MB are still promised, so 400 MB are left to hand out
    EXPECT_TRUE(budget->try_reserve(400 * MB, 500 * MB).has_value());
}

TEST(DiskBudget, WritingMoreThanPromisedNeverGoesNegative) {
    auto budget = make_budget();
    auto reservation = budget->try_reserve(100 * MB, 1000 * MB);
    ASSERT_TRUE(reservation.has_value());
    reservation->written(5000 * MB);
    EXPECT_EQ(reservation->remaining(), 0u);
    EXPECT_EQ(budget->promised(), 0u);
}

TEST(DiskBudget, MinimumFreeSpaceIsAlwaysLeftOver) {
    auto budget = make_budget(100 * MB);
    EXPECT_FALSE(budget->try_reserve(950 * MB, 1000 * MB).has_value());   // would leave only 50 MB
    EXPECT_TRUE(budget->try_reserve(900 * MB, 1000 * MB).has_value());    // leaves exactly 100 MB
}

TEST(DiskBudget, MinimumFreeSpaceCountsPromisesOfOtherUploadsToo) {
    auto budget = make_budget(100 * MB);
    auto first = budget->try_reserve(500 * MB, 1000 * MB);
    ASSERT_TRUE(first.has_value());
    EXPECT_FALSE(budget->try_reserve(401 * MB, 1000 * MB).has_value());
    EXPECT_TRUE(budget->try_reserve(400 * MB, 1000 * MB).has_value());
}

TEST(DiskBudget, EmptyFileIsAlwaysAccepted) {
    auto budget = make_budget(100 * MB);
    EXPECT_TRUE(budget->try_reserve(0, 0).has_value());
}

TEST(DiskBudget, AbsurdSizesAreRefusedWithoutOverflow) {
    auto budget = make_budget(100 * MB);
    EXPECT_FALSE(budget->try_reserve(UINT64_MAX, 1000 * MB).has_value());
    EXPECT_FALSE(budget->try_reserve(UINT64_MAX, UINT64_MAX).has_value());
    auto first = budget->try_reserve(500 * MB, 1000 * MB);
    ASSERT_TRUE(first.has_value());
    EXPECT_FALSE(budget->try_reserve(UINT64_MAX - 10, UINT64_MAX).has_value());
    EXPECT_EQ(budget->promised(), 500 * MB);
}

TEST(DiskBudget, MovingAReservationDoesNotGiveItBackTwice) {
    auto budget = make_budget();
    auto first = budget->try_reserve(300 * MB, 1000 * MB);
    ASSERT_TRUE(first.has_value());
    DiskBudget::Reservation kept = std::move(*first);
    first.reset();
    EXPECT_EQ(budget->promised(), 300 * MB);   // still held by `kept`
    DiskBudget::Reservation other;
    other = std::move(kept);
    EXPECT_EQ(budget->promised(), 300 * MB);
    other = DiskBudget::Reservation();         // replaced by an empty one: released exactly once
    EXPECT_EQ(budget->promised(), 0u);
}

TEST(DiskBudget, ReservationKeepsTheBudgetAliveAfterTheOwnerIsGone) {
    DiskBudget::Reservation reservation;
    {
        auto budget = make_budget();
        auto result = budget->try_reserve(10 * MB, 100 * MB);
        ASSERT_TRUE(result.has_value());
        reservation = std::move(*result);
    }   // the budget's last outside owner is gone, the reservation must not dangle
    reservation.written(5 * MB);
    EXPECT_EQ(reservation.remaining(), 5 * MB);
}
