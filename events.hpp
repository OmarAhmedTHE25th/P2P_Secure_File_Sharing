#pragma once
// A bundle of optional callbacks the network code can call to report what is happening.
// Every one is optional: an empty std::function simply means "nobody is listening",
// so the CLI and the tests keep working exactly as before.

#include <cstdint>
#include <functional>
#include <string>

struct TransferEvents {
    // one human-readable line, already prefixed with [CLIENT] or [SERVER]
    std::function<void(const std::string& line)> on_log;
    // bytes done so far and the total (total can be 0 for an empty file)
    std::function<void(uint64_t done, uint64_t total)> on_progress;
    // fired exactly once per transfer, whatever way it ended
    std::function<void(bool success, const std::string& message)> on_finished;
    // the other side proved who it is
    std::function<void(const std::string& name, const std::string& fingerprint)> on_peer;
};