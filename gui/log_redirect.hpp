#pragma once
#include <functional>
#include <iostream>
#include <mutex>
#include <streambuf>
#include <string>

// Sits behind std::cout / std::cerr. Every finished line goes to on_line,
// and everything is still passed through to the original terminal buffer.
class LineForwardBuf : public std::streambuf {
public:
    LineForwardBuf(std::ostream& stream, std::function<void(const std::string&)> on_line)
        : stream_(stream), old_(stream.rdbuf(this)), on_line_(std::move(on_line)) {}
    ~LineForwardBuf() override { stream_.rdbuf(old_); }

protected:
    int_type overflow(int_type ch) override {
        if (traits_type::eq_int_type(ch, traits_type::eof())) return traits_type::not_eof(ch);
        std::lock_guard<std::mutex> lock(mutex_);
        old_->sputc(traits_type::to_char_type(ch));
        if (ch == '\n' || ch == '\r') {
            // skip the live "Progress: [=====   ]" lines, they would spam the log
            if (!line_.empty() && line_.find("Progress: [") == std::string::npos) on_line_(line_);
            line_.clear();
        } else {
            line_.push_back(traits_type::to_char_type(ch));
        }
        return ch;
    }
    int sync() override { return old_->pubsync(); }

private:
    std::ostream& stream_;
    std::streambuf* old_;
    std::function<void(const std::string&)> on_line_;
    std::string line_;
    std::mutex mutex_;
};