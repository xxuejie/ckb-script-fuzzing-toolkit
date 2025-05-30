#ifndef CKB_FUZZING_SYSCALLS_ARGV_BUILDER_H_
#define CKB_FUZZING_SYSCALLS_ARGV_BUILDER_H_

#include <vector>

class ArgvBuilder {
  char* buffer_;
  size_t length_;
  std::vector<size_t> offsets_;

 public:
  ArgvBuilder() : buffer_(NULL), length_(0) {}

  ~ArgvBuilder() {
    if (buffer_ != NULL) {
      free(buffer_);
    }
  }

  void push(const char* arg) {
    // Each argv is aligned by 8 bytes.
    size_t current_len = strlen(arg) + 1;
    size_t rounded_len = ((current_len + 7) / 8) * 8;

    buffer_ = (char*)realloc(buffer_, length_ + rounded_len);
    memcpy(&buffer_[length_], arg, current_len);
    if (rounded_len > current_len) {
      memset(&buffer_[length_ + current_len], 0, rounded_len - current_len);
    }

    offsets_.push_back(length_);
    length_ += rounded_len;
  }

  int argc() const { return offsets_.size(); }

  char** argv() const {
    // At the start, each argv item requires a pointer, plus a NULL pointer
    size_t pointers_size = (offsets_.size() + 1) * sizeof(size_t);
    char* flattened_argv = (char*)malloc(pointers_size + length_);
    if (length_ > 0) {
      memcpy(&flattened_argv[pointers_size], buffer_, length_);
    }
    for (size_t i = 0; i < offsets_.size(); i++) {
      ((size_t*)flattened_argv)[i] =
          (size_t)(&flattened_argv[pointers_size + offsets_[i]]);
    }
    ((size_t*)flattened_argv)[offsets_.size()] = 0;
    return (char**)flattened_argv;
  }
};

#endif  // CKB_FUZZING_SYSCALLS_ARGV_BUILDER_H_
