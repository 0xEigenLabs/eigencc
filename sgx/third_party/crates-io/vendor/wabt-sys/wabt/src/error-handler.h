/*
 * Copyright 2017 WebAssembly Community Group participants
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WABT_ERROR_HANDLER_H_
#define WABT_ERROR_HANDLER_H_

#include <string>

#include "src/color.h"
#include "src/common.h"

namespace wabt {

class ErrorHandler {
 public:
  explicit ErrorHandler(Location::Type);

  virtual ~ErrorHandler() {}

  // Returns true if the error was handled.
  virtual bool OnError(ErrorLevel,
                       const Location&,
                       const std::string& error,
                       const std::string& source_line,
                       size_t source_line_column_offset) = 0;

  // Helper function for binary locations.
  bool OnError(ErrorLevel error_level,
               size_t offset,
               const std::string& error) {
    return OnError(error_level, Location(offset), error, std::string(), 0);
  }

  // OnError will be called with with source_line trimmed to this length.
  virtual size_t source_line_max_length() const = 0;

  std::string DefaultErrorMessage(ErrorLevel,
                                  const Color&,
                                  const Location&,
                                  const std::string& error,
                                  const std::string& source_line,
                                  size_t source_line_column_offset,
                                  int indent);

 protected:
  Location::Type location_type_;
};

class ErrorHandlerNop : public ErrorHandler {
 public:
  ErrorHandlerNop();

  bool OnError(ErrorLevel,
               const Location&,
               const std::string& error,
               const std::string& source_line,
               size_t source_line_column_offset) override {
    return false;
  }

  size_t source_line_max_length() const override { return 80; }
};

class ErrorHandlerFile : public ErrorHandler {
 public:
  enum class PrintHeader {
    Never,
    Once,
    Always,
  };

  explicit ErrorHandlerFile(Location::Type,
                            FILE* file = stderr,
                            const std::string& header = std::string(),
                            PrintHeader print_header = PrintHeader::Never,
                            size_t source_line_max_length = 80);

  bool OnError(ErrorLevel,
               const Location&,
               const std::string& error,
               const std::string& source_line,
               size_t source_line_column_offset) override;

  size_t source_line_max_length() const override {
    return source_line_max_length_;
  }

 private:
  void PrintErrorHeader();

  FILE* file_;
  std::string header_;
  PrintHeader print_header_;
  size_t source_line_max_length_;
  Color color_;
};

class ErrorHandlerBuffer : public ErrorHandler {
 public:
  explicit ErrorHandlerBuffer(Location::Type,
                              size_t source_line_max_length = 80);

  bool OnError(ErrorLevel,
               const Location&,
               const std::string& error,
               const std::string& source_line,
               size_t source_line_column_offset) override;

  size_t source_line_max_length() const override {
    return source_line_max_length_;
  }

  const std::string& buffer() const { return buffer_; }

 private:
  size_t source_line_max_length_;
  std::string buffer_;
  Color color_;
};

}  // namespace wabt

#endif  // WABT_ERROR_HANDLER_H_
