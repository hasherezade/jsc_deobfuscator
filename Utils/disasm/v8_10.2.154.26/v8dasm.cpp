// Based on code from: https://github.com/j4k0xb/View8/
#include <fstream>
#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstddef>

#include "include/v8.h"
#include "include/libplatform/libplatform.h"

using namespace v8;
using namespace std;

//---

static Isolate* isolate = nullptr;

// Compatibility with v8 versions that have different ScriptOrigin constructors
template <typename... Args>
ScriptOrigin CreateScriptOrigin(Args&&... args) {
  if constexpr (std::is_constructible_v<ScriptOrigin, Isolate*, Local<String>>) {
      return ScriptOrigin(isolate, std::forward<Args>(args)...);
  } else {
      return ScriptOrigin(std::forward<Args>(args)...);
  }
}

// V8 stores the original source length in the source-hash header word (offset 8)
// for the common case (default origin, no module/wrapped flags) — exactly what
// bytenode and this packer produce. Reproducing a dummy source of that length
// satisfies V8's source-hash check even on a stock, unpatched V8, and keeps the
// `rejected` flag meaningful instead of firing on every file.
static bool readSourceLength(const uint8_t* buf, size_t len, uint32_t& out) {
  if (len < 12) return false;
  std::memcpy(&out, buf + 2 * sizeof(uint32_t), sizeof(out));  // offset 8
  return true;
}

// A V8 code cache (SerializedCodeData) starts with a 6-word, 24-byte header:
//   [0] magic  [1] version hash  [2] source hash
//   [3] flag hash  [4] payload length  [5] checksum
// The magic is 0xC0DE0000 ^ external_reference_count. The count is ~10^3, so
// the top 16 bits are always 0xC0DE for *any* V8 build; only the low bits move.
// A cheap magic + length gate rejects encrypted/packed blobs and truncated
// files before V8 sees them. memcpy avoids alignment / aliasing concerns.
static bool looksLikeCodeCache(const uint8_t* buf, size_t len) {
  constexpr size_t kHeaderSize = 6 * sizeof(uint32_t);  // 24
  if (len < kHeaderSize) return false;

  uint32_t magic, payload_length;
  std::memcpy(&magic, buf, sizeof(magic));
  std::memcpy(&payload_length, buf + 4 * sizeof(uint32_t), sizeof(payload_length));

  if ((magic >> 16) != 0xC0DE) return false;             // not a V8 cache at all
  if (payload_length > len - kHeaderSize) return false;  // truncated / not a cache
  return true;
}

static void loadBytecode(uint8_t* bytecodeBuffer, int length) {
  if (length < 0 || !looksLikeCodeCache(bytecodeBuffer, static_cast<size_t>(length))) {
    std::cerr << "skip: not a V8 code cache (bad magic or payload length)\n";
    return;
  }
  // Load code into code cache.
  ScriptCompiler::CachedData* cached_data = new ScriptCompiler::CachedData(bytecodeBuffer, length);

  // Create dummy source.
  ScriptOrigin origin = CreateScriptOrigin(String::NewFromUtf8Literal(isolate, "code.jsc"));

  // Size the dummy source to the length recorded in the cache so V8's source
  // hash matches. Cap it so a crafted-but-well-formed header can't make us
  // allocate gigabytes.
  uint32_t srcLen = 0;
  readSourceLength(bytecodeBuffer, static_cast<size_t>(length), srcLen);
  constexpr uint32_t kMaxDummySource = 256u * 1024 * 1024;  // 256 MiB
  if (srcLen > kMaxDummySource) {
    std::cerr << "skip: implausible source length in header (" << srcLen << ")\n";
    return;
  }
  std::string dummy(srcLen, '\0');
  Local<String> dummySource = String::NewFromUtf8(isolate, dummy.data(), 
  	NewStringType::kNormal, 
  	static_cast<int>(dummy.size())).ToLocalChecked();

  ScriptCompiler::Source source(dummySource, origin, cached_data);

  // Compile code from code cache to print disassembly.
  MaybeLocal<UnboundScript> script = ScriptCompiler::CompileUnboundScript(isolate, &source, ScriptCompiler::kConsumeCodeCache);

  // After consuming, V8 marks the cache as rejected if it was unusable
  // (version mismatch, flags mismatch, corrupted data, bad checksum).
  if (source.GetCachedData()->rejected) {
    std::cerr << "[!] Bytecode rejected by V8 " << V8::GetVersion()
              << " - the .jsc was likely produced by a different V8 version "
              << "(or the data is corrupted). Disassembly above (if any) is "
              << "from the dummy source, not your input." << std::endl;
  } else if (script.IsEmpty()) {
    std::cerr << "[!] Compilation failed despite cache being accepted." << std::endl;
  }
}

static bool readAllBytes(const std::string& file, std::vector<std::byte>& buffer) {
  std::ifstream infile(file, ios::binary | ios::in);
  if (!infile) {                                   // missing / unreadable
    std::cerr << "error: cannot open " << file << "\n";
    return false;
  }
  infile.seekg(0, infile.end);
  std::streamoff length = infile.tellg();          // signed, so -1 is visible
  if (length <= 0) return false;                   // empty, or tellg failed
  infile.seekg(0, infile.beg);
  buffer.resize(static_cast<size_t>(length));
  infile.read(reinterpret_cast<char*>(buffer.data()), length);
  infile.close();
  return true;
}

int main(int argc, char* argv[])
{
  if (argc < 2) {
    std::cout << "V8-Dasm (built with V8 " << V8::GetVersion() << ")\n"
      << "Args <input file>"
      << std::endl;
    return 0;
  }

  V8::SetFlagsFromString("--no-lazy --no-flush-bytecode");

  V8::InitializeICU();
  std::unique_ptr<Platform> platform = platform::NewDefaultPlatform();
  V8::InitializePlatform(platform.get());
  V8::Initialize();

  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      ArrayBuffer::Allocator::NewDefaultAllocator();

  isolate = Isolate::New(create_params);
  Isolate::Scope isolate_scope(isolate);
  HandleScope handle_scope(isolate);
  Local<v8::Context> context = Context::New(isolate);
  Context::Scope context_scope(context);

  std::vector<std::byte> data;
  if (!readAllBytes(argv[1], data)) return 1;
  loadBytecode((uint8_t*)data.data(), data.size());
}
