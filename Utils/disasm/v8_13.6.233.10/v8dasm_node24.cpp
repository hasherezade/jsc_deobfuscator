// Based on code from: https://github.com/j4k0xb/View8/
// Reworked for Node.js v24.x / V8 13.x code-cache disassembly.
//
// Important design point: create the V8 isolate from Node's built-in startup
// snapshot. This keeps code-cache validation tied to the same snapshot/runtime
// environment as the producing Node build, while still exposing a standalone
// disassembler-style CLI.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "node.h"
#include "uv.h"
#include "v8.h"

using namespace v8;

static Isolate* isolate = nullptr;

// Compatibility helper retained from the original View8 disassembler.
template <typename... Args>
ScriptOrigin CreateScriptOrigin(Args&&... args) {
  if constexpr (std::is_constructible_v<ScriptOrigin, Isolate*, Local<String>>) {
    return ScriptOrigin(isolate, std::forward<Args>(args)...);
  } else {
    return ScriptOrigin(std::forward<Args>(args)...);
  }
}

static uint32_t readU32(const uint8_t* buf, size_t off) {
  uint32_t value = 0;
  std::memcpy(&value, buf + off, sizeof(value));
  return value;
}

static size_t alignUp(size_t value, size_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

// V8 stores the source hash in header word [2] (offset 8). For ordinary
// scripts the low 29 bits contain the source length; upper bits encode source
// properties (wrapped/module flags). JSCeal uses an ordinary script, but the
// mask keeps this compatible with the V8 SourceHash layout.
static bool readSourceLength(const uint8_t* buf, size_t len, uint32_t& out) {
  if (len < 12) return false;
  const uint32_t source_hash = readU32(buf, 2 * sizeof(uint32_t));
  out = source_hash & 0x1fffffffu;
  return true;
}

enum class CacheHeaderLayout {
  kLegacy6Word,
  kModern7Word,
};

struct CacheHeaderInfo {
  CacheHeaderLayout layout;
  size_t header_size;
  uint32_t magic;
  uint32_t version_hash;
  uint32_t source_hash;
  uint32_t flag_hash;
  uint32_t ro_snapshot_checksum;
  uint32_t payload_length;
  uint32_t checksum;
};

// V8 code-cache headers changed between the older View8 target and newer V8.
//
// Legacy layout:
//   [0] magic [1] version [2] source [3] flags [4] payload_len [5] checksum
//
// Modern layout (V8 13.x / Node 24):
//   [0] magic [1] version [2] source [3] flags [4] RO snapshot checksum
//   [5] payload_len [6] checksum [padding to pointer alignment]
//
// We identify the layout from the field that gives a plausible payload length,
// preferring an exact total-size match.
static bool parseCodeCacheHeader(const uint8_t* buf,
                                 size_t len,
                                 CacheHeaderInfo& out) {
  constexpr size_t kLegacyRawHeader = 6 * sizeof(uint32_t);  // 24
  constexpr size_t kModernRawHeader = 7 * sizeof(uint32_t);  // 28
  const size_t kLegacyHeader = alignUp(kLegacyRawHeader, sizeof(void*));
  const size_t kModernHeader = alignUp(kModernRawHeader, sizeof(void*));

  if (len < kLegacyHeader) return false;

  const uint32_t magic = readU32(buf, 0);
  if ((magic >> 16) != 0xC0DE) return false;

  struct Candidate {
    bool valid = false;
    bool exact = false;
    CacheHeaderInfo info{};
  };

  Candidate legacy;
  {
    const uint32_t payload_length = readU32(buf, 4 * sizeof(uint32_t));
    if (payload_length <= len - kLegacyHeader) {
      legacy.valid = true;
      legacy.exact = (kLegacyHeader + payload_length == len);
      legacy.info = {
          CacheHeaderLayout::kLegacy6Word,
          kLegacyHeader,
          magic,
          readU32(buf, 1 * sizeof(uint32_t)),
          readU32(buf, 2 * sizeof(uint32_t)),
          readU32(buf, 3 * sizeof(uint32_t)),
          0,
          payload_length,
          readU32(buf, 5 * sizeof(uint32_t)),
      };
    }
  }

  Candidate modern;
  if (len >= kModernHeader) {
    const uint32_t payload_length = readU32(buf, 5 * sizeof(uint32_t));
    if (payload_length <= len - kModernHeader) {
      modern.valid = true;
      modern.exact = (kModernHeader + payload_length == len);
      modern.info = {
          CacheHeaderLayout::kModern7Word,
          kModernHeader,
          magic,
          readU32(buf, 1 * sizeof(uint32_t)),
          readU32(buf, 2 * sizeof(uint32_t)),
          readU32(buf, 3 * sizeof(uint32_t)),
          readU32(buf, 4 * sizeof(uint32_t)),
          payload_length,
          readU32(buf, 6 * sizeof(uint32_t)),
      };
    }
  }

  if (modern.valid && modern.exact && !(legacy.valid && legacy.exact)) {
    out = modern.info;
    return true;
  }
  if (legacy.valid && legacy.exact && !(modern.valid && modern.exact)) {
    out = legacy.info;
    return true;
  }
  if (modern.valid && modern.exact) {
    out = modern.info;
    return true;
  }
  if (legacy.valid && !modern.valid) {
    out = legacy.info;
    return true;
  }
  if (modern.valid && !legacy.valid) {
    out = modern.info;
    return true;
  }

  return false;
}

static void printCacheHeaderInfo(const CacheHeaderInfo& info) {
  std::cerr << "[i] Runtime V8: " << V8::GetVersion() << "\n";
  std::cerr << "[i] Cache header: "
            << (info.layout == CacheHeaderLayout::kModern7Word
                    ? "modern 7-word"
                    : "legacy 6-word")
            << "\n";
  std::cerr << "    magic:                0x"
            << std::hex << std::setw(8) << std::setfill('0') << info.magic
            << "\n    version hash:         0x" << std::setw(8)
            << info.version_hash
            << "\n    source hash:          0x" << std::setw(8)
            << info.source_hash
            << "\n    flags hash:           0x" << std::setw(8)
            << info.flag_hash;

  if (info.layout == CacheHeaderLayout::kModern7Word) {
    std::cerr << "\n    RO snapshot checksum: 0x" << std::setw(8)
              << info.ro_snapshot_checksum;
  }

  std::cerr << std::dec
            << "\n    payload length:       " << info.payload_length
            << std::hex
            << "\n    payload checksum:     0x" << std::setw(8)
            << info.checksum
            << std::dec << "\n";
}

static bool loadBytecode(uint8_t* bytecodeBuffer, int length) {
  if (length < 0) {
    std::cerr << "[!] Invalid input length\n";
    return false;
  }

  CacheHeaderInfo header{};
  if (!parseCodeCacheHeader(
          bytecodeBuffer, static_cast<size_t>(length), header)) {
    std::cerr << "[!] Not a recognized V8 code cache "
                 "(bad magic/header/payload length)\n";
    return false;
  }

  printCacheHeaderInfo(header);

  uint32_t srcLen = 0;
  if (!readSourceLength(
          bytecodeBuffer, static_cast<size_t>(length), srcLen)) {
    std::cerr << "[!] Cannot read source length from cache header\n";
    return false;
  }

  constexpr uint32_t kMaxDummySource = 256u * 1024 * 1024;
  if (srcLen > kMaxDummySource) {
    std::cerr << "[!] Implausible source length in header ("
              << srcLen << ")\n";
    return false;
  }

  std::cerr << "[i] Dummy source length: " << srcLen << "\n";

  // The CachedData object does not own bytecodeBuffer with the default policy.
  auto* cached_data = new ScriptCompiler::CachedData(bytecodeBuffer, length);

  ScriptOrigin origin =
      CreateScriptOrigin(String::NewFromUtf8Literal(isolate, "code.jsc"));

  std::string dummy(srcLen, '\0');
  Local<String> dummySource =
      String::NewFromUtf8(isolate,
                          dummy.data(),
                          NewStringType::kNormal,
                          static_cast<int>(dummy.size()))
          .ToLocalChecked();

  ScriptCompiler::Source source(dummySource, origin, cached_data);

  // Our V8 patch prints the recovered SharedFunctionInfo tree from inside
  // CodeSerializer::Deserialize(). Nothing is executed here.
  MaybeLocal<UnboundScript> script = ScriptCompiler::CompileUnboundScript(
      isolate, &source, ScriptCompiler::kConsumeCodeCache);

  if (source.GetCachedData()->rejected) {
    std::cerr << "[!] Cache rejected by V8 " << V8::GetVersion() << "\n";
    return false;
  }

  if (script.IsEmpty()) {
    std::cerr << "[!] Compilation failed despite cache being accepted\n";
    return false;
  }

  std::cerr << "[+] Cache accepted; bytecode was not executed\n";
  return true;
}

static bool readAllBytes(const std::string& file,
                         std::vector<std::byte>& buffer) {
  std::ifstream infile(file, std::ios::binary | std::ios::in);
  if (!infile) {
    std::cerr << "[!] Cannot open input: " << file << "\n";
    return false;
  }

  infile.seekg(0, infile.end);
  const std::streamoff length = infile.tellg();
  if (length <= 0) {
    std::cerr << "[!] Input is empty or its size could not be determined\n";
    return false;
  }
  infile.seekg(0, infile.beg);

  buffer.resize(static_cast<size_t>(length));
  if (!infile.read(reinterpret_cast<char*>(buffer.data()), length)) {
    std::cerr << "[!] Failed to read complete input file\n";
    return false;
  }
  return true;
}

static void isolateFinished(void* data) {
  *static_cast<bool*>(data) = true;
}

int main(int argc, char* argv[]) {
  if (argc < 2 || argc > 3) {
    std::cerr << "V8-Dasm (Node snapshot build, V8 " << V8::GetVersion() << ")\n"
              << "Usage: " << argv[0]
              << " <raw-code-cache> [output.disasm.txt]\n";
    return argc < 2 ? 0 : 1;
  }

  const std::string input_path = argv[1];
  const std::string output_path = argc == 3 ? argv[2] : std::string();

  std::vector<std::byte> data;
  if (!readAllBytes(input_path, data)) return 1;
  if (data.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    std::cerr << "[!] Input file is too large\n";
    return 1;
  }

  // Let Node perform its normal one-time process/V8 initialization. This is
  // deliberately different from the old standalone-V8 disassembler.
  // NODE_OPTIONS is disabled so the analyst's environment cannot silently
  // alter V8 flags and invalidate cache matching.
  const std::vector<std::string> node_args{argv[0]};
  auto init = node::InitializeOncePerProcess(
      node_args, node::ProcessInitializationFlags::kDisableNodeOptionsEnv);

  for (const std::string& error : init->errors()) {
    std::cerr << "[node] " << error << "\n";
  }
  if (init->early_return()) {
    return init->exit_code();
  }

  node::MultiIsolatePlatform* platform = init->platform();
  if (platform == nullptr) {
    std::cerr << "[!] Node did not initialize its V8 platform\n";
    node::TearDownOncePerProcess();
    return 1;
  }

  // These are the flags used by the JSCeal loader before consuming cachedData.
  // Set them after Node/V8 process initialization, matching the real loader's
  // ordering rather than baking them into standalone-V8 startup.
  V8::SetFlagsFromString("--no-lazy --no-flush-bytecode");

  uv_loop_t loop;
  if (uv_loop_init(&loop) != 0) {
    std::cerr << "[!] uv_loop_init failed\n";
    node::TearDownOncePerProcess();
    return 1;
  }

  auto allocator = node::ArrayBufferAllocator::Create();
  auto snapshot = node::EmbedderSnapshotData::BuiltinSnapshotData();
  if (!snapshot) {
    std::cerr << "[!] This Node build has no usable built-in snapshot\n";
    uv_loop_close(&loop);
    node::TearDownOncePerProcess();
    return 1;
  }

  Isolate* node_isolate =
      node::NewIsolate(allocator.get(), &loop, platform, snapshot.get());
  if (node_isolate == nullptr) {
    std::cerr << "[!] node::NewIsolate() failed\n";
    uv_loop_close(&loop);
    node::TearDownOncePerProcess();
    return 1;
  }

  // NewIsolate(snapshot) performs the snapshot-aware isolate creation. Finish
  // installing Node's isolate callbacks, as Node does for snapshot-based
  // isolates internally.
  node::SetIsolateUpForNode(node_isolate);
  isolate = node_isolate;

  bool ok = false;
  std::ofstream output;
  std::streambuf* original_stdout = nullptr;

  {
    Locker locker(node_isolate);
    Isolate::Scope isolate_scope(node_isolate);
    HandleScope handle_scope(node_isolate);
    Local<Context> context = Context::New(node_isolate);
    Context::Scope context_scope(context);

    // If an output path is supplied, route std::cout directly to a binary
    // ofstream. This deliberately bypasses Windows PowerShell's native-output
    // transcoding (which can turn redirected output into UTF-16LE).
    if (!output_path.empty()) {
      output.open(output_path,
                  std::ios::out | std::ios::binary | std::ios::trunc);
      if (!output) {
        std::cerr << "[!] Cannot open output: " << output_path << "\n";
      } else {
        original_stdout = std::cout.rdbuf(output.rdbuf());
      }
    }

    if (output_path.empty() || output) {
      ok = loadBytecode(reinterpret_cast<uint8_t*>(data.data()),
                        static_cast<int>(data.size()));
      std::cout.flush();
    }

    if (original_stdout != nullptr) {
      std::cout.rdbuf(original_stdout);
      original_stdout = nullptr;
    }
    if (output.is_open()) output.close();
  }

  isolate = nullptr;

  // NewIsolate() registered the isolate with Node's MultiIsolatePlatform, so
  // dispose it through the platform rather than calling Isolate::Dispose().
  bool platform_finished = false;
  platform->AddIsolateFinishedCallback(
      node_isolate, isolateFinished, &platform_finished);
  platform->DisposeIsolate(node_isolate);
  while (!platform_finished) {
    uv_run(&loop, UV_RUN_ONCE);
  }

  const int close_result = uv_loop_close(&loop);
  if (close_result != 0) {
    std::cerr << "[!] uv_loop_close failed: " << close_result << "\n";
    ok = false;
  }

  node::TearDownOncePerProcess();

  if (ok && !output_path.empty()) {
    std::cerr << "[+] Disassembly written to: " << output_path << "\n";
  }
  return ok ? 0 : 2;
}
