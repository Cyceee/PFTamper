#include <windows.h>
#include <shellapi.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "shell32.lib")

namespace cfg {
    constexpr DWORD  kKeepEntries = 11;
    constexpr DWORD  kFmtHuff = 0x0004;
    constexpr DWORD  kEngMax = 0x0100;
    constexpr DWORD  kSccaSig = 0x41434353;
    constexpr DWORD  kHdrSz = 8;
    constexpr DWORD  kTcStride = 12;

    // Oq voce vai limpar
    inline std::wstring TargetName() {

        std::wstring s;      
        s += L"XVIDEOS";
        s += L".EXE-XXXXXXX"; 
        return s;
    }
}

using FnGetWSS = NTSTATUS(WINAPI*)(USHORT, PULONG, PULONG);
using FnDecomp = NTSTATUS(WINAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
using FnComp = NTSTATUS(WINAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);

#pragma pack(push, 1)
struct CompBlock {
    DWORD sig;
    DWORD uncSz;
};

struct TraceHeader {
    DWORD version;
    DWORD signature;
    DWORD unk0;
    DWORD fileSize;
    WCHAR exeName[30];
    DWORD hash;
    DWORD unk1;
    DWORD fmOff;
    DWORD fmCnt;
    DWORD tcOff;
    DWORD tcCnt;
    DWORD fnOff;
    DWORD fnSz;
    DWORD viOff;
    DWORD viCnt;
    DWORD viSz;
};

struct AccessRecord {
    DWORD startTime;
    DWORD duration;
    DWORD avgDuration;
    DWORD fnStrOff;
    DWORD fnStrSz;
    DWORD flags;
    BYTE  ntfsRef[8];
};
#pragma pack(pop)

static_assert(sizeof(AccessRecord) == 32, "AccessRecord deve ter 32 bytes");

static bool IsElevated() {
    BOOL isAdmin = FALSE;
    PSID adminSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminSid))
    {
        CheckTokenMembership(nullptr, adminSid, &isAdmin);
        FreeSid(adminSid);
    }
    return isAdmin == TRUE;
}

static void RelaunchElevated() {
    WCHAR exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    SHELLEXECUTEINFOW cursed{ sizeof(cursed) };
    cursed.lpVerb = L"runas";
    cursed.lpFile = exe;
    cursed.nShow = SW_NORMAL;
    ShellExecuteExW(&cursed);
}

static std::wstring WStrAt(const BYTE* buf, DWORD off, DWORD bufSz) {
    std::wstring out;
    if (off >= bufSz) return out;
    const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buf + off);
    DWORD maxCh = (bufSz - off) / sizeof(wchar_t);
    out.reserve(64);
    for (DWORD i = 0; i < maxCh && ptr[i]; ++i)
        out += ptr[i];
    return out;
}

static std::wstring Basename(const std::wstring& path) {
    auto p = path.rfind(L'\\');
    return (p == std::wstring::npos) ? path : path.substr(p + 1);
}

static bool InBounds(DWORD off, DWORD sz, DWORD total) {
    return off < total && (total - off) >= sz;
}

struct KernelOps {
    FnGetWSS getWss = nullptr;
    FnDecomp decomp = nullptr;
    FnComp   comp = nullptr;

    bool Load() {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (!nt) return false;
        getWss = reinterpret_cast<FnGetWSS>(GetProcAddress(nt, "RtlGetCompressionWorkSpaceSize"));
        decomp = reinterpret_cast<FnDecomp>(GetProcAddress(nt, "RtlDecompressBufferEx"));
        comp = reinterpret_cast<FnComp>  (GetProcAddress(nt, "RtlCompressBuffer"));
        return getWss && decomp && comp;
    }

   
    std::vector<BYTE> AllocWS(USHORT fmt) const {
        ULONG ws = 0, fws = 0;
        getWss(fmt, &ws, &fws);
        ULONG sz = (ws > fws ? ws : fws);
        if (!sz) sz = 0x10000;
        return std::vector<BYTE>(sz);
    }
};

struct ScopedHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit ScopedHandle(HANDLE hh) : h(hh) {}
    ~ScopedHandle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    operator HANDLE() const { return h; }
    bool Valid() const { return h != INVALID_HANDLE_VALUE; }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
};

static bool ProcessPrefetch(const std::wstring& path, const KernelOps& ntc) {

    ScopedHandle hf(CreateFileW(path.c_str(),
        GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hf.Valid()) return false;

    //  timestamps original
    FILETIME ftC{}, ftA{}, ftW{};
    GetFileTime(hf, &ftC, &ftA, &ftW);

    DWORD fsz = GetFileSize(hf, nullptr);
    if (fsz < cfg::kHdrSz) return false;

    std::vector<BYTE> raw(fsz);
    DWORD rd = 0;
    if (!ReadFile(hf, raw.data(), fsz, &rd, nullptr) || rd != fsz)
        return false;

   
    auto* mam = reinterpret_cast<CompBlock*>(raw.data());
    USHORT fmt = static_cast<USHORT>((mam->sig >> 24) & 0xFF);
    if (!fmt) fmt = cfg::kFmtHuff;

    
    auto ws = ntc.AllocWS(fmt);
    std::vector<BYTE> unc(mam->uncSz);
    ULONG uncSz = 0;

    NTSTATUS st = ntc.decomp(fmt,
        unc.data(), static_cast<ULONG>(unc.size()),
        raw.data() + cfg::kHdrSz, fsz - cfg::kHdrSz,
        &uncSz, ws.data());
    if (st) return false;

    unc.resize(uncSz);

    
    if (uncSz < sizeof(TraceHeader)) return false;
    auto* scca = reinterpret_cast<TraceHeader*>(unc.data());
    if (scca->signature != cfg::kSccaSig) return false;


    DWORD fmBytes = scca->fmCnt * sizeof(AccessRecord);
    if (!InBounds(scca->fmOff, fmBytes, uncSz)) return false;

    auto* fm = reinterpret_cast<AccessRecord*>(unc.data() + scca->fmOff);

   
    struct Entry {
        AccessRecord  metric;
        std::wstring fullPath;
        bool keep;
    };

    std::vector<Entry> entries(scca->fmCnt);
    DWORD nRemove = 0;

    for (DWORD i = 0; i < scca->fmCnt; ++i) {
        entries[i].metric = fm[i];
        entries[i].keep = (i < cfg::kKeepEntries);

        DWORD absOff = scca->fnOff + fm[i].fnStrOff;
        entries[i].fullPath = WStrAt(unc.data(), absOff, uncSz);

       
        if (entries[i].fullPath.empty())
            entries[i].fullPath = WStrAt(unc.data(), fm[i].fnStrOff, uncSz);

        if (!entries[i].keep) ++nRemove;
    }

    if (!nRemove) return true;   

   
    for (auto& e : entries) {
        if (e.keep || e.fullPath.empty()) continue;
        DWORD absOff = scca->fnOff + e.metric.fnStrOff;
        DWORD byteLen = static_cast<DWORD>((e.fullPath.size() + 1) * sizeof(wchar_t));
        if (InBounds(absOff, byteLen, uncSz))
            SecureZeroMemory(unc.data() + absOff, byteLen);
    }

   
    for (DWORD i = cfg::kKeepEntries; i < scca->fmCnt; ++i)
        SecureZeroMemory(&fm[i], sizeof(AccessRecord));

    scca->fmCnt = cfg::kKeepEntries;

   
    if (scca->tcCnt > 0) {
        DWORD tcBytes = scca->tcCnt * cfg::kTcStride;
        if (InBounds(scca->tcOff, tcBytes, uncSz))
            SecureZeroMemory(unc.data() + scca->tcOff, tcBytes);
        scca->tcCnt = 0;
    }

   
    USHORT cFmt = fmt | static_cast<USHORT>(cfg::kEngMax);
    auto ws2 = ntc.AllocWS(cFmt);
    std::vector<BYTE> comp(unc.size() * 2);
    ULONG compSz = 0;

    st = ntc.comp(cFmt,
        unc.data(), uncSz,
        comp.data(), static_cast<ULONG>(comp.size()),
        4096, &compSz, ws2.data());
    if (st) return false;

   
    SetFilePointer(hf, 0, nullptr, FILE_BEGIN);
    CompBlock newMam{ mam->sig, uncSz };
    DWORD wr = 0;
    WriteFile(hf, &newMam, sizeof(CompBlock), &wr, nullptr);
    WriteFile(hf, comp.data(), compSz, &wr, nullptr);
    SetEndOfFile(hf);
    SetFileTime(hf, &ftC, &ftA, &ftW);   // restaura timestamps

    return true;
}



int main() {
    if (!IsElevated()) {
        RelaunchElevated();
        return 0;
    }

    
    PVOID redir = nullptr;
    Wow64DisableWow64FsRedirection(&redir);

    std::wstring pfPath = L"C:\\Windows\\Prefetch\\"
        + cfg::TargetName()
        + L".pf";

    int ret = 1;

    if (GetFileAttributesW(pfPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        KernelOps ntc;
        if (ntc.Load())
            ret = ProcessPrefetch(pfPath, ntc) ? 0 : 1;
    }

    Wow64RevertWow64FsRedirection(redir);
    return ret;
}
