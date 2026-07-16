#include <cstdint>
#include <map>
#include <set>
#include "export_rexglue.h"
#include "sqlite3.h"
#include <sstream>
#include <set>
#include <algorithm>

// REXCRT groups - functions with native ReXGlue runtime implementations
static const char* REXCRT_GROUPS[][30] = {
    {"Heap", "RtlAllocateHeap", "RtlFreeHeap", "RtlSizeHeap", "RtlReAllocateHeap", nullptr},
    {"File I/O", "CreateFileA", "ReadFile", "WriteFile", "SetFilePointer", "GetFileSize",
     "GetFileSizeEx", "SetEndOfFile", "FlushFileBuffers", "DeleteFileA", "CloseHandle",
     "FindFirstFileA", "FindNextFileA", "FindClose", "CreateDirectoryA", "MoveFileA",
     "SetFileAttributesA", "GetFileAttributesA", "GetFileAttributesExA", "SetFilePointerEx",
     "SetFileTime", "CompareFileTime", "CopyFileA", "RemoveDirectoryA", "GetFileType", nullptr},
    {"Memory", "memcpy", "memmove", "memset", "memchr", "XMemCpy", "XMemSet",
     "XMemSet128", "memset_vmx", "memcpy_s", "memmove_s",
     "RtlCopyMemory", "RtlMoveMemory", "RtlFillMemory", "RtlZeroMemory", "RtlImageNtHeader", nullptr},
    {"String", "strncmp", "strncpy", "strchr", "strstr", "strrchr", "strtok",
     "_stricmp", "strcpy_s", "lstrlenA", "lstrcpyA", "lstrcpynA",
     "lstrcatA", "lstrcmpiA", "RtlCompareString", "RtlInitAnsiString",
     "RtlInitUnicodeString", "RtlCopyString", "RtlUpperString", nullptr},
    {"Xbox Audio", "XAudioGetVoiceCategoryVolume", "XAudioGetVoiceCategoryVolumeChangeMask",
     "XAudioSetDuckerReleaseTime", "XAudioRenderDriverLock",
     "XAudioSubmitDigitalPacket", "XAudioUnregisterRenderDriverClient", nullptr},
    {"Xbox Input", "XInputdFFGetDeviceInfo", "XInputdGetDevicePid", "XInputdGetDeviceStats", nullptr},
    {"Xbox Kernel", "KeGetVidInfo", "KeInitializeEvent", "KeSetEvent", "KeResetEvent",
     "KeWaitForSingleObject", "KeWaitForMultipleObjects",
     "KeReleaseMutex", "KeReleaseSemaphore", "KeRaiseIrqlToDpcLevel",
     "KeLowerIrql", "KeAcquireSpinLockRaiseToSynch", "KeReleaseSpinLock",
     "HalFsbInterruptCount", "HalGetNotedArgonErrors",
     "HalNotifyBackgroundModeTransitionComplete",
     "IoReleaseCancelSpinLock", "ExExpansionCall",
     "PsCamDeviceRequest", "McaDeviceRequest", "DetroitDeviceRequest", nullptr},
    {"Xbox Crypto", "XeCryptSha", "XeCryptShaUpdate", "XeCryptShaFinal", "XeCryptSha384Final",
     "HvxKeysExecute", "HvxKeysDes2Cbc", "HvxKeysRsaPrvCrypt",
     "HvxEncryptedEncryptAllocation", "HvxEncryptedReleaseAllocation",
     "HvxStartupProcessors", "HvxFlushEntireTb", "HvxFlushSingleTb",
     "HvxGetSpecialPurposeRegister", "HvxSetSpecialPurposeRegister",
     "HvxLoadImageData", "HvxFinishImageLoad", "HvxZeroPage",
     "HvxSetRevocationList", "HvxHdcpCalculateBKsvSignature", nullptr},
    {"Xbox AV", "VdEnableHDCP", "VdEnumerateVideoModes", "VdRetrainEDRAM",
     "VdSendClosedCaptionData", "XGetVideoMode", "XGetAVPack",
     "XGetGameRegion", "XGetLanguage", nullptr},
    {"Xbox Kinect", "XamNuiCameraElevationGetAngle", "XamNuiCameraElevationSetAngle",
     "XamNuiCameraElevationStopMovement", "XamNuiCameraRememberFloor",
     "XamNuiCameraTiltGetStatus", "XamNuiCameraTiltReportStatus",
     "XamNuiCameraTiltSetCallback", "XamNuiGetDeviceSerialNumber",
     "XamNuiGetDeviceStatus", "XamNuiIdentityGetSessionId", "XUsbcamCreate", nullptr},
    {"Xbox Avatar", "XamAvatarInitialize", "XamAvatarShutdown",
     "XamAvatarGetAssets", "XamAvatarGetAssetsResultSize",
     "XamAvatarGenerateMipMaps", "XamAvatarLoadAnimation",
     "XamAvatarGetManifestLocalUser", "XamAvatarGetMetadataRandom",
     "XamAvatarManifestGetBodyType", nullptr},
    {"Xbox UI", "XamShowNuiSigninUI", "XamShowNuiControllerRequiredUI",
     "XamShowNuiFriendsUI", "XamShowNuiGamerCardUIForXUID",
     "XamShowNuiPartyUI", "XamShowNuiDeviceSelectorUI",
     "XamShowNuiMessageBoxUI", "XamShowNuiTroubleshooterUI", nullptr},
    {"Xbox Voice", "XamVoiceGetMicArrayAudioEx", "XamVoiceGetMicArrayUnderrunStatus",
     "XVoicedSendVPort", nullptr},
    {"Xbox System", "XexLoadExecutable", "XamXStudioRequest",
     "XamXlfsInitializeUploadQueue", "XamXlfsMountUploadQueueInstance",
     "XamXlfsUninitializeUploadQueue", "XamXlfsUnmountUploadQueueInstance",
     "XeKeysExSaveKeyVault", "XeKeysSaveSystemUpdate",
     "XeKeysSaveBootLoaderEx", "XeKeysLockSystemUpdate",
     "XMAIsInputBuffer1Valid", "XMASetInputBuffer0",
     "XamReadBiometricData", "XamWriteBiometricData",
     "XamUserNuiEnableBiometric", "XamUserNuiGetEnrollmentIndex",
     "XamUserNuiGetUserIndex", nullptr},
    {"Xbox Network", "NicGetOpt", "NicGetLinkState",
     "MtpdBeginTransaction", "MtpdEndTransaction",
     "MtpdCancelTransaction", "MtpdVerifyProximity", nullptr},
    {nullptr}
};

static std::set<std::string> build_known_names() {
    std::set<std::string> names;
    for (int g = 0; REXCRT_GROUPS[g][0]; ++g) {
        for (int i = 1; REXCRT_GROUPS[g][i]; ++i) {
            names.insert(REXCRT_GROUPS[g][i]);
        }
    }
    return names;
}

static bool has_sqlite() {
    return sqlite3_libversion() != nullptr;
}

std::string export_rexglue_toml(const std::string& db_path,
                                 const std::string& project_name,
                                 const std::string& file_path,
                                 const std::string& out_directory,
                                 bool all_functions) {
    if (!has_sqlite()) return "-- ERROR: SQLite not available";

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        return "-- ERROR: Cannot open database: " + db_path;
    }

    auto known = build_known_names();
    std::ostringstream toml;

    toml << "project_name = \"" << project_name << "\"\n";
    toml << "file_path = \"" << file_path << "\"\n";
    toml << "out_directory_path = \"" << out_directory << "\"\n\n";

    // Load functions from DB
    sqlite3_stmt* stmt = nullptr;
    std::string q = "SELECT address, name, size FROM functions ORDER BY address";
    if (sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        // Try to find end column
        bool has_end = false;
        {
            sqlite3_stmt* chk = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT end FROM functions LIMIT 1", -1, &chk, nullptr) == SQLITE_OK) {
                has_end = true;
                sqlite3_finalize(chk);
            }
        }

        toml << "[functions]\n";
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint64_t addr = sqlite3_column_int64(stmt, 0);
            const char* name = (const char*)sqlite3_column_text(stmt, 1);
            uint64_t size = sqlite3_column_int64(stmt, 2);

            if (!all_functions && name) {
                std::string n(name);
                if (n.find("sub_") == 0 || n.find("SUB_") == 0 ||
                    n.find("FUN_") == 0 || n.find("loc_") == 0) {
                    continue;
                }
            }

            char addr_hex[32], end_hex[32];
            snprintf(addr_hex, sizeof(addr_hex), "0x%08X", (uint32_t)addr);

            if (has_end) {
                // Get end from another query
                sqlite3_stmt* estmt = nullptr;
                std::string eq = "SELECT end FROM functions WHERE address = " + std::to_string(addr);
                if (sqlite3_prepare_v2(db, eq.c_str(), -1, &estmt, nullptr) == SQLITE_OK && sqlite3_step(estmt) == SQLITE_ROW) {
                    uint64_t end = sqlite3_column_int64(estmt, 0);
                    snprintf(end_hex, sizeof(end_hex), "0x%08X", (uint32_t)end);
                    toml << addr_hex << " = {";
                    if (name && name[0]) toml << "name = \"" << name << "\", ";
                    toml << "end = " << end_hex << "}\n";
                    sqlite3_finalize(estmt);
                } else {
                    snprintf(end_hex, sizeof(end_hex), "0x%08X", (uint32_t)(addr + size));
                    toml << addr_hex << " = {";
                    if (name && name[0]) toml << "name = \"" << name << "\", ";
                    toml << "end = " << end_hex << "}\n";
                    if (estmt) sqlite3_finalize(estmt);
                }
            } else {
                snprintf(end_hex, sizeof(end_hex), "0x%08X", (uint32_t)(addr + size));
                toml << addr_hex << " = {";
                if (name && name[0]) toml << "name = \"" << name << "\", ";
                toml << "end = " << end_hex << "}\n";
            }
        }
        sqlite3_finalize(stmt);
    }
    toml << "\n";

    // Load imports and cross-reference with known names
    std::map<std::string, uint64_t> rexcrt;
    q = "SELECT name, address FROM imports";
    if (sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* name = (const char*)sqlite3_column_text(stmt, 0);
            uint64_t addr = sqlite3_column_int64(stmt, 1);
            if (name && known.count(name)) {
                rexcrt[name] = addr;
            }
        }
        sqlite3_finalize(stmt);
    }

    // Also check named functions
    q = "SELECT name, address FROM functions WHERE is_named = 1";
    if (sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* name = (const char*)sqlite3_column_text(stmt, 0);
            uint64_t addr = sqlite3_column_int64(stmt, 1);
            if (name && known.count(name) && rexcrt.find(name) == rexcrt.end()) {
                rexcrt[name] = addr;
            }
        }
        sqlite3_finalize(stmt);
    }

    // Write [rexcrt] section
    if (!rexcrt.empty()) {
        toml << "[rexcrt]\n";
        for (auto& [name, addr] : rexcrt) {
            char hex[32];
            snprintf(hex, sizeof(hex), "0x%08X", (uint32_t)addr);
            toml << name << " = " << hex << "\n";
        }
        toml << "\n";
    }

    // Load switch tables
    q = "SELECT address, labels FROM switch_tables";
    if (sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint64_t addr = sqlite3_column_int64(stmt, 0);
            const char* labels_json = (const char*)sqlite3_column_text(stmt, 1);
            if (first) { toml << "[[switch_tables]]\n"; first = false; }
            char hex[32];
            snprintf(hex, sizeof(hex), "0x%08X", (uint32_t)addr);
            toml << "address = " << hex << "\n";
            toml << "register = 9\n";
            // Parse labels JSON array
            if (labels_json) {
                toml << "labels = [";
                std::string labels(labels_json);
                bool first_label = true;
                size_t pos = 0;
                while ((pos = labels.find("0x", pos)) != std::string::npos) {
                    if (!first_label) toml << ", ";
                    size_t end = labels.find_first_of(",]", pos);
                    toml << labels.substr(pos, end - pos);
                    pos = end + 1;
                    first_label = false;
                }
                toml << "]\n";
            }
            toml << "\n";
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return toml.str();
}
