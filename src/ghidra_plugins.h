#pragma once
#include "ghidra_detect.h"
#include <string>

struct PluginInfo {
    std::string name;
    std::string description;
    std::string zip_filename;    // filename in plugins/ dir
    std::string download_url;    // fallback: download from GitHub
    std::string version;
};

// Built-in plugins
extern const PluginInfo PLUGIN_EMOTIONENGINE;
extern const PluginInfo PLUGIN_XEXLOADER;

bool check_plugin_installed(const GhidraInfo& ghidra, const PluginInfo& plugin);
bool install_plugin(const GhidraInfo& ghidra, const PluginInfo& plugin);
bool install_plugin_interactive(const GhidraInfo& ghidra, const PluginInfo& plugin);
bool check_and_install_all(const GhidraInfo& ghidra);
