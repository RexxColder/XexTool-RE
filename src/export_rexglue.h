#pragma once
#include <string>

std::string export_rexglue_toml(const std::string& db_path,
                                 const std::string& project_name,
                                 const std::string& file_path,
                                 const std::string& out_directory,
                                 bool all_functions);
