// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#pragma once
#include <fstream>
#include <stdexcept>
#include <string>
namespace pail_pep_gate {
inline std::string NewReportIdentity(){unsigned char b[16];std::ifstream f("/dev/urandom",std::ios::binary);if(!f.read(reinterpret_cast<char*>(b),sizeof(b)))throw std::runtime_error("report identity entropy unavailable");std::string out;const char*h="0123456789abcdef";for(unsigned char c:b){out+=h[c>>4];out+=h[c&15];}return out;}
}
