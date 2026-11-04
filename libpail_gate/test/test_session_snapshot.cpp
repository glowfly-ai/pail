// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#include "pail_gate/gate_session.hpp"
#include <cstdio>
#include <fstream>
#include <unistd.h>

int main() {
  using namespace pail_pep_gate;
  char path[] = "/tmp/pail-snapshot-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) return 2;
  close(fd);
  SessionConfig cfg;
  cfg.skills_file = path;
  cfg.robot_class = "diff_drive_amr";
  SkillRegistryView captured;
  captured.sha256_hex = std::string(64, 'a');
  captured.robot_class = cfg.robot_class;
  // The preflight snapshot must win over a subsequently changed disk file.
  std::ofstream(path) << "not the preflight registry";
  GateSession session(cfg, SessionPolicy{}, Keyring{}, captured);
  captured.sha256_hex = std::string(64, 'b');
  unlink(path);
  if (session.loaded_skills_digest() != std::string(64, 'a')) return 1;
  std::puts("PASS: session owns the supplied snapshot, not disk/caller mutations");
  return 0;
}
