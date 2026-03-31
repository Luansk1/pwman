//
// Created by Luan Sousa Kleinmann on 12.02.26.
//

#ifndef PWMAN_MIGRATIONS_H
#define PWMAN_MIGRATIONS_H

#endif //PWMAN_MIGRATIONS_H
#pragma once

namespace migrations {

    static constexpr const char* kInitSql = R"sql(
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value BLOB
);

CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site TEXT NOT NULL,
  username TEXT NOT NULL,
  password_enc BLOB NOT NULL,
  notes TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_site ON entries(site);
CREATE INDEX IF NOT EXISTS idx_entries_username ON entries(username);
)sql";

} // namespace migrations
