// db.hpp
// Thin SQLite3 wrapper for CloudShare: users, files, and share_links tables.
#pragma once

#include <sqlite3.h>
#include <string>
#include <stdexcept>
#include <vector>
#include <optional>
#include <iostream>

struct UserRow {
    int id;
    std::string email;
    std::string passwordHash;
    std::string salt;
    std::string role;       // "user" | "admin"
    bool isPremium;
    long long storageLimitBytes;
    long long storageUsedBytes;
};

struct FileRow {
    int id;
    int ownerId;
    std::string originalName;
    std::string storedPath;
    long long sizeBytes;
    long long createdAt;
};

struct ShareLinkRow {
    int id;
    int fileId;
    std::string token;
    long long expiresAt;     // epoch seconds, 0 = never
    int maxDownloads;        // -1 = unlimited
    int downloadCount;
};

class Database {
public:
    explicit Database(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database: " + path);
        }
        exec("PRAGMA foreign_keys = ON;");
        migrate();
    }

    ~Database() { if (db_) sqlite3_close(db_); }

    void migrate() {
        exec(R"sql(
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_premium INTEGER NOT NULL DEFAULT 0,
                storage_limit_bytes INTEGER NOT NULL DEFAULT 104857600,
                storage_used_bytes INTEGER NOT NULL DEFAULT 0
            );
        )sql");

        exec(R"sql(
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );
        )sql");

        exec(R"sql(
            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at INTEGER NOT NULL DEFAULT 0,
                max_downloads INTEGER NOT NULL DEFAULT -1,
                download_count INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(file_id) REFERENCES files(id)
            );
        )sql");
    }

    // ---- Users ----
    int createUser(const std::string& email, const std::string& hash,
                    const std::string& salt, const std::string& role = "user") {
        sqlite3_stmt* stmt;
        const char* sql = "INSERT INTO users (email, password_hash, salt, role) VALUES (?, ?, ?, ?);";
        prepare(sql, &stmt);
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, role.c_str(), -1, SQLITE_TRANSIENT);
        step(stmt);
        sqlite3_finalize(stmt);
        return (int)sqlite3_last_insert_rowid(db_);
    }

    std::optional<UserRow> getUserByEmail(const std::string& email) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id, email, password_hash, salt, role, is_premium, "
                           "storage_limit_bytes, storage_used_bytes FROM users WHERE email = ?;";
        prepare(sql, &stmt);
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);
        std::optional<UserRow> result;
        if (sqlite3_step(stmt) == SQLITE_ROW) result = rowToUser(stmt);
        sqlite3_finalize(stmt);
        return result;
    }

    std::optional<UserRow> getUserById(int id) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id, email, password_hash, salt, role, is_premium, "
                           "storage_limit_bytes, storage_used_bytes FROM users WHERE id = ?;";
        prepare(sql, &stmt);
        sqlite3_bind_int(stmt, 1, id);
        std::optional<UserRow> result;
        if (sqlite3_step(stmt) == SQLITE_ROW) result = rowToUser(stmt);
        sqlite3_finalize(stmt);
        return result;
    }

    void setPremium(int userId, bool premium, long long newLimitBytes) {
        sqlite3_stmt* stmt;
        const char* sql = "UPDATE users SET is_premium = ?, storage_limit_bytes = ? WHERE id = ?;";
        prepare(sql, &stmt);
        sqlite3_bind_int(stmt, 1, premium ? 1 : 0);
        sqlite3_bind_int64(stmt, 2, newLimitBytes);
        sqlite3_bind_int(stmt, 3, userId);
        step(stmt);
        sqlite3_finalize(stmt);
    }

    void addStorageUsed(int userId, long long deltaBytes) {
        sqlite3_stmt* stmt;
        const char* sql = "UPDATE users SET storage_used_bytes = storage_used_bytes + ? WHERE id = ?;";
        prepare(sql, &stmt);
        sqlite3_bind_int64(stmt, 1, deltaBytes);
        sqlite3_bind_int(stmt, 2, userId);
        step(stmt);
        sqlite3_finalize(stmt);
    }

    // ---- Files ----
    int createFile(int ownerId, const std::string& originalName,
                    const std::string& storedPath, long long sizeBytes, long long createdAt) {
        sqlite3_stmt* stmt;
        const char* sql = "INSERT INTO files (owner_id, original_name, stored_path, size_bytes, created_at) "
                           "VALUES (?, ?, ?, ?, ?);";
        prepare(sql, &stmt);
        sqlite3_bind_int(stmt, 1, ownerId);
        sqlite3_bind_text(stmt, 2, originalName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, storedPath.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, sizeBytes);
        sqlite3_bind_int64(stmt, 5, createdAt);
        step(stmt);
        sqlite3_finalize(stmt);
        return (int)sqlite3_last_insert_rowid(db_);
    }

    std::vector<FileRow> listFilesForUser(int ownerId) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id, owner_id, original_name, stored_path, size_bytes, created_at "
                           "FROM files WHERE owner_id = ? ORDER BY created_at DESC;";
        prepare(sql, &stmt);
        sqlite3_bind_int(stmt, 1, ownerId);
        std::vector<FileRow> out;
        while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(rowToFile(stmt));
        sqlite3_finalize(stmt);
        return out;
    }

    std::vector<FileRow> listAllFiles() {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id, owner_id, original_name, stored_path, size_bytes, created_at "
                           "FROM files ORDER BY created_at DESC;";
        prepare(sql, &stmt);
        std::vector<FileRow> out;
        while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(rowToFile(stmt));
        sqlite3_finalize(stmt);
        return out;
    }

    std::optional<FileRow> getFileById(int fileId) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id, owner_id, original_name, stored_path, size_bytes, created_at "
                           "FROM files WHERE id = ?;";
        prepare(sql, &stmt);
        sqlite3_bind_int(stmt, 1, fileId);
        std::optional<FileRow> result;
        if (sqlite3_step(stmt) == SQLITE_ROW) result = rowToFile(stmt);
        sqlite3_finalize(stmt);
        return result;
    }

    // ---- Share links ----
    int createShareLink(int fileId, const std::string& token, long long expiresAt, int maxDownloads) {
        sqlite3_stmt* stmt;
        const char* sql = "INSERT INTO share_links (file_id, token, expires_at, max_downloads) "
                           "VALUES (?, ?, ?, ?);";
        prepare(sql, &stmt);
        sqlite3_bind_int(stmt, 1, fileId);
        sqlite3_bind_text(stmt, 2, token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, expiresAt);
        sqlite3_bind_int(stmt, 4, maxDownloads);
        step(stmt);
        sqlite3_finalize(stmt);
        return (int)sqlite3_last_insert_rowid(db_);
    }

    std::optional<ShareLinkRow> getShareLinkByToken(const std::string& token) {
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id, file_id, token, expires_at, max_downloads, download_count "
                           "FROM share_links WHERE token = ?;";
        prepare(sql, &stmt);
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
        std::optional<ShareLinkRow> result;
        if (sqlite3_step(stmt) == SQLITE_ROW) result = rowToShareLink(stmt);
        sqlite3_finalize(stmt);
        return result;
    }

    void incrementDownloadCount(int shareLinkId) {
        sqlite3_stmt* stmt;
        const char* sql = "UPDATE share_links SET download_count = download_count + 1 WHERE id = ?;";
        prepare(sql, &stmt);
        sqlite3_bind_int(stmt, 1, shareLinkId);
        step(stmt);
        sqlite3_finalize(stmt);
    }

private:
    sqlite3* db_ = nullptr;

    void exec(const std::string& sql) {
        char* errMsg = nullptr;
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
            std::string msg = errMsg ? errMsg : "unknown sqlite error";
            sqlite3_free(errMsg);
            throw std::runtime_error("SQLite exec error: " + msg);
        }
    }

    void prepare(const char* sql, sqlite3_stmt** stmt) {
        if (sqlite3_prepare_v2(db_, sql, -1, stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("SQLite prepare error: ") + sqlite3_errmsg(db_));
        }
    }

    void step(sqlite3_stmt* stmt) {
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            throw std::runtime_error(std::string("SQLite step error: ") + sqlite3_errmsg(db_));
        }
    }

    static UserRow rowToUser(sqlite3_stmt* stmt) {
        UserRow u;
        u.id = sqlite3_column_int(stmt, 0);
        u.email = (const char*)sqlite3_column_text(stmt, 1);
        u.passwordHash = (const char*)sqlite3_column_text(stmt, 2);
        u.salt = (const char*)sqlite3_column_text(stmt, 3);
        u.role = (const char*)sqlite3_column_text(stmt, 4);
        u.isPremium = sqlite3_column_int(stmt, 5) != 0;
        u.storageLimitBytes = sqlite3_column_int64(stmt, 6);
        u.storageUsedBytes = sqlite3_column_int64(stmt, 7);
        return u;
    }

    static FileRow rowToFile(sqlite3_stmt* stmt) {
        FileRow f;
        f.id = sqlite3_column_int(stmt, 0);
        f.ownerId = sqlite3_column_int(stmt, 1);
        f.originalName = (const char*)sqlite3_column_text(stmt, 2);
        f.storedPath = (const char*)sqlite3_column_text(stmt, 3);
        f.sizeBytes = sqlite3_column_int64(stmt, 4);
        f.createdAt = sqlite3_column_int64(stmt, 5);
        return f;
    }

    static ShareLinkRow rowToShareLink(sqlite3_stmt* stmt) {
        ShareLinkRow s;
        s.id = sqlite3_column_int(stmt, 0);
        s.fileId = sqlite3_column_int(stmt, 1);
        s.token = (const char*)sqlite3_column_text(stmt, 2);
        s.expiresAt = sqlite3_column_int64(stmt, 3);
        s.maxDownloads = sqlite3_column_int(stmt, 4);
        s.downloadCount = sqlite3_column_int(stmt, 5);
        return s;
    }
};
