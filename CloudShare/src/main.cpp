// main.cpp
// CloudShare - Secure File Storage & Sharing Platform (C++ backend)
//
// Stack: cpp-httplib (HTTP server), SQLite3 (persistence), OpenSSL (hashing/HMAC)
// Endpoints:
//   POST   /register                 - create account
//   POST   /login                    - returns a signed session token
//   POST   /files/upload             - upload a file (auth required)
//   GET    /files                    - list your files (auth required)
//   GET    /files/all                - list all files (admin only)
//   POST   /files/:id/share          - create a protected share link
//   GET    /share/:token             - download via share link (public, checked)
//   POST   /billing/upgrade/order    - create a mock payment order for premium
//   POST   /billing/upgrade/confirm  - confirm payment, upgrade storage limit
//
// Role-based access: "user" vs "admin". Premium users get a larger storage quota.

#include "httplib.h"
#include "nlohmann/json.hpp"
#include "db.hpp"
#include "crypto_utils.hpp"
#include "payment_gateway.hpp"

#include <fstream>
#include <filesystem>
#include <iostream>
#include <memory>

using json = nlohmann::json;
namespace fs = std::filesystem;

static const std::string JWT_SECRET = "cloudshare-dev-secret-change-in-prod";
static const std::string STORAGE_DIR = "storage";
static const long long DEFAULT_QUOTA_BYTES = 100LL * 1024 * 1024;   // 100 MB
static const long long PREMIUM_QUOTA_BYTES = 5LL * 1024 * 1024 * 1024; // 5 GB

std::unique_ptr<Database> dbPtr;
#define db (*dbPtr)

// ---- Auth helpers ----

std::string issueToken(const UserRow& user) {
    json payload = {
        {"uid", user.id},
        {"email", user.email},
        {"role", user.role},
        {"iat", crypto_utils::nowEpochSeconds()}
    };
    return crypto_utils::signToken(payload.dump(), JWT_SECRET);
}

// Returns userId if token is valid, -1 otherwise.
int authenticate(const httplib::Request& req) {
    auto authHeader = req.get_header_value("Authorization");
    const std::string prefix = "Bearer ";
    if (authHeader.rfind(prefix, 0) != 0) return -1;
    std::string token = authHeader.substr(prefix.size());
    std::string payloadStr = crypto_utils::verifyToken(token, JWT_SECRET);
    if (payloadStr.empty()) return -1;
    try {
        json payload = json::parse(payloadStr);
        return payload.at("uid").get<int>();
    } catch (...) {
        return -1;
    }
}

void sendJson(httplib::Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(), "application/json");
}

int main() {
    fs::create_directories(STORAGE_DIR);
    fs::create_directories("data");
    dbPtr = std::make_unique<Database>("data/cloudshare.db");

    httplib::Server svr;

    // ---- Register ----
    svr.Post("/register", [](const httplib::Request& req, httplib::Response& res) {
        try {
            json body = json::parse(req.body);
            std::string email = body.at("email").get<std::string>();
            std::string password = body.at("password").get<std::string>();

            if (email.empty() || password.size() < 6) {
                return sendJson(res, 400, {{"error", "email required, password must be >= 6 chars"}});
            }
            if (db.getUserByEmail(email).has_value()) {
                return sendJson(res, 409, {{"error", "email already registered"}});
            }

            std::string salt = crypto_utils::generateSalt();
            std::string hash = crypto_utils::hashPassword(password, salt);
            int userId = db.createUser(email, hash, salt, "user");

            auto user = db.getUserById(userId);
            sendJson(res, 201, {{"userId", userId}, {"token", issueToken(*user)}});
        } catch (const std::exception& e) {
            sendJson(res, 400, {{"error", std::string("bad request: ") + e.what()}});
        }
    });

    // ---- Login ----
    svr.Post("/login", [](const httplib::Request& req, httplib::Response& res) {
        try {
            json body = json::parse(req.body);
            std::string email = body.at("email").get<std::string>();
            std::string password = body.at("password").get<std::string>();

            auto userOpt = db.getUserByEmail(email);
            if (!userOpt.has_value() ||
                !crypto_utils::verifyPassword(password, userOpt->salt, userOpt->passwordHash)) {
                return sendJson(res, 401, {{"error", "invalid email or password"}});
            }
            sendJson(res, 200, {{"token", issueToken(*userOpt)}, {"role", userOpt->role}});
        } catch (const std::exception& e) {
            sendJson(res, 400, {{"error", std::string("bad request: ") + e.what()}});
        }
    });

    // ---- Upload file (base64 body for simplicity; a real client streams multipart) ----
    svr.Post("/files/upload", [](const httplib::Request& req, httplib::Response& res) {
        int userId = authenticate(req);
        if (userId < 0) return sendJson(res, 401, {{"error", "unauthenticated"}});

        try {
            json body = json::parse(req.body);
            std::string filename = body.at("filename").get<std::string>();
            std::string base64Content = body.at("content_base64").get<std::string>();
            std::string decoded = crypto_utils::base64Decode(base64Content);

            auto user = db.getUserById(userId);
            long long newUsed = user->storageUsedBytes + (long long)decoded.size();
            if (newUsed > user->storageLimitBytes) {
                return sendJson(res, 413, {{"error", "storage quota exceeded"},
                                            {"limit_bytes", user->storageLimitBytes},
                                            {"used_bytes", user->storageUsedBytes}});
            }

            std::string storedName = std::to_string(userId) + "_" +
                                      crypto_utils::randomToken(8) + "_" + filename;
            std::string storedPath = STORAGE_DIR + "/" + storedName;
            std::ofstream out(storedPath, std::ios::binary);
            out.write(decoded.data(), (std::streamsize)decoded.size());
            out.close();

            int fileId = db.createFile(userId, filename, storedPath,
                                        (long long)decoded.size(), crypto_utils::nowEpochSeconds());
            db.addStorageUsed(userId, (long long)decoded.size());

            sendJson(res, 201, {{"fileId", fileId}, {"size_bytes", decoded.size()}});
        } catch (const std::exception& e) {
            sendJson(res, 400, {{"error", std::string("bad request: ") + e.what()}});
        }
    });

    // ---- List own files ----
    svr.Get("/files", [](const httplib::Request& req, httplib::Response& res) {
        int userId = authenticate(req);
        if (userId < 0) return sendJson(res, 401, {{"error", "unauthenticated"}});

        auto files = db.listFilesForUser(userId);
        json arr = json::array();
        for (auto& f : files) {
            arr.push_back({{"id", f.id}, {"name", f.originalName},
                            {"size_bytes", f.sizeBytes}, {"created_at", f.createdAt}});
        }
        sendJson(res, 200, {{"files", arr}});
    });

    // ---- Admin: list all files across all users ----
    svr.Get("/files/all", [](const httplib::Request& req, httplib::Response& res) {
        int userId = authenticate(req);
        if (userId < 0) return sendJson(res, 401, {{"error", "unauthenticated"}});
        auto user = db.getUserById(userId);
        if (!user.has_value() || user->role != "admin") {
            return sendJson(res, 403, {{"error", "admin role required"}});
        }
        auto files = db.listAllFiles();
        json arr = json::array();
        for (auto& f : files) {
            arr.push_back({{"id", f.id}, {"owner_id", f.ownerId}, {"name", f.originalName},
                            {"size_bytes", f.sizeBytes}, {"created_at", f.createdAt}});
        }
        sendJson(res, 200, {{"files", arr}});
    });

    // ---- Create a protected share link for a file you own ----
    svr.Post(R"(/files/(\d+)/share)", [](const httplib::Request& req, httplib::Response& res) {
        int userId = authenticate(req);
        if (userId < 0) return sendJson(res, 401, {{"error", "unauthenticated"}});

        int fileId = std::stoi(req.matches[1]);
        auto fileOpt = db.getFileById(fileId);
        if (!fileOpt.has_value() || fileOpt->ownerId != userId) {
            return sendJson(res, 404, {{"error", "file not found or not owned by you"}});
        }

        long long expiresInSeconds = 3600; // default 1 hour
        int maxDownloads = -1;
        if (!req.body.empty()) {
            try {
                json body = json::parse(req.body);
                if (body.contains("expires_in_seconds"))
                    expiresInSeconds = body.at("expires_in_seconds").get<long long>();
                if (body.contains("max_downloads"))
                    maxDownloads = body.at("max_downloads").get<int>();
            } catch (...) { /* use defaults */ }
        }

        std::string token = crypto_utils::randomToken(16);
        long long expiresAt = expiresInSeconds > 0
                                   ? crypto_utils::nowEpochSeconds() + expiresInSeconds
                                   : 0;
        db.createShareLink(fileId, token, expiresAt, maxDownloads);

        sendJson(res, 201, {{"share_token", token}, {"expires_at", expiresAt},
                             {"max_downloads", maxDownloads}, {"url", "/share/" + token}});
    });

    // ---- Download via a protected share link (no auth needed, link itself is the credential) ----
    svr.Get(R"(/share/([a-fA-F0-9]+))", [](const httplib::Request& req, httplib::Response& res) {
        std::string token = req.matches[1];
        auto linkOpt = db.getShareLinkByToken(token);
        if (!linkOpt.has_value()) return sendJson(res, 404, {{"error", "invalid share link"}});

        if (linkOpt->expiresAt != 0 && crypto_utils::nowEpochSeconds() > linkOpt->expiresAt) {
            return sendJson(res, 410, {{"error", "share link expired"}});
        }
        if (linkOpt->maxDownloads >= 0 && linkOpt->downloadCount >= linkOpt->maxDownloads) {
            return sendJson(res, 410, {{"error", "download limit reached"}});
        }

        auto fileOpt = db.getFileById(linkOpt->fileId);
        if (!fileOpt.has_value() || !fs::exists(fileOpt->storedPath)) {
            return sendJson(res, 404, {{"error", "file no longer available"}});
        }

        std::ifstream in(fileOpt->storedPath, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        db.incrementDownloadCount(linkOpt->id);

        res.set_header("Content-Disposition", "attachment; filename=\"" + fileOpt->originalName + "\"");
        res.set_content(content, "application/octet-stream");
    });

    // ---- Billing: create a mock order to upgrade to premium (simulated Razorpay flow) ----
    svr.Post("/billing/upgrade/order", [](const httplib::Request& req, httplib::Response& res) {
        int userId = authenticate(req);
        if (userId < 0) return sendJson(res, 401, {{"error", "unauthenticated"}});

        auto order = payment_gateway::createOrder(49900); // Rs. 499.00 in paise
        sendJson(res, 200, {{"order_id", order.orderId}, {"amount_paise", order.amountPaise},
                             {"currency", order.currency}});
    });

    svr.Post("/billing/upgrade/confirm", [](const httplib::Request& req, httplib::Response& res) {
        int userId = authenticate(req);
        if (userId < 0) return sendJson(res, 401, {{"error", "unauthenticated"}});

        try {
            json body = json::parse(req.body);
            payment_gateway::Order order;
            order.orderId = body.at("order_id").get<std::string>();
            order.status = "created";
            std::string paymentId = body.at("payment_id").get<std::string>();

            if (!payment_gateway::verifyAndCapture(order, paymentId)) {
                return sendJson(res, 402, {{"error", "payment verification failed"}});
            }

            db.setPremium(userId, true, PREMIUM_QUOTA_BYTES);
            sendJson(res, 200, {{"status", "premium activated"},
                                 {"new_limit_bytes", PREMIUM_QUOTA_BYTES}});
        } catch (const std::exception& e) {
            sendJson(res, 400, {{"error", std::string("bad request: ") + e.what()}});
        }
    });

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        sendJson(res, 200, {{"status", "ok"}});
    });

    std::cout << "CloudShare backend listening on http://localhost:8080\n";
    svr.listen("0.0.0.0", 8080);
    return 0;
}
