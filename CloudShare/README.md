# CloudShare — Secure File Storage & Sharing Platform (C++ backend)

A backend-intensive file storage and sharing service, built in C++ to demonstrate
REST API design, authentication, role-based access control, and payment-flow
integration patterns — the same concepts a Java/Spring Boot version would use,
implemented here with a lighter native stack.

## Stack

| Concern            | Library / Tool                          |
|--------------------|------------------------------------------|
| HTTP server        | [cpp-httplib](https://github.com/yhirose/cpp-httplib) (header-only) |
| JSON               | [nlohmann/json](https://github.com/nlohmann/json) (header-only) |
| Persistence        | SQLite3 (via `libsqlite3-dev`)          |
| Hashing / signing  | OpenSSL (SHA-256, HMAC-SHA256)          |
| Build system       | CMake                                   |

No web framework magic — every route, every SQL query, every byte of the
file storage logic is explicit, so you can walk through and explain any part
of it in an interview.

## Why some pieces are "local stand-ins"

The original idea called for **Clerk** (hosted auth) and **Razorpay**
(payments). Both require live third-party accounts and API keys that aren't
available in this environment, so:

- **Auth** — instead of Clerk, `crypto_utils.hpp` implements the same idea
  Clerk (or any auth provider) gives you under the hood: a signed session
  token. It's base64url(payload) + "." + HMAC-SHA256 signature — structurally
  the same as a JWT. Swapping this for Clerk later means replacing
  `issueToken`/`authenticate` in `main.cpp` with Clerk's SDK verification call;
  nothing else in the app needs to change.
- **Payments** — `payment_gateway.hpp` mirrors Razorpay's real flow
  (`create order` → client pays → `verify + capture`) but fakes the two
  network calls locally. Swapping in real Razorpay means replacing those two
  functions with actual HTTPS calls to `api.razorpay.com`, using your key
  id/secret — the `/billing/upgrade/*` routes don't change.

This is the honest, practical way to build a "payments-integrated" project
without a merchant account: the **architecture and API contract are real and
correct**, only the two outbound network calls are simulated.

## Architecture

```
CloudShare/
├── CMakeLists.txt
├── include/              # header-only third-party libs (httplib, nlohmann/json)
├── src/
│   ├── main.cpp           # HTTP routes, wires everything together
│   ├── db.hpp              # SQLite wrapper: users, files, share_links tables
│   ├── crypto_utils.hpp    # password hashing, HMAC token signing, base64
│   └── payment_gateway.hpp # mock Razorpay-style order/verify flow
├── storage/               # uploaded file bytes live here on disk
└── data/                  # cloudshare.db (SQLite file)
```

**Data model**
- `users(id, email, password_hash, salt, role, is_premium, storage_limit_bytes, storage_used_bytes)`
- `files(id, owner_id, original_name, stored_path, size_bytes, created_at)`
- `share_links(id, file_id, token, expires_at, max_downloads, download_count)`

**Auth flow**: `/register` and `/login` return a signed token. Every
protected route reads `Authorization: Bearer <token>`, verifies the HMAC
signature, and pulls `uid`/`role` out of the payload — no server-side
session table needed (stateless auth, same principle as JWT).

**Role-based access control**: `role` is `"user"` or `"admin"`. `/files/all`
checks `role == "admin"` before returning every user's files — a real
authorization check, not just a UI hide/show.

**Storage quota enforcement**: each user has `storage_limit_bytes`
(100 MB default, 5 GB after "premium" upgrade). Every upload checks
`storage_used_bytes + new_file_size` against the limit before writing to disk.

**Protected share links**: `POST /files/:id/share` generates a random token,
optional expiry (`expires_in_seconds`) and optional download cap
(`max_downloads`). `GET /share/:token` is deliberately unauthenticated — the
token itself is the credential — but checks expiry and download count before
serving the file, and increments the download counter atomically in SQLite.

## API Reference

| Method | Route                        | Auth        | Description |
|--------|-------------------------------|-------------|--------------|
| POST   | `/register`                   | none        | `{email, password}` → account + token |
| POST   | `/login`                      | none        | `{email, password}` → token |
| POST   | `/files/upload`               | user        | `{filename, content_base64}` → stores file, enforces quota |
| GET    | `/files`                      | user        | list your own files |
| GET    | `/files/all`                  | admin only  | list every user's files |
| POST   | `/files/:id/share`            | owner only  | `{expires_in_seconds?, max_downloads?}` → share token + URL |
| GET    | `/share/:token`                | none (token is the credential) | downloads the file if link valid |
| POST   | `/billing/upgrade/order`      | user        | creates a mock payment order |
| POST   | `/billing/upgrade/confirm`    | user        | `{order_id, payment_id}` → upgrades to premium quota |
| GET    | `/health`                     | none        | liveness check |

## Build & run

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
./cloudshare        # listens on http://localhost:8080
```

## Try it end-to-end

```bash
# Register + login
curl -X POST localhost:8080/register -H "Content-Type: application/json" \
  -d '{"email":"you@test.com","password":"secret123"}'

TOKEN=$(curl -s -X POST localhost:8080/login -H "Content-Type: application/json" \
  -d '{"email":"you@test.com","password":"secret123"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")

# Upload a file (base64-encoded content)
B64=$(echo -n "hello world" | base64 -w0)
curl -X POST localhost:8080/files/upload -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"filename\":\"note.txt\",\"content_base64\":\"$B64\"}"

# List your files
curl localhost:8080/files -H "Authorization: Bearer $TOKEN"
```

## What to actually understand before an interview

If you put this on a resume, be ready to explain, in your own words:
1. Why the share-link download route is unauthenticated but still secure
   (the token is high-entropy and single-purpose — the "credential is the link" pattern).
2. Why storage quota is checked *before* the file is written, and why
   `addStorageUsed` is a separate step from `createFile`.
3. Why the token is signed (HMAC) rather than just base64-encoded — what
   attack that prevents (tampering with `role`/`uid` in the payload).
4. What you'd change to make this production-ready (rate limiting, HTTPS
   termination, moving file storage to S3/GCS instead of local disk, real
   Clerk/Razorpay integration, refresh tokens/expiry on session tokens).
