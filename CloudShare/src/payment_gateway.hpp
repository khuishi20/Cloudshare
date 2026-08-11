// payment_gateway.hpp
// Local stand-in for a payment gateway (e.g. Razorpay). Real Razorpay
// integration works over its REST API with a key id/secret; this module
// mirrors the same "create order -> verify payment" flow so the rest of
// the app (see routes.hpp) doesn't need to change when a real key is wired in.
#pragma once

#include <string>
#include "crypto_utils.hpp"

namespace payment_gateway {

struct Order {
    std::string orderId;
    long long amountPaise;   // amount in smallest currency unit, like Razorpay does
    std::string currency;
    std::string status;      // "created" | "paid"
};

// In a real integration this would call POST https://api.razorpay.com/v1/orders
// with Basic Auth (key_id:key_secret). Here we generate a local order id.
inline Order createOrder(long long amountPaise, const std::string& currency = "INR") {
    Order o;
    o.orderId = "order_" + crypto_utils::randomToken(10);
    o.amountPaise = amountPaise;
    o.currency = currency;
    o.status = "created";
    return o;
}

// In a real integration you'd verify the Razorpay payment signature
// (HMAC-SHA256 of order_id|payment_id using the key secret) sent back
// from the client-side checkout. We simulate a successful payment here.
inline bool verifyAndCapture(const Order& order, const std::string& simulatedPaymentId) {
    // Simulated: any non-empty payment id "succeeds". Replace with real
    // signature verification against Razorpay's webhook/callback payload.
    return !simulatedPaymentId.empty() && order.status == "created";
}

} // namespace payment_gateway
