/**
 * PayZa Zambia payment server
 *
 * This server implements PayZa's documented ZMW flow:
 * 1. Create a ZMW payment with POST /api/payments.
 * 2. Redirect the customer to data.payment_url.
 * 3. Receive the result at POST /api/payza/webhook.
 * 4. Verify a payment with GET /api/payments/:reference/verify.
 *
 * Important: PayZa documents direct `stk_push` for Kenyan M-Pesa.
 * For Zambia, PayZa documents hosted checkout followed by a mobile-money
 * prompt for Airtel, MTN, or Zamtel.
 */

const crypto = require("node:crypto");
const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();
const port = Number.parseInt(process.env.PORT || "3000", 10);
const payzaBaseUrl = (
  process.env.PAYZA_API_BASE_URL || "https://payzaapi.co.ke"
).replace(/\/+$/, "");
const frontendOrigins = (process.env.FRONTEND_ORIGINS || "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function getMissingConfiguration() {
  const required = [
    ["PAYZA_PUBLIC_KEY", process.env.PAYZA_PUBLIC_KEY],
    ["PAYZA_SECRET_KEY", process.env.PAYZA_SECRET_KEY],
    ["PAYZA_WEBHOOK_URL", process.env.PAYZA_WEBHOOK_URL],
  ];

  return required
    .filter(([, value]) => !value || !value.trim())
    .map(([name]) => name);
}

function requireConfiguration() {
  const missing = getMissingConfiguration();
  if (missing.length > 0) {
    throw new HttpError(
      500,
      "SERVER_NOT_CONFIGURED",
      "The payment server is not configured.",
      { missing }
    );
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function getText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function getFirstValue(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Zambia mobile numbers:
 * - Local format: 095xxxxxxx, 096xxxxxxx, 076xxxxxxx, 097xxxxxxx, 077xxxxxxx
 * - International format: +26095xxxxxxx, +26096xxxxxxx, +26076xxxxxxx,
 *   +26097xxxxxxx, +26077xxxxxxx
 *
 * PayZa's ZMW docs do not require customer.phone because the hosted checkout
 * collects the mobile-money number. If a frontend sends one, validate it and
 * send it in normalized international format.
 */
function normalizeZambianPhone(value) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  if (typeof value !== "string" && typeof value !== "number") {
    throw new HttpError(
      400,
      "INVALID_PHONE",
      "phone must be a Zambian mobile number."
    );
  }

  let phone = String(value).trim().replace(/[\s().-]/g, "");
  if (phone.startsWith("00")) {
    phone = `+${phone.slice(2)}`;
  }

  if (phone.startsWith("0")) {
    phone = `+260${phone.slice(1)}`;
  } else if (/^260\d+$/.test(phone)) {
    phone = `+${phone}`;
  }

  if (!/^\+260(?:95|96|76|97|77)\d{7}$/.test(phone)) {
    throw new HttpError(
      400,
      "INVALID_PHONE",
      "phone must be a valid Zambian mobile number using Airtel, MTN, or Zamtel format.",
      {
        acceptedExamples: [
          "0971234567",
          "0961234567",
          "0761234567",
          "+260971234567",
        ],
        acceptedNetworks: ["Airtel", "MTN", "Zamtel"],
      }
    );
  }

  return phone;
}

function validateReference(value) {
  if (value === undefined || value === null || value === "") {
    return `ZM-${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;
  }

  const reference = getText(value);
  if (reference.length < 1 || reference.length > 64) {
    throw new HttpError(
      400,
      "INVALID_REFERENCE",
      "reference must be between 1 and 64 characters."
    );
  }

  if (!/^[A-Za-z0-9._:-]+$/.test(reference)) {
    throw new HttpError(
      400,
      "INVALID_REFERENCE",
      "reference may contain only letters, numbers, hyphens, underscores, periods, and colons."
    );
  }

  return reference;
}

function validateAmount(value) {
  const amount =
    typeof value === "string" && value.trim() !== "" ? Number(value) : value;

  if (
    typeof amount !== "number" ||
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    throw new HttpError(
      400,
      "INVALID_AMOUNT",
      "amount must be a positive number in ZMW. PayZa applies the exact network minimum."
    );
  }

  return Math.round((amount + Number.EPSILON) * 100) / 100;
}

function validateUrl(value, fieldName) {
  const url = getText(value);
  if (!url) {
    throw new HttpError(
      400,
      `MISSING_${fieldName.toUpperCase()}`,
      `${fieldName} is required for PayZa hosted checkout.`
    );
  }

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") {
      throw new Error("HTTPS required");
    }
  } catch {
    throw new HttpError(
      400,
      `INVALID_${fieldName.toUpperCase()}`,
      `${fieldName} must be a valid HTTPS URL.`
    );
  }

  return url;
}

function buildPayzaHeaders() {
  return {
    Accept: "application/json",
    "Content-Type": "application/json",
    "X-Public-Key": process.env.PAYZA_PUBLIC_KEY,
    "X-Secret-Key": process.env.PAYZA_SECRET_KEY,
  };
}

async function readPayzaResponse(response) {
  const raw = await response.text();
  let body;

  try {
    body = raw ? JSON.parse(raw) : {};
  } catch {
    body = { raw };
  }

  if (!response.ok) {
    const upstreamMessage =
      body && typeof body.message === "string"
        ? body.message
        : `PayZa returned HTTP ${response.status}.`;

    throw new HttpError(
      response.status === 409 ? 409 : 502,
      "PAYZA_API_ERROR",
      upstreamMessage,
      {
        upstreamStatus: response.status,
        upstreamResponse: body,
      }
    );
  }

  if (!isPlainObject(body)) {
    throw new HttpError(
      502,
      "INVALID_PAYZA_RESPONSE",
      "PayZa returned an invalid response.",
      { upstreamStatus: response.status }
    );
  }

  if (body.success === false) {
    throw new HttpError(
      502,
      "PAYZA_PAYMENT_REJECTED",
      body.message || "PayZa rejected the payment request.",
      { upstreamStatus: response.status, upstreamResponse: body }
    );
  }

  return body;
}

async function payzaRequest(path, options = {}) {
  let response;

  try {
    response = await fetch(`${payzaBaseUrl}${path}`, {
      ...options,
      headers: {
        ...buildPayzaHeaders(),
        ...(options.headers || {}),
      },
      signal: AbortSignal.timeout(20_000),
    });
  } catch (error) {
    throw new HttpError(
      502,
      "PAYZA_UNREACHABLE",
      "PayZa could not be reached. Try again shortly.",
      { cause: error.message }
    );
  }

  return readPayzaResponse(response);
}

function extractPaymentInput(body) {
  if (!isPlainObject(body)) {
    throw new HttpError(400, "INVALID_BODY", "Request body must be a JSON object.");
  }

  const nestedCustomer = isPlainObject(body.customer) ? body.customer : {};
  const amount = validateAmount(body.amount);
  const reference = validateReference(body.reference);
  const email = getText(
    getFirstValue(body.email, body.customer_email, nestedCustomer.email)
  );
  const name = getText(
    getFirstValue(body.name, body.customer_name, nestedCustomer.name)
  );
  const rawPhone = getFirstValue(
    body.phone,
    body.customer_phone,
    nestedCustomer.phone
  );
  const phone = normalizeZambianPhone(rawPhone);

  if (!email || !validateEmail(email)) {
    throw new HttpError(
      400,
      "INVALID_EMAIL",
      "A valid customer email is required by PayZa."
    );
  }

  if (name.length > 150) {
    throw new HttpError(400, "INVALID_NAME", "name must not exceed 150 characters.");
  }

  const redirectUrl = validateUrl(
    getFirstValue(body.redirect_url, process.env.PAYZA_REDIRECT_URL),
    "redirect_url"
  );
  const cancelUrl = validateUrl(
    getFirstValue(body.cancel_url, process.env.PAYZA_CANCEL_URL),
    "cancel_url"
  );

  let metadata = body.metadata;
  if (metadata !== undefined && !isPlainObject(metadata)) {
    throw new HttpError(400, "INVALID_METADATA", "metadata must be a JSON object.");
  }

  const description = getText(
    getFirstValue(body.description, "Zambian mobile-money payment")
  );
  if (description.length > 100) {
    throw new HttpError(
      400,
      "INVALID_DESCRIPTION",
      "description must not exceed 100 characters."
    );
  }

  return {
    amount,
    reference,
    email,
    name: name || undefined,
    phone,
    redirectUrl,
    cancelUrl,
    description,
    metadata,
  };
}

function createPayzaPaymentPayload(input) {
  const customer = {
    email: input.email,
  };

  if (input.name) customer.name = input.name;
  if (input.phone) customer.phone = input.phone;

  return {
    amount: input.amount,
    currency: "ZMW",
    reference: input.reference,
    customer,
    callback_url: process.env.PAYZA_WEBHOOK_URL,
    redirect_url: input.redirectUrl,
    cancel_url: input.cancelUrl,
    description: input.description,
    ...(input.metadata ? { metadata: input.metadata } : {}),
  };
}

function paymentResponse(body) {
  const data = isPlainObject(body.data) ? body.data : {};

  return {
    success: true,
    message:
      body.message ||
      "ZMW payment created. Redirect the customer to payment_url.",
    data: {
      reference: data.reference,
      payment_url: data.payment_url,
      amount: data.amount,
      currency: data.currency || "ZMW",
      status: data.status || "pending",
      gateway: data.gateway,
      actual_gateway: data.actual_gateway,
      stk_sent: data.stk_sent,
      accepted_methods: data.accepted_methods,
      note:
        "For Zambia, use payment_url for hosted mobile-money checkout. PayZa does not document a direct Zambia stk_push flag.",
    },
  };
}

function verifyWebhookSignature(req) {
  const signingSecret = getText(process.env.PAYZA_WEBHOOK_SIGNING_SECRET);
  if (!signingSecret) return;

  const signature = getText(req.get("X-Payza-Signature"));
  if (!signature || !req.rawBody) {
    throw new HttpError(
      401,
      "INVALID_WEBHOOK_SIGNATURE",
      "Webhook signature is missing."
    );
  }

  const expected = crypto
    .createHmac("sha256", signingSecret)
    .update(req.rawBody)
    .digest("hex");

  const receivedBuffer = Buffer.from(signature, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");

  if (
    receivedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(receivedBuffer, expectedBuffer)
  ) {
    throw new HttpError(
      401,
      "INVALID_WEBHOOK_SIGNATURE",
      "Webhook signature is invalid."
    );
  }
}

function sendError(res, error) {
  const status = error instanceof HttpError ? error.status : 500;
  const payload = {
    success: false,
    error: {
      code: error.code || "INTERNAL_SERVER_ERROR",
      message:
        error instanceof HttpError
          ? error.message
          : "An unexpected server error occurred.",
    },
  };

  if (error instanceof HttpError && error.details) {
    payload.error.details = error.details;
  }

  if (!(error instanceof HttpError)) {
    console.error(error);
  }

  return res.status(status).json(payload);
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || frontendOrigins.includes("*") || frontendOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new HttpError(
          403,
          "CORS_ORIGIN_NOT_ALLOWED",
          "This frontend origin is not allowed by FRONTEND_ORIGINS."
        )
      );
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-Requested-With"],
  })
);

app.use(
  express.json({
    limit: "100kb",
    verify(req, _res, buffer) {
      req.rawBody = Buffer.from(buffer);
    },
  })
);

app.get("/health", (_req, res) => {
  res.json({
    success: true,
    service: "payza-zambia-payment-server",
    payzaBaseUrl,
    payzaConfigured:
      Boolean(process.env.PAYZA_PUBLIC_KEY) &&
      Boolean(process.env.PAYZA_SECRET_KEY),
    webhookConfigured: Boolean(process.env.PAYZA_WEBHOOK_URL),
    frontendOrigins,
    currency: "ZMW",
    networks: ["Airtel", "MTN", "Zamtel"],
  });
});

app.post("/api/payments", async (req, res) => {
  try {
    requireConfiguration();
    const input = extractPaymentInput(req.body);
    const upstream = await payzaRequest("/api/v1/pay", {
      method: "POST",
      body: JSON.stringify(createPayzaPaymentPayload(input)),
    });

    return res.status(201).json(paymentResponse(upstream));
  } catch (error) {
    return sendError(res, error);
  }
});

app.get("/api/payments/:reference/verify", async (req, res) => {
  try {
    requireConfiguration();
    const reference = validateReference(req.params.reference);
    const upstream = await payzaRequest(
      `/api/v1/verify/${encodeURIComponent(reference)}`,
      { method: "GET" }
    );

    return res.json(upstream);
  } catch (error) {
    return sendError(res, error);
  }
});

app.post("/api/payza/webhook", (req, res) => {
  try {
    verifyWebhookSignature(req);

    const event = isPlainObject(req.body) ? req.body : {};
    const reference = getText(event.reference);
    const status = getText(event.status);

    console.log(
      JSON.stringify({
        type: "payza_webhook",
        event: getText(event.event) || "unknown",
        reference: reference || null,
        status: status || null,
        receivedAt: new Date().toISOString(),
      })
    );

    return res.status(200).json({
      success: true,
      received: true,
      reference: reference || null,
      status: status || null,
    });
  } catch (error) {
    return sendError(res, error);
  }
});

app.use((_req, res) => {
  return res.status(404).json({
    success: false,
    error: {
      code: "NOT_FOUND",
      message: "Route not found.",
    },
  });
});

app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && "body" in error) {
    return sendError(
      res,
      new HttpError(400, "INVALID_JSON", "Request body contains invalid JSON.")
    );
  }

  return sendError(res, error);
});

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

app.listen(port, () => {
  console.log(
    JSON.stringify({
      service: "payza-zambia-payment-server",
      port,
      payzaBaseUrl,
      currency: "ZMW",
      networks: ["Airtel", "MTN", "Zamtel"],
    })
  );
});