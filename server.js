/**
 * PayZa mobile-money payment server
 *
 * This server implements PayZa's documented hosted mobile-money flow for:
 * - Zambia: ZMW
 * - Malawi: MWK
 * - Sierra Leone: SLL in the PayZa API (display SLE to customers)
 *
 * 1. Create a payment with POST /api/payments.
 * 2. Redirect the customer to data.payment_url.
 * 3. Receive the result at POST /api/payza/webhook.
 * 4. Verify a payment with GET /api/payments/:reference/verify.
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
const paymentRequestCache = new Map();
const PAYMENT_REQUEST_CACHE_TTL_MS = 15 * 60 * 1000;
const frontendOrigins = (process.env.FRONTEND_ORIGINS || "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const COUNTRY_PROFILES = {
  ZM: {
    code: "ZM",
    name: "Zambia",
    currency: "ZMW",
    displayCurrency: "ZMW",
    countryCode: "260",
    phonePattern: /^\+260(?:95|96|76|97|77)\d{7}$/,
    examples: ["0971234567", "+260971234567"],
    networks: [
      { name: "Airtel", pattern: /^\+260(?:97|77)\d{7}$/ },
      { name: "MTN", pattern: /^\+260(?:96|76)\d{7}$/ },
      { name: "Zamtel", pattern: /^\+26095\d{7}$/ },
    ],
  },
  MW: {
    code: "MW",
    name: "Malawi",
    currency: "MWK",
    displayCurrency: "MWK",
    countryCode: "265",
    phonePattern: /^\+265(?:98|99|88)\d{7}$/,
    examples: ["0991234567", "+265991234567"],
    networks: [
      { name: "Airtel", pattern: /^\+265(?:98|99)\d{7}$/ },
      { name: "TNM", pattern: /^\+26588\d{7}$/ },
    ],
  },
  SL: {
    code: "SL",
    name: "Sierra Leone",
    currency: "SLL",
    displayCurrency: "SLE",
    countryCode: "232",
    phonePattern: /^\+232(?:72|73|74|75|76|78|79)\d{6}$/,
    examples: ["072123456", "+23272123456"],
    networks: [
      {
        name: "Orange",
        pattern: /^\+232(?:72|73|74|75|76|78|79)\d{6}$/,
      },
    ],
  },
};

const COUNTRY_ALIASES = {
  ZM: "ZM",
  ZAMBIA: "ZM",
  ZMW: "ZM",
  MW: "MW",
  MALAWI: "MW",
  MWK: "MW",
  SL: "SL",
  "SIERRA LEONE": "SL",
  SLL: "SL",
  SLE: "SL",
};

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
    ["PAYZA_REDIRECT_URL", process.env.PAYZA_REDIRECT_URL],
    ["PAYZA_CANCEL_URL", process.env.PAYZA_CANCEL_URL],
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

function getCountryProfile(value) {
  const alias = getText(value).toUpperCase();
  const code = COUNTRY_ALIASES[alias];
  const profile = code ? COUNTRY_PROFILES[code] : undefined;

  if (!profile) {
    throw new HttpError(
      400,
      "INVALID_COUNTRY",
      "Choose a supported country: Zambia, Malawi, or Sierra Leone.",
      {
        supportedCountries: Object.values(COUNTRY_PROFILES).map((item) => ({
          code: item.code,
          name: item.name,
          currency: item.currency,
          displayCurrency: item.displayCurrency,
        })),
      }
    );
  }

  return profile;
}

function normalizePhone(value, profile) {
  if (value === undefined || value === null || value === "") {
    throw new HttpError(
      400,
      "MISSING_PHONE",
      `A ${profile.name} mobile number is required.`
    );
  }

  if (typeof value !== "string" && typeof value !== "number") {
    throw new HttpError(
      400,
      "INVALID_PHONE",
      `phone must be a valid ${profile.name} mobile number.`
    );
  }

  let phone = String(value).trim().replace(/[\s().-]/g, "");
  if (phone.startsWith("00")) {
    phone = `+${phone.slice(2)}`;
  }

  if (phone.startsWith("0")) {
    phone = `+${profile.countryCode}${phone.slice(1)}`;
  } else if (new RegExp(`^${profile.countryCode}\\d+$`).test(phone)) {
    phone = `+${phone}`;
  }

  const network = profile.networks.find((item) => item.pattern.test(phone));
  if (!profile.phonePattern.test(phone) || !network) {
    throw new HttpError(
      400,
      "INVALID_PHONE",
      `phone must be a valid ${profile.name} mobile number.`,
      {
        acceptedExamples: profile.examples,
        acceptedNetworks: profile.networks.map((item) => item.name),
      }
    );
  }

  return { phone, network: network.name };
}

function validateReference(value) {
  const reference = getText(value);
  if (reference.length < 1 || reference.length > 64) {
    throw new HttpError(
      400,
      reference.length === 0 ? "MISSING_REFERENCE" : "INVALID_REFERENCE",
      reference.length === 0
        ? "reference is required."
        : "reference must be between 1 and 64 characters."
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

function validateAmount(value, profile) {
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
      `amount must be a positive number in ${profile.displayCurrency}. PayZa applies the exact network minimum.`
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

function getPaymentRequestFingerprint(input) {
  return JSON.stringify({
    amount: input.amount,
    currency: input.profile.currency,
    email: input.email,
    name: input.name,
    phone: input.phone,
  });
}

function getCachedPaymentRequest(reference) {
  const entry = paymentRequestCache.get(reference);
  if (!entry) return null;

  if (Date.now() - entry.createdAt > PAYMENT_REQUEST_CACHE_TTL_MS) {
    paymentRequestCache.delete(reference);
    return null;
  }

  return entry;
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
  const profile = getCountryProfile(
    getFirstValue(body.country, body.country_code, body.currency)
  );
  const amount = validateAmount(body.amount, profile);
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
  const phoneResult = normalizePhone(rawPhone, profile);

  if (!email || !validateEmail(email)) {
    throw new HttpError(
      400,
      "INVALID_EMAIL",
      "A valid customer email is required by PayZa."
    );
  }

  if (name.length < 2 || name.length > 150) {
    throw new HttpError(
      400,
      name.length < 2 ? "MISSING_NAME" : "INVALID_NAME",
      name.length < 2
        ? "A customer name is required."
        : "name must not exceed 150 characters."
    );
  }

  const redirectUrl = validateUrl(
    process.env.PAYZA_REDIRECT_URL,
    "redirect_url"
  );
  const cancelUrl = validateUrl(
    process.env.PAYZA_CANCEL_URL,
    "cancel_url"
  );

  if (body.network && body.network !== phoneResult.network) {
    throw new HttpError(
      400,
      "NETWORK_MISMATCH",
      "The selected country and phone number do not match the detected network.",
      {
        detectedNetwork: phoneResult.network,
        receivedNetwork: body.network,
      }
    );
  }

  let metadata = body.metadata;
  if (metadata !== undefined && !isPlainObject(metadata)) {
    throw new HttpError(400, "INVALID_METADATA", "metadata must be a JSON object.");
  }

  const description = getText(body.description) || `${profile.name} mobile-money payment`;
  if (description.length > 100) {
    throw new HttpError(
      400,
      "INVALID_DESCRIPTION",
      "description must not exceed 100 characters."
    );
  }

  return {
    profile,
    amount,
    reference,
    email,
    name,
    phone: phoneResult.phone,
    network: phoneResult.network,
    redirectUrl,
    cancelUrl,
    description,
    metadata,
  };
}

function createPayzaPaymentPayload(input) {
  const customer = {
    email: input.email,
    name: input.name,
    phone: input.phone,
  };

  return {
    amount: input.amount,
    currency: input.profile.currency,
    reference: input.reference,
    customer,
    callback_url: process.env.PAYZA_WEBHOOK_URL,
    redirect_url: input.redirectUrl,
    cancel_url: input.cancelUrl,
    description: input.description,
    metadata: {
      ...(input.metadata || {}),
      country: input.profile.code,
      country_name: input.profile.name,
      detected_network: input.network,
    },
  };
}

function paymentResponse(body, input) {
  const data = isPlainObject(body.data) ? body.data : {};

  return {
    success: true,
    message:
      body.message ||
      `${input.profile.name} payment created. Redirect the customer to payment_url.`,
    data: {
      reference: data.reference,
      payment_url: data.payment_url,
      amount: data.amount,
      currency: data.currency || input.profile.currency,
      display_currency: input.profile.displayCurrency,
      country: input.profile.name,
      detected_network: input.network,
      status: data.status || "pending",
      gateway: data.gateway,
      actual_gateway: data.actual_gateway,
      stk_sent: data.stk_sent,
      accepted_methods: data.accepted_methods,
      note:
        "This payment uses PayZa hosted mobile-money checkout.",
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
    service: "payza-mobile-money-payment-server",
    payzaBaseUrl,
    payzaConfigured:
      Boolean(process.env.PAYZA_PUBLIC_KEY) &&
      Boolean(process.env.PAYZA_SECRET_KEY),
    webhookConfigured: Boolean(process.env.PAYZA_WEBHOOK_URL),
    redirectConfigured:
      Boolean(process.env.PAYZA_REDIRECT_URL) &&
      Boolean(process.env.PAYZA_CANCEL_URL),
    frontendOrigins,
    supportedCountries: Object.values(COUNTRY_PROFILES).map((profile) => ({
      code: profile.code,
      name: profile.name,
      currency: profile.currency,
      displayCurrency: profile.displayCurrency,
      networks: profile.networks.map((network) => network.name),
    })),
  });
});

app.post("/api/payments", async (req, res) => {
  try {
    requireConfiguration();
    const input = extractPaymentInput(req.body);
    const fingerprint = getPaymentRequestFingerprint(input);
    const cached = getCachedPaymentRequest(input.reference);

    if (cached) {
      if (cached.fingerprint !== fingerprint) {
        throw new HttpError(
          409,
          "REFERENCE_ALREADY_USED",
          "This payment reference is already associated with different payment details."
        );
      }

      const cachedResponse = await cached.promise;
      return res.status(201).json(cachedResponse);
    }

    const paymentPromise = payzaRequest("/api/v1/pay", {
      method: "POST",
      body: JSON.stringify(createPayzaPaymentPayload(input)),
    }).then((upstream) => paymentResponse(upstream, input));

    paymentRequestCache.set(input.reference, {
      createdAt: Date.now(),
      fingerprint,
      promise: paymentPromise,
    });

    try {
      const createdPayment = await paymentPromise;
      return res.status(201).json(createdPayment);
    } catch (error) {
      const current = paymentRequestCache.get(input.reference);
      if (current && current.promise === paymentPromise) {
        paymentRequestCache.delete(input.reference);
      }
      throw error;
    }
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
      service: "payza-mobile-money-payment-server",
      port,
      payzaBaseUrl,
      supportedCurrencies: Object.values(COUNTRY_PROFILES).map(
        (profile) => profile.currency
      ),
    })
  );
});