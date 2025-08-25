import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import Stripe from "stripe";
import { pool, query } from "./db.js";

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// --- security & misc middleware ---
const origins = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: origins.length ? origins : true, credentials: false }));
app.use(helmet());
app.set("trust proxy", 1);
app.use(rateLimit({ windowMs: 60_000, max: 100 })); // 100 req/min per IP

// Webhook MUST get the raw body for signature verification
app.post("/v1/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const sig = req.headers["stripe-signature"];
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);

    // de-duplicate
    const payloadHash = crypto.createHash("sha256").update(req.body).digest("hex");
    const existed = await query("SELECT 1 FROM webhook_events WHERE event_id=$1", [event.id]);
    if (existed.rowCount) return res.status(200).send({ ok: true, deduped: true });

    // minimal handlers
    if (event.type === "payment_intent.succeeded") {
      const pi = event.data.object; // Stripe PI
      // Upsert payment_intents
      await query(
        `INSERT INTO payment_intents (provider, provider_id, amount_cents, currency, status)
         VALUES ('stripe',$1,$2,$3,'succeeded')
         ON CONFLICT (provider_id) DO UPDATE SET status='succeeded', updated_at=now()`,
        [pi.id, pi.amount_received, pi.currency]
      );
      // Write ledger: Customer -> Platform Escrow
      const { rows: escrow } = await query("SELECT id FROM accounts WHERE type='platform_escrow' LIMIT 1");
      const customerAccountId = crypto.randomUUID(); // in real life: map to your user account
      await query("INSERT INTO accounts (id,name,type) VALUES ($1,$2,'customer') ON CONFLICT DO NOTHING",
        [customerAccountId, `Customer ${pi.customer ?? 'anon'}`]);
      await query(
        `INSERT INTO transactions (debit_account, credit_account, amount_cents, currency, external_ref)
         VALUES ($1,$2,$3,$4,$5)`,
        [customerAccountId, escrow[0].id, pi.amount_received, pi.currency, pi.id]
      );
    } else if (event.type === "charge.refunded") {
      // you can mirror refunds with reversing ledger entries here
    }

    await query(
      "INSERT INTO webhook_events (event_id, type, payload_hash) VALUES ($1,$2,$3)",
      [event.id, event.type, payloadHash]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Webhook error:", err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

// All other routes use JSON
app.use(express.json());

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// Create payment intent (idempotent)
app.post("/v1/payment_intents", async (req, res) => {
  try {
    const { amount_cents, currency = "usd", metadata = {} } = req.body || {};
    const idem = req.header("Idempotency-Key");
    if (!idem) return res.status(400).json({ error: "Missing Idempotency-Key" });
    if (!Number.isInteger(amount_cents) || amount_cents <= 0) {
      return res.status(400).json({ error: "amount_cents must be a positive integer" });
    }

    const endpoint = "/v1/payment_intents";
    const found = await query(
      "SELECT response_json FROM idempotency_keys WHERE key=$1 AND endpoint=$2",
      [idem, endpoint]
    );
    if (found.rowCount) return res.json(found.rows[0].response_json);

    const pi = await stripe.paymentIntents.create(
      {
        amount: amount_cents,
        currency,
        automatic_payment_methods: { enabled: true },
        metadata
      },
      { idempotencyKey: idem }
    );

    await query(
      `INSERT INTO payment_intents (provider, provider_id, amount_cents, currency, status)
       VALUES ('stripe',$1,$2,$3,$4)
       ON CONFLICT (provider_id) DO NOTHING`,
      [pi.id, amount_cents, currency, pi.status]
    );

    const response = { id: pi.id, client_secret: pi.client_secret, status: pi.status };
    await query(
      "INSERT INTO idempotency_keys (key, endpoint, response_json) VALUES ($1,$2,$3)",
      [idem, endpoint, response]
    );

    res.json(response);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create payment intent" });
  }
});

// Basic lookup
app.get("/v1/payments/:provider_id", async (req, res) => {
  const { rows } = await query(
    "SELECT provider_id, amount_cents, currency, status, created_at FROM payment_intents WHERE provider_id=$1",
    [req.params.provider_id]
  );
  if (!rows.length) return res.status(404).json({ error: "Not found" });
  res.json(rows[0]);
});

// Refund (simplified)
app.post("/v1/refunds", async (req, res) => {
  try {
    const { provider_payment_intent_id } = req.body || {};
    const refund = await stripe.refunds.create({ payment_intent: provider_payment_intent_id });
    res.json({ id: refund.id, status: refund.status });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: "Refund failed" });
  }
});

const port = process.env.PORT || 8000;
app.listen(port, "0.0.0.0", () => console.log(`Server listening on ${port}`));

