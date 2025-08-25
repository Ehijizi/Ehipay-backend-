import express from "express";
import Stripe from "stripe";
import cors from "cors";

const app = express();
const stripe = new Stripe("YOUR_STRIPE_SECRET_KEY"); // Test key

app.use(cors());
app.use(express.json());

app.post("/create-checkout-session", async (req, res) => {
  const { amount, item } = req.body;
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    line_items: [{
      price_data: {
        currency: "usd",
        product_data: { name: item },
        unit_amount: parseInt(amount) * 100
      },
      quantity: 1
    }],
    mode: "payment",
    success_url: "https://your-frontend-url.com/success.html",
    cancel_url: "https://your-frontend-url.com/cancel.html"
  });
  res.json({ url: session.url });
});

app.listen(3000, () => console.log("Server running on port 3000"));
