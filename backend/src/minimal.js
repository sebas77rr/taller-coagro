import express from "express";

const app = express();

app.get("/", (req, res) => res.json({ ok: true, msg: "minimal up" }));
app.get("/api/health", (req, res) =>
  res.json({ ok: true, service: "minimal" })
);

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log("MINIMAL UP on", PORT)
);