import express from "express";

const app = express();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send("PING OK 🚀");
});

app.listen(PORT, () => {
  console.log("PING SERVER UP ON PORT", PORT);
});
