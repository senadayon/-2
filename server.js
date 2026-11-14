const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

// 静的ファイルを公開
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
  res.send("Voice Changer Server is running!");
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Voice Changer started on port ${PORT}`);
});
