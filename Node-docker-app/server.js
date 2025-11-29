const express = require("express");
const path = require("path");
const app = express();
const PORT = 3000;

// Serve the frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Backend API endpoint
app.get("/api/data", (req, res) => {
  res.json({
    message: "Hello from the Node.js API inside Docker!",
    status: "success",
    timestamp: new Date()
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
