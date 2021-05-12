require("dotenv").config();

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

app.use(express.json());

const users = [];
let refrsehTokens = [];

app.get("/users", (req, res) => {
  res.json(users);
});

app.delete("/logout", (req, res) => {
  refrsehTokens = refrsehTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

app.post("/token", (req, res) => {
  const refrsehToken = req.body.token;
  if (refrsehToken == null) return res.sendStatus(401);
  if (!refrsehTokens.includes(refrsehToken)) return res.sendStatus(403);
  jwt.verify(refrsehToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAcessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

app.post("/signup", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { name: req.body.name, password: hashedPassword };
    users.push(user);
    res.status(201).send();
  } catch {
    res.status(500).send();
  }
});

app.post("/login", async (req, res) => {
  const userName = req.body.name;
  const User = users.find((user) => user.name == userName);
  if (User == null) {
    return res.status(400).send("Invalid Username");
  }
  try {
    if (await bcrypt.compare(req.body.password, User.password)) {
      const user = { name: userName };
      const accessToken = generateAcessToken(user);
      const refrsehToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      refrsehTokens.push(refrsehToken);
      res.json({ accessToken: accessToken, refrsehToken: refrsehToken });
    } else {
      res.send("Not Allowed");
    }
  } catch {
    res.status(500).send();
  }
});

function generateAcessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "60s" });
}

app.listen(4000, () => {
  console.log(`server started at 4000`);
});
