const { response } = require("express");
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());
const PORT = process.env.PORT || 5000;

const users = [
  {
    id: 1,
    username: "john",
    password: "John123",
    isAdmin: true,
  },
  {
    id: 2,
    username: "tom",
    password: "Tom123",
    isAdmin: false,
  },
];

let refreshTokens = [];

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
    expiresIn: "20m",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecretKey");
};

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    //Generate an access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    refreshTokens.push(refreshToken);
    res.json({
      ...user,
      accessToken,
      refreshToken,
    });

    res.json(user);
  } else {
    res.status(400).json("Username or password incorrect");
  }
});

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!");
      }
      req.user = user;
      next();
    });
  }
};

app.post("/api/refresh", (req, res) => {
  // take refresh from user
  const refreshToken = req.body.token;

  //send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json("You are not authenticated");
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ message: "Refresh token is not valid" });
  }
  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);
    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
  //if everything is ok,create new access token, refresh token and send to user
});

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted");
  } else {
    res
      .status(403)
      .json({ message: "You are not allowed to delete this user" });
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json({ message: "You logged out successfully." });
});

app.listen(PORT, () => console.log(`Backend server is running at ${PORT}`));
