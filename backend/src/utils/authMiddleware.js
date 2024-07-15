const jwt = require("jsonwebtoken");
const { secretKey } = require("../configuration/jwtConfig");

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized: Missing token!" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized: Token not found" });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden: Invalid Token" });
    }
    req.user = user; // Attach the decoded user object to the request
    next();
  });
}

function verifyToken(token) {
  const decoded = jwt.verify(token, secretKey);
}

module.exports = { authenticateToken, verifyToken };
