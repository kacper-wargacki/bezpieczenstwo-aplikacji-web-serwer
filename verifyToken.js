require("dotenv").config();
const jwt = require("jsonwebtoken");
const verifyToken = async (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.username) {
      return { message: "Token verification error", status: 404 };
    } else {
      return { message: "Token OK", status: 200, decoded };
    }
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return { message: "Token expired, please login again", status: 400 };
    } else {
      return { message: error, status: 500 };
    }
  }
};
exports.verifyToken = verifyToken;
