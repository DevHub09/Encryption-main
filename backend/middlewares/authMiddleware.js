import Jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
// !Protected Routes Token based
//Todo=> Remember token is always in header

// user access
export const requireSignIn = async (req, res, next) => {
  try {
    const decode = Jwt.verify(
      req.headers.authorization,
      process.env.JWT_SECRET
    );
    req.user = decode;
    next();
  } catch (error) {
    console.log(error);
  }
};

// admin access
export const isAdmin = async (req, res, next) => {
  try {
    const user = await userModel.findById(req.user._id);
    if (user.role !== 1) {
      return res.status(401).send({
        success: false,
        message: "Unauthorized access",
      });
    } else {
      next();
    }
  } catch (error) {
    console.log(error);
    res.status(404).send({
      success: false,
      error,
      message: "Error in admin middleware",
    });
  }
};
