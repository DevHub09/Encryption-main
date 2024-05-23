import { comparePassword, hashPassword } from "../helpers/authHelper.js";
import userModel from "../models/userModel.js";
import Jwt from "jsonwebtoken";

//! Register Controller

export const registerController = async (req, res) => {
  try {
    const { name, email, password, secret_word } = req.body;
    // validations
    if (!name) {
      res.send({ message: "Name is required" });
    }
    if (!email) {
      res.send({ message: "Email is required" });
    }
    if (!password) {
      res.send({ message: "Password is required" });
    }

    if (!secret_word) {
      res.send({ message: "secret_word is required" });
    }
    // Checking the users
    const existingUser = await userModel.findOne({ email });
    // Existing Users
    if (existingUser) {
      return res.status(200).send({
        success: false,
        message: "User Already registered please login",
      });
    }
    // Register User
    const hashedPassword = await hashPassword(password);
    // Saving the Password
    const user = await new userModel({
      name,
      email,

      password: hashedPassword,
      secret_word,
    }).save();
    res.status(201).send({
      success: true,
      message: "User registered Successfully",
      user,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in Registration",
      error,
    });
  }
};
export const hashController = async (req, res) => {
  const { text } = req.body;
  if (!text) {
      return res.status(400).send({ error: 'Text is required' });
  }

  try {
      const saltRounds = 10;
      const hashedText = await bcrypt.hash(text, saltRounds);
      res.send({ text, hashedText });
  } catch (error) {
      res.status(500).send({ error: 'Error hashing text' });
  }
};

//! Login Controller
export const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
    // validations
    if (!email || !password) {
      return res.status(404).send({
        success: false,
        message: "Invalid email or password",
      });
    }
    // Checking the User
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Email is not registerd",
      });
    }
    // Encrypting the Password
    const match = await comparePassword(password, user.password);
    if (!match) {
      return res.status(200).send({
        success: false,
        message: "Invalid Password",
      });
    }
    // !Creating a token(token provides users with access to protected pages and resources for a limited period of time without having to re-enter their username and password.)
    const token = await Jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.status(200).send({
      success: true,
      message: "Login Successfully",
      user: {
        name: user.name,  
        email: user.email,
        role: user.role,
      },
      token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in Login",
      error,
    });
  }
};
// Forgot Password Controller
export const forgotPasswordController = async (req, res) => {
  try {
    const { email, secret_word, newPassword } = req.body;
    // validations
    if (!email) {
      res.status(400).send({ message: "Email is required" });
    }
    if (!secret_word) {
      res.status(400).send({ message: "secret_word is required" });
    }
    if (!newPassword) {
      res.status(400).send({ message: "New Password is required" });
    }
    // checking the user
    const user = await userModel.findOne({ email, secret_word });
    // validation
    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Incorrect Email or Answer",
      });
    }
    const hashed = await hashPassword(newPassword);
    await userModel.findByIdAndUpdate(user._id, { password: hashed });
    res.status(200).send({
      success: true,
      message: "Password reset Successfully",
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Something wents wrong",
      error,
    });
  }
};
// Test Controller
export const testController = (req, res) => {
  res.send("protected route");
};
