import mongoose from "mongoose";

//Creating a database Schema

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true, //unique means with one email id only one user can login
    },
    password: {
      type: String,
      required: true,
    },

    secret_word: {
      type: String,
      required: true,
    },
    role: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);
export default mongoose.model("users", userSchema);
