import express from "express";
import colors from "colors";
import dotenv from "dotenv";
import morgan from "morgan";
import connectDb from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import categoryRoutes from "./routes/categoryRoutes.js";
import productRoutes from "./routes/productRoutes.js";
import cors from "cors";
// configuring env
dotenv.config();
// Database Config
connectDb();
// Rest Object
const app = express();

// middlewares
app.use(cors());
app.use(express.json());
app.use(morgan("dev")); //TODO morgan help in http requests like post get nd many other things etc

// Routes
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/category", categoryRoutes);
app.use("/api/v1/product", productRoutes);

/* 

Rest API
 app.get("/",(req,res)=>{
    res.send({
        message:"Welcome to ecommerce app"
    })
 })
 
 */

// PORT
const PORT = process.env.PORT;

// run listner
app.listen(PORT, () => {
  console.log(
    `Server is running on ${process.env.DEV_MODE} mode at port  ${PORT}`.bgWhite
      .black
  );
});
