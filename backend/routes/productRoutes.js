import express from "express";
import { isAdmin, requireSignIn } from "../middlewares/authMiddleware.js";
import {
  createProductController,
  getProductController,
  getSingleProductController,
  getPhotoController,
  updateProductController,
  deleteProductController,
  productFiltersController,
} from "../controllers/productController.js";
import formidable from "express-formidable";

//TODO Routes

const router = express.Router();

// Create Product Route

router.post(
  "/create-product",
  requireSignIn,
  isAdmin,
  formidable(),
  createProductController
);
// Update Product Route

router.put(
  "/update-product/:pid",
  requireSignIn,
  isAdmin,
  formidable(),
  updateProductController
);

// Get Product Product Route

router.get("/get-product", getProductController);

// Get Single Product Route

router.get("/get-product/:slug", getSingleProductController);

// Get photo Route

router.get("/product-photo/:pid", getPhotoController);

// Delete Product Route

router.delete("/delete-product/:pid", deleteProductController);

// Filter Product Route
router.post("/product-filter", productFiltersController);

export default router;
