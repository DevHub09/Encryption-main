import express from "express";
const router = express.Router();
import { isAdmin, requireSignIn } from "../middlewares/authMiddleware.js";
import {
  createCategoryController,
  updateCategoryController,
  categoryController,
  singleCategoryController,
  deleteCategoryController,
} from "../controllers/categoryController.js";

//Todo=> ROUTES

// Create Category Route
router.post(
  "/create-category",
  // requireSignIn,
  // isAdmin,
  createCategoryController
);

// Update Category Route
router.put(
  "/update-category/:id",
  // requireSignIn,
  // isAdmin,
  updateCategoryController
);

// Get All Category Route
router.get("/get-category", categoryController);

// Single Category Route
router.get("/single-category/:slug", singleCategoryController);

// Delete Category Route
router.delete(
  "/delete-category/:id",
  requireSignIn,
  isAdmin,
  deleteCategoryController
);

export default router;
