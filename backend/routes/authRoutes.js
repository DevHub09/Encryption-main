import express from "express";
import {
  registerController,
  loginController,
  testController,
  forgotPasswordController,
  hashController
} from "../controllers/authController.js";
import { isAdmin, requireSignIn } from "../middlewares/authMiddleware.js";
// router object(it will be created when you make routes in seperate file)
const router = express.Router();

/*Routing*/

// REGISTER || Method POST
router.post("/register", registerController);
router.post("/hash", hashController);

//LOGIN || Method POST
router.post("/login", loginController);
// FORGOT PASSWORD || Method POST
router.post('/forgot-password',forgotPasswordController)
// Test Route || Method GET
router.get("/test", requireSignIn, isAdmin, testController);

// protected user route auth
router.get("/user-auth", requireSignIn, (req, res) => {
  res.status(200).send({ ok: true });
});
// protected admin route auth
router.get("/admin-auth", requireSignIn, isAdmin,(req, res) => {
  res.status(200).send({ ok: true });
});

export default router;
