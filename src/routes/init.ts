import express from "express";
import userRouter from "./user.js";
import adminRouter from "./admin.js";
import adminAuthRouter from "./admin-auth.js";

const router = express.Router();

router.use("/users", userRouter);
router.use("/admin/sessions", adminRouter);
router.use("/admin/auth", adminAuthRouter);

export default router;