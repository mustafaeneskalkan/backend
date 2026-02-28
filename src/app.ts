import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import initRouter from "./routes/init.js";
import { requestIdMiddleware } from "./middleware/request-id.js";
import { issueCsrfToken } from "./middleware/csrf.js";

export function createApp(): express.Express {
  const app = express();

  const NODE_ENV = process.env.NODE_ENV || "development";
  const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:3000";

  // Basic middleware
  app.use(requestIdMiddleware);
  app.use(helmet());
  app.use(morgan("dev"));
  app.use(express.json());
  // app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  // CORS setup - allow credentials and specific origin from .env
  app.use(
    cors({
      origin: CORS_ORIGIN,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      credentials: true,
    }),
  );

  // Expose a route to get a CSRF token (double-submit cookie)
  app.get("/csrf-token", issueCsrfToken);

  // Mount routers (protected routes should use csrfProtection as needed)
  app.use("/api", initRouter);

  // Basic health check
  app.get("/health", (req: express.Request, res: express.Response) =>
    res.json({ status: "ok", env: NODE_ENV }),
  );

  // Global error handler
  app.use(
    (
      err: any,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ) => {
      console.error(err);
      res
        .status(err?.status || 500)
        .json({ error: err?.message || "Internal Server Error" });
    },
  );

  return app;
}
