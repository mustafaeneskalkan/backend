import express, { Request, Response, NextFunction } from "express";
import UserController from "../controllers/user.js";
import { requireCsrf } from "../middleware/csrf.js";

const router = express.Router();
const { NODE_ENV } = process.env;

// CSRF double-submit protection (no-op for GET/HEAD/OPTIONS)
router.use(requireCsrf);

function getOriginHost(originOrReferer: string | undefined): string | undefined {
  if (!originOrReferer) return undefined;
  try {
    return new URL(originOrReferer).host;
  } catch {
    return undefined;
  }
}

/**
 * Restrict admin auth endpoints to requests coming from the CMS origin.
 * Set `CMS_ORIGIN` (e.g. https://cms.example.com) in env.
 * If not set, this check is a no-op.
 */
function requireCmsOrigin(req: Request, res: Response, next: NextFunction): void {
  const cmsOrigin = process.env.CMS_ORIGIN;
  if (!cmsOrigin) {
    next();
    return;
  }

  const allowedHost = getOriginHost(cmsOrigin);
  const originHost = getOriginHost(req.headers.origin as string | undefined);
  const refererHost = getOriginHost(req.headers.referer as string | undefined);

  const ok = (!!allowedHost && (originHost === allowedHost || refererHost === allowedHost)) || (NODE_ENV === "development");
  if (!ok) {
    res.status(403).json({
      error: "Forbidden",
      code: "CMS_ORIGIN_BLOCKED",
    });
    return;
  }

  next();
}

router.post("/login", requireCmsOrigin, UserController.loginAdmin.bind(UserController));

export default router;
