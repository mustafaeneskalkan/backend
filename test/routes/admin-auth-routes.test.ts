import { jest } from "@jest/globals";
import request from "supertest";

describe("admin auth routes wiring", () => {
  beforeEach(() => {
    jest.resetModules();
    delete process.env.CMS_ORIGIN;
  });

  it("POST /api/admin/auth/login requires CSRF", async () => {
    jest.unstable_mockModule("../../src/controllers/user.js", () => ({
      default: {
        register: (req: any, res: any) => res.status(201).json({ created: true }),
        login: (req: any, res: any) => res.json({ ok: true }),
        refreshToken: (req: any, res: any) => res.json({ ok: true }),
        verifyEmail: (req: any, res: any) => res.json({ ok: true }),
        verifyEmailChange: (req: any, res: any) => res.json({ ok: true }),
        resendVerification: (req: any, res: any) => res.json({ ok: true }),
        logout: (req: any, res: any) => res.json({ ok: true }),
        logoutAll: (req: any, res: any) => res.json({ ok: true }),
        getSession: (req: any, res: any) => res.json({ ok: true }),
        getSessions: (req: any, res: any) => res.json({ ok: true }),
        terminateSession: (req: any, res: any) => res.json({ ok: true }),
        changeEmail: (req: any, res: any) => res.json({ ok: true }),
        changePassword: (req: any, res: any) => res.json({ ok: true }),
        requestPasswordReset: (req: any, res: any) => res.json({ ok: true }),
        resetPassword: (req: any, res: any) => res.json({ ok: true }),
        loginAdmin: async (req: any, res: any) => res.status(200).json({ ok: true }),
      },
    }));

    const { createApp } = await import("../../src/app.js");
    const app = createApp();
    const agent = request.agent(app);

    const missing = await agent.post("/api/admin/auth/login").send({ usernameOrEmail: "a", password: "b" });
    expect(missing.status).toBe(403);
    expect(missing.body?.code).toBe("CSRF_INVALID");

    const csrfRes = await agent.get("/csrf-token");
    const token = csrfRes.body.csrfToken as string;

    const ok = await agent
      .post("/api/admin/auth/login")
      .set("x-xsrf-token", token)
      .send({ usernameOrEmail: "a", password: "b" });
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ ok: true });
  });

  it("blocks login when CMS_ORIGIN is set and Origin mismatches", async () => {
    process.env.CMS_ORIGIN = "https://cms.example.com";

    jest.unstable_mockModule("../../src/controllers/user.js", () => ({
      default: {
        register: (req: any, res: any) => res.status(201).json({ created: true }),
        login: (req: any, res: any) => res.json({ ok: true }),
        refreshToken: (req: any, res: any) => res.json({ ok: true }),
        verifyEmail: (req: any, res: any) => res.json({ ok: true }),
        verifyEmailChange: (req: any, res: any) => res.json({ ok: true }),
        resendVerification: (req: any, res: any) => res.json({ ok: true }),
        logout: (req: any, res: any) => res.json({ ok: true }),
        logoutAll: (req: any, res: any) => res.json({ ok: true }),
        getSession: (req: any, res: any) => res.json({ ok: true }),
        getSessions: (req: any, res: any) => res.json({ ok: true }),
        terminateSession: (req: any, res: any) => res.json({ ok: true }),
        changeEmail: (req: any, res: any) => res.json({ ok: true }),
        changePassword: (req: any, res: any) => res.json({ ok: true }),
        requestPasswordReset: (req: any, res: any) => res.json({ ok: true }),
        resetPassword: (req: any, res: any) => res.json({ ok: true }),
        loginAdmin: async (req: any, res: any) => res.status(200).json({ ok: true }),
      },
    }));

    const { createApp } = await import("../../src/app.js");
    const app = createApp();
    const agent = request.agent(app);

    const csrfRes = await agent.get("/csrf-token");
    const token = csrfRes.body.csrfToken as string;

    const blocked = await agent
      .post("/api/admin/auth/login")
      .set("x-xsrf-token", token)
      .set("origin", "https://not-cms.example.com")
      .send({ usernameOrEmail: "a", password: "b" });
    expect(blocked.status).toBe(403);
    expect(blocked.body?.code).toBe("CMS_ORIGIN_BLOCKED");

    const allowed = await agent
      .post("/api/admin/auth/login")
      .set("x-xsrf-token", token)
      .set("origin", "https://cms.example.com")
      .send({ usernameOrEmail: "a", password: "b" });
    expect(allowed.status).toBe(200);
    expect(allowed.body).toEqual({ ok: true });
  });
});
