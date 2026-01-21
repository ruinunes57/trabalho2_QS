"use strict";

/**
 * Suite de testes (Jest + Supertest) ao servidor Express.
 * Objetivo: validar rotas, middleware de autenticação/sessão e contratos HTTP,
 * usando mocks para evitar dependências externas (ex.: base de dados).
 */

const request = require("supertest");

// ---------------------------
// Mocks dos handlers (evitam dependências externas)
// ---------------------------

jest.mock("../scripts/authentication-handlers.js", () => ({
    login: (req, res) => {
        const { login, password } = req.body || {};

        if (!login || !password || password === "wrong") {
            return res.sendStatus(401);
        }

        if (login === "trigger-500") {
            return res.sendStatus(500);
        }

        req.session.User = { id: 1, userName: "test.user" };
        return res.status(200).json({ id: 1, userName: "test.user" });
    },
}));

jest.mock("../scripts/clients-handlers.js", () => ({
    getClients: (req, res) => res.status(200).json({ clients: [{ id: 10, name: "Client A" }] }),

    createClient: (req, res) => {
        if (!req.body || !req.body.name) return res.sendStatus(400);
        return res.sendStatus(200);
    },

    editClient: (req, res) => {
        if (!req.body || !req.body.id) return res.status(200).json({ success: false });
        return res.status(200).json({ success: true });
    },

    deleteClient: (req, res) => {
        if (!req.params || !req.params.id) return res.sendStatus(400);
        return res.sendStatus(200);
    },
}));

jest.mock("../scripts/users-handlers.js", () => ({
    getUsers: (req, res) => res.status(200).json({ users: [{ id: 20, userName: "u1" }] }),
    getPageSettings: (req, res) => res.status(200).json({ pageSettings: [[]] }),
    createUser: (req, res) => res.sendStatus(200),
    editUser: (req, res) => res.status(200).json({ success: true }),
    deleteUser: (req, res) => res.sendStatus(200),
}));

jest.mock("../scripts/jobs-handlers.js", () => ({
    getListJobs: (req, res) => res.status(200).json({ jobs: [] }),
    createJob: (req, res) => res.sendStatus(200),
    getUserInfoInitState: (req, res) => res.status(200).json({}),
    reopenJob: (req, res) => res.sendStatus(200),
    editJobInfo: (req, res) => res.sendStatus(200),
    editOrderPriority: (req, res) => res.sendStatus(200),
}));

jest.mock("../scripts/messaging-handlers.js", () => ({
    loadWebSocketSettings: (req, res) => res.status(200).json({}),
    loadWebSocketMessages: (req, res) => res.status(200).json({ messages: [] }),
    messagingInsertNew: (message, cb) => cb(1),
}));

const app = require("../app");

// Helpers
async function loginAsValidUser(agent) {
    return agent.post("/api/login").send({ login: "valid", password: "valid" });
}

describe("Testes de caracterização (15 mais importantes)", () => {
    // Verifica que a raiz (/) está protegida: sem sessão, o utilizador é redireccionado para a página de login.
    test("CARACT | GET / redireciona para /login.html quando não existe sessão", async () => {
        const res = await request(app).get("/");
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe("/login.html");
    });

    // Garante que uma página típica “protegida” (/home.html) não é acessível sem autenticação.
    test("CARACT | GET /home.html redireciona para /login.html quando não existe sessão", async () => {
        const res = await request(app).get("/home.html");
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe("/login.html");
    });

    // Confirma que a página de login é pública e é servida como HTML (não exige sessão).
    test("CARACT | GET /login.html é acessível sem sessão", async () => {
        const res = await request(app).get("/login.html");
        expect(res.status).toBe(200);
        expect(res.headers["content-type"]).toMatch(/text\/html/i);
    });

    // Valida o fluxo base de autenticação: login cria sessão e, depois disso, /login.html redirecciona para /home.html.
    test("CARACT | POST /api/login cria sessão e depois GET /login.html redireciona para /home.html", async () => {
        const agent = request.agent(app);

        const loginRes = await agent.post("/api/login").send({ login: "valid", password: "valid" });
        expect(loginRes.status).toBe(200);
        expect(loginRes.headers["content-type"]).toMatch(/application\/json/i);
        expect(loginRes.body).toMatchObject({ id: 1, userName: "test.user" });

        const res2 = await agent.get("/login.html");
        expect(res2.status).toBe(302);
        expect(res2.headers.location).toBe("/home.html");
    });

    // Confirma que, com sessão válida, o utilizador consegue aceder a /home.html e recebe HTML.
    test("CARACT | Com sessão, GET /home.html devolve 200 (ficheiro estático)", async () => {
        const agent = request.agent(app);
        await loginAsValidUser(agent);

        const res = await agent.get("/home.html");
        expect(res.status).toBe(200);
        expect(res.headers["content-type"]).toMatch(/text\/html/i);
    });

    // Caracteriza o comportamento do “guard”: paths mais profundos (ex.: /scripts/...) não são redireccionados.
    test("CARACT | GET /scripts/nao-existe.js não deve redirecionar (bypass do guard para paths profundos)", async () => {
        const res = await request(app).get("/scripts/nao-existe.js");
        expect(res.status).not.toBe(302);
        expect([404, 200]).toContain(res.status);
    });

    // Verifica que o logout remove o efeito da sessão: após logout, /home.html volta a exigir autenticação.
    test("CARACT | Depois de logout, GET /home.html volta a redirecionar para /login.html", async () => {
        const agent = request.agent(app);
        await loginAsValidUser(agent);

        const logoutRes = await agent.get("/api/logout");
        expect(logoutRes.status).toBe(200);

        const res2 = await agent.get("/home.html");
        expect(res2.status).toBe(302);
        expect(res2.headers.location).toBe("/login.html");
    });

    // Garante o contrato do endpoint de clientes: responde 200 e devolve JSON com a chave 'clients' (array).
    test("CARACT | GET /api/getClients devolve JSON com envelope { clients: [...] }", async () => {
        const res = await request(app).get("/api/getClients");
        expect(res.status).toBe(200);
        expect(res.headers["content-type"]).toMatch(/application\/json/i);
        expect(res.body).toHaveProperty("clients");
        expect(Array.isArray(res.body.clients)).toBe(true);
    });

    // Verifica o endpoint de edição de cliente (caso de sucesso) quando é enviado um ID válido.
    test("CARACT | PUT /api/editClient devolve sucesso quando ID é fornecido", async () => {
        const res = await request(app).put("/api/editClient").send({ id: 10, name: "New Name" });
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
    });

    // Caracteriza um comportamento actual relevante: o endpoint /api/getUsers está acessível sem sessão.
    test("CARACT | GET /api/getUsers está acessível sem sessão (comportamento actual)", async () => {
        const res = await request(app).get("/api/getUsers");
        expect(res.status).toBe(200);
        expect(res.headers["content-type"]).toMatch(/application\/json/i);
        expect(res.body).toHaveProperty("users");
    });

    // Verifica o contrato do endpoint de configurações: devolve JSON com a chave 'pageSettings'.
    test("CARACT | GET /api/getPageSettings devolve configurações", async () => {
        const res = await request(app).get("/api/getPageSettings");
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty("pageSettings");
    });

    // Garante o contrato do endpoint de listagem de jobs: devolve JSON com a chave 'jobs' (mesmo que vazio).
    test("CARACT | POST /api/getListJobs devolve lista vazia (mock)", async () => {
        const res = await request(app).post("/api/getListJobs");
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty("jobs");
    });

    // Verifica o contrato do endpoint de mensagens: devolve JSON com a chave 'messages'.
    test("CARACT | POST /api/loadWebSocketMessages devolve mensagens", async () => {
        const res = await request(app).post("/api/loadWebSocketMessages");
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty("messages");
    });

    // Valida o tratamento de credenciais inválidas no login: a API deve devolver 401.
    test("CARACT | POST /api/login com password inválida devolve 401", async () => {
        const res = await request(app).post("/api/login").send({ login: "valid", password: "wrong" });
        expect(res.status).toBe(401);
    });

    // Confirma que o servidor rejeita JSON malformado no body (o parser deve responder 400).
    test("CARACT | POST /api/createClient com JSON inválido devolve 400 (parser)", async () => {
        const res = await request(app)
            .post("/api/createClient")
            .set("Content-Type", "application/json")
            .send("{ invalid json }");
        expect(res.status).toBe(400);
    });
});
