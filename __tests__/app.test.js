"use strict";

/**
 * Test suite for the Express app focused on Software Quality goals.
 *
 * Nota importante (QS):
 * - Estes testes são desenhados para serem determinísticos e não dependerem de DB/rede.
 * - Usamos mocks para isolar o comportamento do servidor (rotas, middleware, sessão, contratos HTTP).
 * - Há dois tipos de testes:
 *   1) "Caracterização": descrevem o comportamento atual/observável (devem passar).
 *   2) "Objetivos de Qualidade": descrevem o comportamento desejável (podem estar em skip como "KNOWN DEFECT").
 */

const request = require("supertest");

// ---------------------------
// Mocks dos handlers (evitam MySQL real)
// ---------------------------

// Auth: permite simular login bem-sucedido e falhado sem DB.
jest.mock("../scripts/authentication-handlers.js", () => ({
    login: (req, res) => {
        const { login, password } = req.body || {};

        // Simulação de "credenciais inválidas"
        if (!login || !password || password === "wrong") {
            return res.sendStatus(401);
        }

        // Simulação de "erro interno"
        if (login === "trigger-500") {
            return res.sendStatus(500);
        }

        // Simulação de login OK (define sessão)
        req.session.User = { id: 1, userName: "test.user" };
        return res.status(200).json({ id: 1, userName: "test.user" });
    },
}));

// Clients: respostas previsíveis + um endpoint que retorna 400 se faltar o "name" (apenas no mock).
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

// Users: mantém envelopes consistentes.
jest.mock("../scripts/users-handlers.js", () => ({
    getUsers: (req, res) => res.status(200).json({ users: [{ id: 20, userName: "u1" }] }),
    getPageSettings: (req, res) => res.status(200).json({ pageSettings: [[]] }),
    createUser: (req, res) => res.sendStatus(200),
    editUser: (req, res) => res.status(200).json({ success: true }),
    deleteUser: (req, res) => res.sendStatus(200),
}));

// Jobs: respostas previsíveis.
jest.mock("../scripts/jobs-handlers.js", () => ({
    getListJobs: (req, res) => res.status(200).json({ jobs: [] }),
    createJob: (req, res) => res.sendStatus(200),
    getUserInfoInitState: (req, res) => res.status(200).json({}),
    reopenJob: (req, res) => res.sendStatus(200),
    editJobInfo: (req, res) => res.sendStatus(200),
    editOrderPriority: (req, res) => res.sendStatus(200),
}));

// Messaging: respostas previsíveis.
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

describe("Testes de caracterização (comportamento atual observável)", () => {
    test(
        // Objetivo: caracterizar o controlo de acesso quando NÃO há sessão.
        // O que acontece: pedidos para páginas raiz (top-level) são redirecionados para /login.html.
        "CARACT | GET / redireciona para /login.html quando não existe sessão",
        async () => {
            const res = await request(app).get("/");
            expect(res.status).toBe(302);
            expect(res.headers.location).toBe("/login.html");
        }
    );

    test(
        // Objetivo: caracterizar o comportamento do middleware para páginas protegidas (top-level).
        // O que acontece: /home.html é redirecionado para /login.html quando o utilizador não está autenticado.
        "CARACT | GET /home.html redireciona para /login.html quando não existe sessão",
        async () => {
            const res = await request(app).get("/home.html");
            expect(res.status).toBe(302);
            expect(res.headers.location).toBe("/login.html");
        }
    );

    test(
        // Objetivo: caracterizar o acesso à página de login sem autenticação.
        // O que acontece: /login.html é servido (200) sem necessidade de sessão.
        "CARACT | GET /login.html é acessível sem sessão",
        async () => {
            const res = await request(app).get("/login.html");
            expect(res.status).toBe(200);
            expect(res.headers["content-type"]).toMatch(/text\/html/i);
        }
    );

    test(
        // Objetivo: caracterizar o efeito do login na sessão.
        // O que acontece: após login, o acesso a /login.html (ou /) é redirecionado para /home.html.
        "CARACT | POST /api/login cria sessão e depois GET /login.html redireciona para /home.html",
        async () => {
            const agent = request.agent(app);

            const loginRes = await agent.post("/api/login").send({ login: "valid", password: "valid" });
            expect(loginRes.status).toBe(200);
            expect(loginRes.headers["content-type"]).toMatch(/application\/json/i);
            expect(loginRes.body).toMatchObject({ id: 1, userName: "test.user" });

            const res2 = await agent.get("/login.html");
            expect(res2.status).toBe(302);
            expect(res2.headers.location).toBe("/home.html");
        }
    );

    test(
        // Objetivo: caracterizar o comportamento do sistema com sessão válida ao pedir páginas estáticas.
        // O que acontece: /home.html é servido com 200 quando existe sessão.
        "CARACT | Com sessão, GET /home.html devolve 200 (ficheiro estático)",
        async () => {
            const agent = request.agent(app);
            await loginAsValidUser(agent);

            const res = await agent.get("/home.html");
            expect(res.status).toBe(200);
            expect(res.headers["content-type"]).toMatch(/text\/html/i);
        }
    );

    test(
        // Objetivo: caracterizar o comportamento com sessão para página inexistente (top-level).
        // O que acontece: se o ficheiro não existir, o sistema redireciona para /login.html (mesmo estando autenticado).
        "CARACT | Com sessão, GET /ficheiro-inexistente.html redireciona para /login.html",
        async () => {
            const agent = request.agent(app);
            await loginAsValidUser(agent);

            const res = await agent.get("/ficheiro-inexistente.html");
            expect(res.status).toBe(302);
            expect(res.headers.location).toBe("/login.html");
        }
    );

    test(
        // Objetivo: caracterizar o bypass do middleware para caminhos "profundos" (mais do que um '/').
        // O que acontece: o middleware ignora este pedido (não redireciona), e o resultado tende a ser 404.
        "CARACT | GET /scripts/nao-existe.js não deve redirecionar (bypass do guard para paths profundos)",
        async () => {
            const res = await request(app).get("/scripts/nao-existe.js");
            expect(res.status).not.toBe(302);
            expect([404, 200]).toContain(res.status);
        }
    );

    test(
        // Objetivo: caracterizar o logout como operação idempotente.
        // O que acontece: /api/logout responde 200 mesmo sem sessão.
        "CARACT | GET /api/logout devolve 200 mesmo sem sessão",
        async () => {
            const res = await request(app).get("/api/logout");
            expect(res.status).toBe(200);
        }
    );

    test(
        // Objetivo: caracterizar o efeito do logout numa sessão previamente autenticada.
        // O que acontece: depois de logout, pedidos a páginas protegidas voltam a redirecionar para /login.html.
        "CARACT | Depois de logout, GET /home.html volta a redirecionar para /login.html",
        async () => {
            const agent = request.agent(app);
            await loginAsValidUser(agent);

            const logoutRes = await agent.get("/api/logout");
            expect(logoutRes.status).toBe(200);

            const res2 = await agent.get("/home.html");
            expect(res2.status).toBe(302);
            expect(res2.headers.location).toBe("/login.html");
        }
    );

    test(
        // Objetivo: caracterizar o contrato básico de um endpoint API (formato JSON).
        // O que acontece: /api/getClients devolve 200 e JSON com a chave 'clients'.
        "CARACT | GET /api/getClients devolve JSON com envelope { clients: [...] }",
        async () => {
            const res = await request(app).get("/api/getClients");
            expect(res.status).toBe(200);
            expect(res.headers["content-type"]).toMatch(/application\/json/i);
            expect(res.body).toHaveProperty("clients");
            expect(Array.isArray(res.body.clients)).toBe(true);
        }
    );

    test(
        // Objetivo: caracterizar um comportamento atual potencialmente problemático: API acessível sem sessão.
        // O que acontece: /api/getUsers está acessível sem login (isto pode ser um problema de segurança).
        "CARACT | GET /api/getUsers está acessível sem sessão (comportamento atual)",
        async () => {
            const res = await request(app).get("/api/getUsers");
            expect(res.status).toBe(200);
            expect(res.headers["content-type"]).toMatch(/application\/json/i);
            expect(res.body).toHaveProperty("users");
        }
    );

    test(
        // Objetivo: caracterizar falhas de autenticação (credenciais inválidas).
        // O que acontece: quando o handler devolve 401, a app propaga 401.
        "CARACT | POST /api/login com password inválida devolve 401",
        async () => {
            const res = await request(app).post("/api/login").send({ login: "valid", password: "wrong" });
            expect(res.status).toBe(401);
        }
    );

    test(
        // Objetivo: caracterizar falhas internas no login.
        // O que acontece: quando o handler devolve 500, a app propaga 500.
        "CARACT | POST /api/login quando ocorre erro interno devolve 500",
        async () => {
            const res = await request(app).post("/api/login").send({ login: "trigger-500", password: "valid" });
            expect(res.status).toBe(500);
        }
    );

    test(
        // Objetivo: caracterizar parsing de JSON (body-parser) quando o cliente envia JSON inválido.
        // O que acontece: Express/body-parser tende a responder 400 Bad Request para JSON malformado.
        "CARACT | POST /api/createClient com JSON inválido devolve 400 (parser)",
        async () => {
            const res = await request(app)
                .post("/api/createClient")
                .set("Content-Type", "application/json")
                .send("{ invalid json }"); // corpo inválido de propósito
            expect(res.status).toBe(400);
        }
    );

    test(
        // Objetivo: caracterizar o comportamento do endpoint de criação quando faltam campos obrigatórios (no nosso mock).
        // O que acontece: se faltar 'name', o handler (mock) devolve 400.
        "CARACT | POST /api/createClient sem 'name' devolve 400 (validação no mock)",
        async () => {
            const res = await request(app)
                .post("/api/createClient")
                .send({ address: "X", postCode: "0000-000", email: "a@b.com", nif: "123" });
            expect(res.status).toBe(400);
        }
    );
});

describe("Testes de objetivos de qualidade (requisitos desejáveis) - marcados como KNOWN DEFECT", () => {
    test.skip(
        // Objetivo: reforçar segurança (API não deve ser pública).
        // O que deveria acontecer: endpoints /api/* deveriam exigir sessão e devolver 401/403 sem autenticação.
        // O que acontece atualmente: o middleware ignora paths com mais de um '/', logo /api/* fica acessível.
        "QUALIDADE | API deveria exigir autenticação: GET /api/getClients deveria devolver 401/403 sem sessão (KNOWN DEFECT)",
        async () => {
            const res = await request(app).get("/api/getClients");
            expect([401, 403]).toContain(res.status);
        }
    );

    test.skip(
        // Objetivo: consistência de respostas de erro (contrato de API).
        // O que deveria acontecer: em falha de login, devolver JSON (ex.: { error: ... }) com Content-Type JSON.
        // O que acontece atualmente: a resposta é apenas status code (401) sem JSON.
        "QUALIDADE | Login inválido deveria devolver JSON de erro (KNOWN DEFECT)",
        async () => {
            const res = await request(app).post("/api/login").send({ login: "valid", password: "wrong" });
            expect(res.status).toBe(401);
            expect(res.headers["content-type"]).toMatch(/application\/json/i);
            expect(res.body).toHaveProperty("error");
        }
    );

    test.skip(
        // Objetivo: validação de input no servidor (defesa contra dados incompletos).
        // O que deveria acontecer: POST /api/createClient sem 'name' deveria ser 400 SEM depender do mock.
        // Nota: este teste está em skip porque a validação real não existe no código base (KNOWN DEFECT).
        "QUALIDADE | createClient deveria validar obrigatórios no servidor (KNOWN DEFECT)",
        async () => {
            const res = await request(app).post("/api/createClient").send({});
            expect(res.status).toBe(400);
        }
    );

    test.skip(
        // Objetivo: controlo de acesso consistente a recursos estáticos.
        // O que deveria acontecer: utilizador autenticado não deveria ser enviado para /login.html por pedir ficheiro inexistente;
        // deveria receber 404 (ou uma página de erro) mantendo contexto de sessão.
        // O que acontece atualmente: redireciona para /login.html.
        "QUALIDADE | Com sessão, ficheiro inexistente deveria devolver 404 em vez de redirecionar para login (KNOWN DEFECT)",
        async () => {
            const agent = request.agent(app);
            await loginAsValidUser(agent);

            const res = await agent.get("/ficheiro-inexistente.html");
            expect(res.status).toBe(404);
        }
    );
});