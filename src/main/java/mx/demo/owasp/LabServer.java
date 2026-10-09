package mx.demo.owasp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

public final class LabServer implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final LabState state;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newFixedThreadPool(8);

    public LabServer(String host, int port) throws Exception {
        state = new LabState();
        server = HttpServer.create(new InetSocketAddress(host, port), 32);
        server.setExecutor(executor);
        server.createContext("/", this::handle);
    }

    public void start() { server.start(); }
    public int port() { return server.getAddress().getPort(); }
    @Override public void close() { server.stop(0); executor.shutdownNow(); state.close(); }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/") && exchange.getRequestMethod().equals("GET")) {
                try (var resource = getClass().getResourceAsStream("/index.html")) {
                    send(exchange, 200, "text/html; charset=utf-8", Objects.requireNonNull(resource).readAllBytes());
                }
                return;
            }
            Map<String, String> input = decode(exchange.getRequestURI().getRawQuery());
            if (exchange.getRequestMethod().equals("POST")) {
                byte[] body = exchange.getRequestBody().readNBytes(16385);
                if (body.length > 16384) { json(exchange, 413, Map.of("error", "Cuerpo demasiado grande")); return; }
                input.putAll(decode(new String(body, StandardCharsets.UTF_8)));
            }
            route(exchange, exchange.getRequestMethod() + " " + path, input);
        } catch (IllegalArgumentException e) {
            json(exchange, 400, Map.of("error", "Entrada inválida"));
        } catch (Exception e) {
            json(exchange, 500, Map.of("error", "Error del laboratorio", "type", e.getClass().getSimpleName()));
        } finally { exchange.close(); }
    }

    private void route(HttpExchange x, String route, Map<String, String> p) throws Exception {
        switch (route) {
            case "GET /health" -> json(x, 200, Map.of("status", "UP", "edition", "2025"));
            case "POST /api/login" -> login(x, p, false);
            case "GET /api/me" -> {
                String user = currentUser(x);
                json(x, user == null ? 401 : 200, Map.of("user", user == null ? "anonymous" : user));
            }
            case "GET /api/a01/invoice" -> invoice(x, p);
            case "GET /api/a02/debug" -> debug(x);
            case "POST /api/a03/update" -> {
                String channel = p.getOrDefault("channel", "trusted");
                json(x, 200, Map.of("component", "vendor.PriceRule", "channel", channel,
                        "catalogPrice", 1000, "chargedPrice", SupplyChain.quote(channel, 1000), "signatureVerified", false));
            }
            case "GET /api/a04/hashes" -> json(x, 200, Map.of("algorithm", "MD5", "salt", "", "hashes", state.passwordHashes));
            case "GET /api/a05/customers" -> customers(x, p);
            case "GET /api/a06/wallet" -> json(x, 200, Map.of("balance", state.wallet.get()));
            case "POST /api/a06/redeem" -> redeem(x, p);
            case "POST /api/a07/reset" -> resetPassword(x, p);
            case "GET /api/a08/cart" -> {
                String cart = JSON.writeValueAsString(Map.of("sku", "LAPTOP-DEMO", "quantity", 1, "unitPrice", 1000));
                json(x, 200, Map.of("cart", Base64.getEncoder().encodeToString(cart.getBytes(StandardCharsets.UTF_8))));
            }
            case "POST /api/a08/checkout" -> checkout(x, p);
            case "POST /api/a09/login" -> login(x, p, true);
            case "GET /api/a09/telemetry" -> json(x, 200, Map.of("observedFailures", state.observedLoginFailures.get(),
                    "securityEvents", List.of(), "alerts", List.of()));
            case "POST /api/a10/pay" -> pay(x, p);
            default -> json(x, 404, Map.of("error", "Ruta o método no disponible"));
        }
    }

    private void login(HttpExchange x, Map<String, String> p, boolean silent) throws Exception {
        String user = p.getOrDefault("user", "");
        String hash = LabState.md5(p.getOrDefault("password", ""));
        if (!hash.equals(state.passwordHashes.get(user))) {
            // VULNERABLE A09: no se emite evento de seguridad ni alerta.
            // El contador es instrumentación didáctica, no un registro de auditoría.
            if (silent) state.observedLoginFailures.incrementAndGet();
            json(x, 401, Map.of("error", "Credenciales inválidas")); return;
        }
        String session = UUID.randomUUID().toString();
        state.sessions.put(session, user);
        x.getResponseHeaders().add("Set-Cookie", "LABSESSION=" + session + "; Path=/; HttpOnly; SameSite=Lax");
        json(x, 200, Map.of("user", user, "token", session));
    }

    private String currentUser(HttpExchange x) {
        String auth = x.getRequestHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) return state.sessions.get(auth.substring(7));
        String cookies = x.getRequestHeaders().getFirst("Cookie");
        if (cookies != null) for (String cookie : cookies.split(";")) {
            String[] pair = cookie.trim().split("=", 2);
            if (pair.length == 2 && pair[0].equals("LABSESSION")) return state.sessions.get(pair[1]);
        }
        return null;
    }

    private void invoice(HttpExchange x, Map<String, String> p) throws IOException {
        String viewer = currentUser(x);
        if (viewer == null) { json(x, 401, Map.of("error", "Inicia sesión")); return; }
        String id = p.getOrDefault("id", "1001");
        if (!Set.of("1001", "1002").contains(id)) { json(x, 404, Map.of("error", "Factura desconocida")); return; }
        String owner = id.equals("1001") ? "alice" : "bob";
        // VULNERABLE A01: existe autenticación, pero no autorización por propietario.
        json(x, 200, Map.of("id", id, "owner", owner, "viewer", viewer, "total", 1500, "address", "Domicilio ficticio de " + owner));
    }

    private void debug(HttpExchange x) throws IOException {
        // VULNERABLE A02: diagnóstico habilitado y público. Todos los secretos son ficticios.
        x.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        json(x, 200, Map.of("debug", true, "database", state.databaseUrl,
                "paymentApiKey", "DEMO-NOT-A-REAL-SECRET", "adminUser", "admin", "adminPassword", "admin123"));
    }

    private void customers(HttpExchange x, Map<String, String> p) throws Exception {
        // VULNERABLE A05: concatenación de entrada en una consulta SQL ejecutada en H2.
        String query = "SELECT id, name, private_note FROM customers WHERE name = '" + p.getOrDefault("name", "Alice") + "'";
        var rows = new ArrayList<Map<String, Object>>();
        try (var connection = DriverManager.getConnection(state.databaseUrl);
             var statement = connection.createStatement(); var results = statement.executeQuery(query)) {
            while (results.next()) rows.add(Map.of("id", results.getInt(1), "name", results.getString(2), "privateNote", results.getString(3)));
        }
        json(x, 200, Map.of("query", query, "count", rows.size(), "customers", rows));
    }

    private void redeem(HttpExchange x, Map<String, String> p) throws IOException {
        if (!"WELCOME10".equals(p.get("coupon"))) { json(x, 400, Map.of("error", "Cupón inválido")); return; }
        // VULNERABLE A06: el negocio define un solo uso, pero el diseño no registra el canje.
        json(x, 200, Map.of("balance", state.wallet.addAndGet(10), "credit", 10));
    }

    private void resetPassword(HttpExchange x, Map<String, String> p) throws Exception {
        String user = p.getOrDefault("user", "");
        // VULNERABLE A07: token predecible, sin expiración ni consumo de un solo uso.
        if (!state.passwordHashes.containsKey(user) || !p.getOrDefault("token", "").equals("reset-" + user)) {
            json(x, 403, Map.of("error", "Token inválido")); return;
        }
        state.passwordHashes.put(user, LabState.md5(p.getOrDefault("password", "changed123")));
        json(x, 200, Map.of("reset", true, "user", user));
    }

    private void checkout(HttpExchange x, Map<String, String> p) throws Exception {
        var cart = JSON.readTree(Base64.getDecoder().decode(p.getOrDefault("cart", "")));
        // VULNERABLE A08: Base64 no garantiza integridad; se confía en el precio del cliente.
        int total = cart.path("unitPrice").asInt() * cart.path("quantity").asInt();
        json(x, 200, Map.of("sku", cart.path("sku").asText(), "charged", total, "integrityVerified", false));
    }

    private void pay(HttpExchange x, Map<String, String> p) throws IOException {
        int amount = Integer.parseInt(p.getOrDefault("amount", "1000"));
        boolean approved;
        String reason;
        try {
            // Interruptor local de fallos para probar una caída del servicio antifraude.
            if ("offline".equals(p.get("riskService"))) throw new IllegalStateException("Antifraude no disponible");
            approved = amount <= 500;
            reason = approved ? "risk-accepted" : "risk-rejected";
        } catch (IllegalStateException exception) {
            // VULNERABLE A10: se permite el pago cuando falla una dependencia de seguridad.
            approved = true;
            reason = "fail-open";
        }
        int count = approved ? state.orders.incrementAndGet() : state.orders.get();
        json(x, approved ? 200 : 403, Map.of("approved", approved, "reason", reason, "amount", amount, "completedOrders", count));
    }

    private static Map<String, String> decode(String encoded) {
        var result = new HashMap<String, String>();
        if (encoded != null && !encoded.isBlank()) for (String item : encoded.split("&")) {
            String[] pair = item.split("=", 2);
            result.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                    pair.length > 1 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "");
        }
        return result;
    }

    private static void json(HttpExchange x, int status, Object value) throws IOException {
        send(x, status, "application/json; charset=utf-8", JSON.writeValueAsBytes(value));
    }

    private static void send(HttpExchange x, int status, String type, byte[] body) throws IOException {
        x.getResponseHeaders().set("Content-Type", type);
        x.getResponseHeaders().set("Cache-Control", "no-store");
        x.sendResponseHeaders(status, body.length);
        x.getResponseBody().write(body);
    }
}
