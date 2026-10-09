package mx.demo.owasp;

import com.fasterxml.jackson.databind.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/** Verificación contra el proceso real. Modifica solo datos ficticios del laboratorio. */
public final class SmokeCheck {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private static String base;
    private record Reply(int status, JsonNode body) { }

    private static Reply call(String path, Map<String, String> data, String token) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(5));
        if (token != null) request.header("Authorization", "Bearer " + token);
        if (data == null) request.GET();
        else request.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(
                data.entrySet().stream().map(e -> encode(e.getKey()) + "=" + encode(e.getValue())).collect(Collectors.joining("&"))));
        var response = CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofString());
        return new Reply(response.statusCode(), JSON.readTree(response.body()));
    }
    private static Reply get(String path) throws Exception { return call(path, null, null); }
    private static Reply post(String path, Map<String, String> data) throws Exception { return call(path, data, null); }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static void check(boolean success, String label) {
        if (!success) throw new IllegalStateException("FALLO: " + label);
        System.out.println("OK " + label);
    }

    public static void main(String[] args) throws Exception {
        base = args.length == 0 ? "http://127.0.0.1:8080" : args[0];
        check(get("/health").body.path("edition").asText().equals("2025"), "Servidor del laboratorio");
        var session = post("/api/login", Map.of("user", "alice", "password", "demo123"));
        var invoice = call("/api/a01/invoice?id=1002", null, session.body.path("token").asText());
        check(invoice.status == 200 && invoice.body.path("owner").asText().equals("bob")
                && invoice.body.path("viewer").asText().equals("alice"), "A01: factura ajena accesible");

        var debug = get("/api/a02/debug").body;
        check(post("/api/login", Map.of("user", debug.path("adminUser").asText(), "password", debug.path("adminPassword").asText())).status == 200,
                "A02: credenciales expuestas funcionales");

        var original = post("/api/a03/update", Map.of("channel", "trusted"));
        var compromised = post("/api/a03/update", Map.of("channel", "compromised"));
        check(original.body.path("chargedPrice").asInt() == 1000 && compromised.body.path("chargedPrice").asInt() == 1,
                "A03: JAR alterado cambia el precio");

        check(get("/api/a04/hashes").body.path("hashes").path("alice").asText().equals(LabState.md5("demo123")),
                "A04: hash MD5 recuperable");

        check(get("/api/a05/customers?name=Alice").body.path("count").asInt() == 1
                && get("/api/a05/customers?name=" + encode("' OR '1'='1")).body.path("count").asInt() == 3,
                "A05: SQL manipulado devuelve tres clientes");

        int before = get("/api/a06/wallet").body.path("balance").asInt();
        post("/api/a06/redeem", Map.of("coupon", "WELCOME10"));
        check(post("/api/a06/redeem", Map.of("coupon", "WELCOME10")).body.path("balance").asInt() == before + 20,
                "A06: cupon canjeado dos veces");

        var reset = post("/api/a07/reset", Map.of("user", "bob", "token", "reset-bob", "password", "taken123"));
        check(reset.status == 200 && post("/api/login", Map.of("user", "bob", "password", "taken123")).status == 200,
                "A07: recuperacion permite tomar cuenta de Bob");

        String cart = get("/api/a08/cart").body.path("cart").asText();
        String tampered = Base64.getEncoder().encodeToString("{\"sku\":\"LAPTOP-DEMO\",\"quantity\":1,\"unitPrice\":1}".getBytes(StandardCharsets.UTF_8));
        check(post("/api/a08/checkout", Map.of("cart", cart)).body.path("charged").asInt() == 1000
                && post("/api/a08/checkout", Map.of("cart", tampered)).body.path("charged").asInt() == 1,
                "A08: carrito alterado aceptado");

        int failures = get("/api/a09/telemetry").body.path("observedFailures").asInt();
        for (int i = 0; i < 8; i++) {
            if (post("/api/a09/login", Map.of("user", "admin", "password", "wrong")).status != 401)
                throw new IllegalStateException("A09 esperaba rechazo de credenciales");
        }
        var telemetry = get("/api/a09/telemetry").body;
        check(telemetry.path("observedFailures").asInt() == failures + 8
                && telemetry.path("securityEvents").isEmpty() && telemetry.path("alerts").isEmpty(),
                "A09: ocho fallos sin eventos ni alertas");

        var denied = post("/api/a10/pay", Map.of("amount", "1000", "riskService", "online"));
        var approved = post("/api/a10/pay", Map.of("amount", "1000", "riskService", "offline"));
        check(denied.status == 403 && approved.status == 200 && approved.body.path("reason").asText().equals("fail-open"),
                "A10: excepcion aprueba el pago");
        System.out.println("10/10 demostraciones verificadas. Restaurar con: docker compose restart lab");
    }
}
