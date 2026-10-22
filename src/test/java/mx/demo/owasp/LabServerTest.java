/*package mx.demo.owasp;

import com.fasterxml.jackson.databind.*;
import org.junit.jupiter.api.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import static org.junit.jupiter.api.Assertions.*;

// Estas pruebas confirman vulnerabilidades intencionales; no certifican seguridad.
class LabServerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private LabServer server;
    private HttpClient client;
    private String base;
    record Reply(int status, JsonNode json) { }

    @BeforeEach void start() throws Exception {
        server = new LabServer("127.0.0.1", 0);
        server.start();
        base = "http://127.0.0.1:" + server.port();
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    }
    @AfterEach void stop() { server.close(); }

    private Reply call(String method, String path, Map<String, String> form, String token) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(5));
        if (token != null) request.header("Authorization", "Bearer " + token);
        if (method.equals("POST")) request.header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form.entrySet().stream()
                        .map(e -> encode(e.getKey()) + "=" + encode(e.getValue())).collect(Collectors.joining("&"))));
        else request.GET();
        var response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        return new Reply(response.statusCode(), JSON.readTree(response.body()));
    }
    private Reply get(String path) throws Exception { return call("GET", path, Map.of(), null); }
    private Reply post(String path, Map<String, String> form) throws Exception { return call("POST", path, form, null); }
    private static String encode(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    @Test void healthAndLandingAreAvailable() throws Exception {
        assertEquals("UP", get("/health").json.path("status").asText());
        var page = client.send(HttpRequest.newBuilder(URI.create(base)).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, page.statusCode());
        assertTrue(page.body().contains("A10"));
        assertEquals(404, get("/missing").status);
    }

    @Test void a01AliceCanReadBobsInvoiceButAnonymousCannot() throws Exception {
        assertEquals(401, get("/api/a01/invoice?id=1002").status);
        var login = post("/api/login", Map.of("user", "alice", "password", "demo123"));
        String token = login.json.path("token").asText();
        assertEquals("alice", call("GET", "/api/a01/invoice?id=1001", Map.of(), token).json.path("owner").asText());
        var leaked = call("GET", "/api/a01/invoice?id=1002", Map.of(), token);
        assertEquals(200, leaked.status);
        assertEquals("bob", leaked.json.path("owner").asText());
        assertEquals("alice", leaked.json.path("viewer").asText());
    }

    @Test void a02DebugLeaksWorkingDemoAdminCredentials() throws Exception {
        var debug = get("/api/a02/debug");
        assertEquals(200, debug.status);
        assertTrue(debug.json.path("debug").asBoolean());
        assertEquals(200, post("/api/login", Map.of("user", debug.json.path("adminUser").asText(),
                "password", debug.json.path("adminPassword").asText())).status);
    }

    @Test void a03CompromisedSupplierJarActuallyChangesExecutedCode() throws Exception {
        var baseline = post("/api/a03/update", Map.of("channel", "trusted"));
        var compromised = post("/api/a03/update", Map.of("channel", "compromised"));
        assertEquals(200, baseline.status);
        assertEquals(1000, baseline.json.path("chargedPrice").asInt());
        assertEquals(200, compromised.status);
        assertEquals(1, compromised.json.path("chargedPrice").asInt());
        assertFalse(compromised.json.path("signatureVerified").asBoolean());
        assertEquals(400, post("/api/a03/update", Map.of("channel", "../../outside")).status);
    }

    @Test void a04UnsaltedHashesCanBeRecoveredWithTinyDictionary() throws Exception {
        var hashes = get("/api/a04/hashes").json.path("hashes");
        assertEquals(hashes.path("alice"), hashes.path("bob"));
        String recovered = null;
        for (String word : List.of("password", "demo123", "welcome")) {
            if (LabState.md5(word).equals(hashes.path("alice").asText())) recovered = word;
        }
        assertEquals("demo123", recovered);
        assertEquals(200, post("/api/login", Map.of("user", "alice", "password", recovered)).status);
    }

    @Test void a05SqlInjectionReadsAllCustomers() throws Exception {
        assertEquals(1, get("/api/a05/customers?name=Alice").json.path("count").asInt());
        var injection = get("/api/a05/customers?name=" + encode("' OR '1'='1"));
        assertEquals(200, injection.status);
        assertEquals(3, injection.json.path("count").asInt());
        assertTrue(injection.json.path("customers").toString().contains("ADMIN-003"));
    }

    @Test void a06SingleUseCouponCanBeReplayed() throws Exception {
        assertEquals(100, get("/api/a06/wallet").json.path("balance").asInt());
        assertEquals(110, post("/api/a06/redeem", Map.of("coupon", "WELCOME10")).json.path("balance").asInt());
        assertEquals(120, post("/api/a06/redeem", Map.of("coupon", "WELCOME10")).json.path("balance").asInt());
    }

    @Test void a07PredictableResetTokenTakesOverBobAndCanBeReused() throws Exception {
        assertEquals(403, post("/api/a07/reset", Map.of("user", "bob", "token", "invalid")).status);
        assertEquals(200, post("/api/a07/reset", Map.of("user", "bob", "token", "reset-bob", "password", "taken123")).status);
        assertEquals(401, post("/api/login", Map.of("user", "bob", "password", "demo123")).status);
        assertEquals(200, post("/api/login", Map.of("user", "bob", "password", "taken123")).status);
        assertEquals(200, post("/api/a07/reset", Map.of("user", "bob", "token", "reset-bob", "password", "again123")).status);
    }

    @Test void a08ClientCanChangeUnsignedCartPrice() throws Exception {
        String original = get("/api/a08/cart").json.path("cart").asText();
        assertEquals(1000, post("/api/a08/checkout", Map.of("cart", original)).json.path("charged").asInt());
        String tampered = Base64.getEncoder().encodeToString("{\"sku\":\"LAPTOP-DEMO\",\"quantity\":1,\"unitPrice\":1}".getBytes(StandardCharsets.UTF_8));
        var checkout = post("/api/a08/checkout", Map.of("cart", tampered));
        assertEquals(200, checkout.status);
        assertEquals(1, checkout.json.path("charged").asInt());
    }

    @Test void a09RepeatedFailuresNeverProduceSecurityEventsOrAlerts() throws Exception {
        for (int i = 0; i < 8; i++) assertEquals(401, post("/api/a09/login", Map.of("user", "admin", "password", "wrong")).status);
        var telemetry = get("/api/a09/telemetry").json;
        assertEquals(8, telemetry.path("observedFailures").asInt());
        assertEquals(0, telemetry.path("securityEvents").size());
        assertEquals(0, telemetry.path("alerts").size());
        assertEquals(200, post("/api/a09/login", Map.of("user", "admin", "password", "admin123")).status);
    }

    @Test void a10SecurityDependencyFailureApprovesOtherwiseDeniedPayment() throws Exception {
        var denied = post("/api/a10/pay", Map.of("amount", "1000", "riskService", "online"));
        assertEquals(403, denied.status);
        assertEquals(0, denied.json.path("completedOrders").asInt());
        var failure = post("/api/a10/pay", Map.of("amount", "1000", "riskService", "offline"));
        assertEquals(200, failure.status);
        assertTrue(failure.json.path("approved").asBoolean());
        assertEquals("fail-open", failure.json.path("reason").asText());
        assertEquals(1, failure.json.path("completedOrders").asInt());
    }

    @Test void oversizedInputAndWrongMethodsDoNotTriggerLabActions() throws Exception {
        assertEquals(413, post("/api/a06/redeem", Map.of("coupon", "x".repeat(17000))).status);
        assertEquals(404, get("/api/a06/redeem?coupon=WELCOME10").status);
        assertEquals(100, get("/api/a06/wallet").json.path("balance").asInt());
    }
}
*/