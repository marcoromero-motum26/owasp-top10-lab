package mx.demo.owasp;

import java.net.URI;
import java.net.http.*;
import java.time.Duration;

public final class HealthCheck {
    public static void main(String[] args) throws Exception {
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:8080/health"))
                .timeout(Duration.ofSeconds(2)).GET().build();
        System.exit(client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode() == 200 ? 0 : 1);
    }
}
