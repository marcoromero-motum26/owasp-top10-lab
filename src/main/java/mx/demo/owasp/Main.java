package mx.demo.owasp;

public final class Main {
    public static void main(String[] args) throws Exception {
        var server = new LabServer(System.getenv().getOrDefault("LAB_BIND", "127.0.0.1"), 8080);
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        server.start();
        System.out.println("OWASP Top 10:2025 LAB INSEGURO - http://localhost:8080 - datos ficticios");
    }
}
