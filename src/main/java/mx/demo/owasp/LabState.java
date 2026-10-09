package mx.demo.owasp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

final class LabState implements AutoCloseable {
    final Map<String, String> passwordHashes = new ConcurrentHashMap<>();
    final Map<String, String> sessions = new ConcurrentHashMap<>();
    final AtomicInteger wallet = new AtomicInteger(100);
    final AtomicInteger orders = new AtomicInteger();
    final AtomicInteger observedLoginFailures = new AtomicInteger();
    final String databaseUrl = "jdbc:h2:mem:lab_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";
    private final Connection keeper;

    LabState() throws Exception {
        keeper = DriverManager.getConnection(databaseUrl);
        passwordHashes.put("alice", md5("demo123"));
        passwordHashes.put("bob", md5("demo123"));
        passwordHashes.put("admin", md5("admin123"));
        try (var sql = keeper.createStatement()) {
            sql.execute("CREATE TABLE customers(id INT PRIMARY KEY, name VARCHAR(80), private_note VARCHAR(200))");
            sql.execute("INSERT INTO customers VALUES (1, 'Alice', 'Cuenta ficticia ALICE-001'), (2, 'Bob', 'Cuenta ficticia BOB-002'), (3, 'Admin', 'Presupuesto ficticio ADMIN-003')");
        }
    }

    // VULNERABLE A04: hash rápido, sin salt, compartido entre cuentas.
    static String md5(String password) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(password.getBytes(StandardCharsets.UTF_8)));
    }

    @Override public void close() {
        try (var sql = keeper.createStatement()) { sql.execute("SHUTDOWN"); }
        catch (SQLException ignored) { /* Finalización del laboratorio. */ }
        try { keeper.close(); } catch (SQLException ignored) { }
    }
}
