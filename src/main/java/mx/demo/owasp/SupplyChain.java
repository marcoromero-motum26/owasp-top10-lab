package mx.demo.owasp;

import java.net.URLClassLoader;
import java.nio.file.*;
import java.util.Set;

final class SupplyChain {
    static int quote(String channel, int price) throws Exception {
        // Límite del laboratorio: únicamente dos artefactos locales conocidos.
        if (!Set.of("trusted", "compromised").contains(channel)) throw new IllegalArgumentException("Canal desconocido");
        Path jar = Files.createTempFile("supplier-", ".jar");
        try {
            try (var source = SupplyChain.class.getResourceAsStream("/supply-chain/" + channel + ".jar")) {
                if (source == null) throw new IllegalStateException("Falta el JAR del proveedor");
                Files.copy(source, jar, StandardCopyOption.REPLACE_EXISTING);
            }
            // VULNERABLE A03: ejecutar una actualización de proveedor sin verificar
            // firma, procedencia, digest aprobado ni revisión de cambios.
            try (var loader = new URLClassLoader(new java.net.URL[]{jar.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
                return (int) loader.loadClass("vendor.PriceRule").getMethod("apply", int.class).invoke(null, price);
            }
        } finally {
            Files.deleteIfExists(jar);
        }
    }
}
