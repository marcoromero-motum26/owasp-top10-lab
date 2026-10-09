# Mitigaciones específicas del laboratorio OWASP Top 10:2025

Este archivo describe **cómo corregir cada vulnerabilidad de este proyecto**. Las correcciones son propuestas: no están aplicadas en la versión didáctica. Los fragmentos ilustran el cambio central y pueden requerir nuevos repositorios, tablas o servicios; no son parches completos para copiar sin adaptación.

Para practicar, crea una rama de correcciones, implementa los cambios y transforma las pruebas de `src/test/java/mx/demo/owasp/LabServerTest.java` en pruebas que esperen el rechazo del abuso. Mantén también casos legítimos para evitar que una corrección consista simplemente en inutilizar la función.

La clasificación sigue [OWASP Top 10:2025](https://top10.owasp.org/2025/es/). Cada categoría puede abarcar muchas debilidades y algunos controles se complementan entre sí.

## A01 — Pérdida de control de acceso

**Ubicación:** `src/main/java/mx/demo/owasp/LabServer.java`, métodos `invoice` y `currentUser`; ruta `GET /api/a01/invoice`.

**Problema:** se exige sesión, pero cualquier usuario autenticado obtiene una factura de cualquier propietario al cambiar `id`. Autenticar no equivale a autorizar.

**Cambios necesarios:**

1. Obtén el propietario desde el almacenamiento del servidor y compáralo con el principal de la sesión antes de devolver datos.
2. Implementa denegación por defecto y una política central para operaciones y objetos; un rol administrativo debe proceder del servidor, nunca de un campo enviado por el cliente.
3. En una versión con base de datos, filtra por objeto **y propietario** en la misma consulta. No consideres los UUID una sustitución de la autorización.
4. Protege igualmente lectura, modificación, listados y exportación. Evita confirmar la existencia de objetos ajenos cuando no sea necesario.

```java
// En invoice, después de obtener owner y antes de construir la respuesta:
if (!owner.equals(viewer)) {
    json(x, 404, Map.of("error", "Factura no disponible"));
    return;
}
```

**Verificación:** Alice obtiene 1001; Alice no obtiene 1002 ni su domicilio; Bob obtiene 1002; un usuario sin sesión recibe 401. Cambia la expectativa de la prueba `a01AliceCanReadBobsInvoiceButAnonymousCannot` a 403/404 para la factura ajena.

## A02 — Configuración de seguridad incorrecta

**Ubicación:** `LabServer.debug`, ruta `GET /api/a02/debug`, credenciales iniciales en `LabState`.

**Problema:** diagnóstico público con credenciales funcionales, secreto ficticio y CORS permisivo. No basta con ocultar el enlace en la página.

**Cambios necesarios:**

1. Elimina la ruta de diagnóstico de la distribución de producción o regístrala solo en un perfil local explícito. Si se conserva para operación, exige una autorización administrativa independiente y devuelve campos permitidos de forma expresa.
2. No serialices variables de entorno, credenciales ni configuración completa. Sustituye secretos incrustados por un gestor de secretos y rota las credenciales expuestas; eliminarlas del HTML no revoca su uso.
3. Quita `Access-Control-Allow-Origin: *`; la aplicación usa el mismo origen y no lo necesita. Cuando haya otro cliente web, configura una lista exacta de orígenes y revisa métodos/cabeceras.
4. Añade cabeceras apropiadas, como `X-Content-Type-Options: nosniff` y una CSP. Mueve el JavaScript inline de `index.html` a un recurso propio para usar una política `script-src 'self'` sin habilitar ejecución inline indiscriminada.
5. Deshabilita cuentas de demostración, depuración y respuestas detalladas de excepciones en una aplicación real. Conserva diagnósticos internos sin secretos.

**Verificación:** un visitante recibe 404/403 en `/api/a02/debug`; ninguna respuesta contiene `admin123` o la clave ficticia; `admin/admin123` deja de autenticar. Una petición de origen no autorizado no obtiene permiso CORS. CORS es un control del navegador, no reemplaza autorización.

## A03 — Fallas en la cadena de suministro de software

**Ubicación:** `src/main/java/mx/demo/owasp/SupplyChain.java`, método `quote`; `fixtures/`; plugins/dependencias de `pom.xml`; imágenes base de `Dockerfile`.

**Problema:** el proceso de actualización carga y ejecuta la clase de un proveedor sin acreditar procedencia ni aprobación. Los dos JAR locales permiten observar el mismo riesgo sin descargar software malicioso.

**Cambios necesarios:**

1. Retira del cliente web la posibilidad de seleccionar una actualización. Instala componentes mediante un flujo administrativo con revisión y aprobación.
2. Usa un registro de artefactos de confianza, versiones inmutables, firma y procedencia verificables. Mantén claves de confianza fuera del control del artefacto descargado.
3. Verifica el contenido **antes** de crear `URLClassLoader`. Un digest esperado debe provenir de una referencia previamente aprobada, no del mismo repositorio potencialmente comprometido.
4. Mantén SBOM de dependencias directas, transitivas, plugins, JDK e imagen del sistema operativo. Integra análisis de composición de software, revisión de avisos y actualizaciones con responsables y plazos.
5. Protege CI/CD, ramas y registros con mínimo privilegio, revisión, MFA y credenciales de alcance limitado. Promueve el mismo artefacto validado entre entornos y usa despliegues graduales.
6. Fija imágenes por digest si necesitas builds reproducibles y actualiza esos digests de manera controlada. No confundas fijar versiones con mantenerlas actualizadas.

```java
// Ejemplo conceptual antes de cargar el JAR; expectedDigest viene de una
// configuración aprobada y protegida, nunca del parámetro channel.
byte[] actual = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar));
if (!MessageDigest.isEqual(expectedDigest, actual)) {
    throw new SecurityException("Artefacto no aprobado");
}
// Además: validar firma/procedencia con una raíz de confianza independiente.
```

Un checksum coincidente no acredita por sí solo quién produjo el software. La firma tampoco garantiza que un proveedor confiable no haya introducido código defectuoso: se necesitan revisión, pruebas y respuesta a compromisos.

**Verificación:** el artefacto aprobado mantiene el precio 1000; el fixture comprometido se rechaza **antes de invocar** `PriceRule.apply`. Un archivo alterado, firma desconocida, versión no aprobada o ausencia del servicio de verificación no deben habilitar su carga. Sustituye las expectativas de `a03CompromisedSupplierJarActuallyChangesExecutedCode`.

## A04 — Fallas criptográficas

**Ubicación:** `LabState.md5`, `passwordHashes`, `LabServer.login`, `resetPassword` y `/api/a04/hashes`.

**Problema:** MD5 sin salt permite identificar contraseñas iguales y probar diccionarios rápidamente. El volcado del ejercicio representa acceso a hashes robados.

**Cambios necesarios:**

1. Sustituye MD5 por una implementación mantenida de Argon2id con salt único por contraseña y coste ajustado al servicio. No sustituyas MD5 por SHA-256 simple: sigue siendo rápido para ataques de diccionario.
2. Encapsula almacenamiento y verificación en un servicio de contraseñas, para que `login` y `resetPassword` usen la misma política. Guarda algoritmo, parámetros y salt junto al hash.
3. Migra gradualmente: verifica un hash legado solo durante el acceso válido, recalcula inmediatamente el hash moderno y elimina el anterior. Fuerza restablecimiento para cuentas que no se migren o que se consideren comprometidas.
4. Elimina `/api/a04/hashes` de una distribución real. Limita acceso al almacenamiento y a sus respaldos.
5. Para datos reversibles sensibles, usa cifrado autenticado y gestión de claves con rotación; no uses el algoritmo de hashing de contraseñas como cifrado. Usa TLS y cookies `Secure` cuando la aplicación se sirva por HTTPS.

**Verificación:** Alice y Bob tienen hashes almacenados distintos aun con la misma contraseña; ambas verifican correctamente; una contraseña incorrecta no verifica; el diccionario MD5 deja de reproducir el hash. Revisa parámetros y coste en el entorno de ejecución real, sin escribir criptografía propia.

Referencia: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## A05 — Inyección

**Ubicación:** `LabServer.customers`, `GET /api/a05/customers`.

**Problema:** `name` pasa a formar parte de la sintaxis SQL. El valor `' OR '1'='1` cambia el significado de la consulta.

**Cambio principal:** reemplaza la concatenación y `Statement` por SQL fijo con `PreparedStatement` y parámetros enlazados.

```java
String query = "SELECT id, name, private_note FROM customers WHERE name = ?";
try (var connection = DriverManager.getConnection(state.databaseUrl);
     var statement = connection.prepareStatement(query)) {
    statement.setString(1, p.getOrDefault("name", "Alice"));
    try (var results = statement.executeQuery()) {
        // Construir una respuesta que contenga solo los campos autorizados.
    }
}
```

Valida además longitud y formato de entrada por reglas de negocio. No uses listas de palabras prohibidas ni escapes manuales como sustituto de parámetros. Para identificadores SQL dinámicos que no admitan parámetros, usa una selección de valores permitidos controlada por el servidor. Reduce privilegios de la cuenta de base de datos y no devuelvas SQL ni notas privadas a usuarios no autorizados.

**Verificación:** `Alice` devuelve el registro permitido; el payload se trata como un nombre literal y devuelve cero filas, sin error SQL ni notas ajenas. Prueba también nombres legítimos con apóstrofos. La parametrización no reemplaza los controles de acceso de A01.

## A06 — Diseño inseguro

**Ubicación:** `LabServer.redeem`, `LabState.wallet`.

**Problema:** el requisito de un canje por billetera no está representado en el modelo. La operación suma saldo en cada llamada aunque el cupón ya se haya consumido.

**Cambios necesarios:**

1. Define el invariante: un usuario autenticado puede canjear cada campaña como máximo una vez; la billetera de destino procede del servidor.
2. Introduce una tabla de canjes con restricción única `(user_id, campaign_id)`. El registro del canje y el crédito deben ocurrir en una única transacción.
3. Si la inserción encuentra un canje existente, devuelve 409 o la respuesta idempotente original sin volver a acreditar saldo.
4. Protege también llamadas concurrentes. La secuencia «consultar si existe, luego insertar» sin restricción/transacción permite carreras.
5. Define caducidad, presupuesto de campaña, elegibilidad y recuperación ante fallos antes de implementar promociones.

```sql
CREATE TABLE coupon_redemptions (
    user_id VARCHAR(80) NOT NULL,
    campaign_id VARCHAR(80) NOT NULL,
    redeemed_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, campaign_id)
);
-- En la misma transacción: INSERT del canje + UPDATE de la billetera.
```

**Verificación:** primer canje 100 → 110; segundo canje mantiene 110. Varias peticiones simultáneas solo generan un crédito. Si se inyecta un fallo después de registrar el canje pero antes de acreditar el saldo, se revierte toda la transacción.

## A07 — Fallas de autenticación

**Ubicación:** `LabServer.resetPassword`, `login`, `currentUser`; mapas de contraseñas y sesiones en `LabState`.

**Problema:** `reset-<usuario>` puede calcularse sin probar identidad, no caduca y se reutiliza. El cambio de contraseña tampoco revoca sesiones existentes.

**Cambios necesarios:**

1. Genera tokens opacos con `SecureRandom` y entropía suficiente, por ejemplo 32 bytes aleatorios codificados en Base64url.
2. Envía el token por un canal previamente verificado. No lo devuelvas a quien solicita un restablecimiento en una API pública.
3. Almacena un hash del token ligado al usuario, propósito, caducidad y estado de consumo. Consúmelo y cambia la contraseña de forma atómica. Aquí un hash criptográfico rápido de un token de alta entropía tiene un propósito distinto del hashing de contraseñas.
4. Devuelve respuestas uniformes al solicitar recuperación para no enumerar cuentas. Limita intentos y solicitudes por cuenta y origen con una política que contemple abuso y usuarios legítimos.
5. Revoca sesiones después del restablecimiento, rota identificadores al autenticar y establece expiración de sesiones. Agrega MFA a operaciones y cuentas de riesgo.

```java
byte[] random = new byte[32];
new java.security.SecureRandom().nextBytes(random);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
// Persistir solo su hash + usuario + expiresAt + consumedAt; entregar por canal verificado.
```

**Verificación:** `reset-bob` se rechaza; un token válido funciona una sola vez y solo para Bob; tokens caducados, reutilizados o de otro usuario no cambian contraseñas. La contraseña anterior y las sesiones anteriores dejan de funcionar tras un cambio válido.

## A08 — Fallas en integridad de software o datos

**Ubicación:** `LabServer.checkout`, `/api/a08/cart`.

**Problema:** `unitPrice` recibido en un carrito Base64 decide cuánto cobrar. No se acredita integridad ni autoridad del dato.

**Cambios necesarios:**

1. Acepta del cliente SKU y cantidad. Resuelve precio, descuentos, impuestos y disponibilidad a partir de información confiable del servidor.
2. Valida SKU existente, cantidad positiva y límites. Calcula importes con unidades monetarias enteras y comprobación de overflow, o `BigDecimal` con reglas explícitas de redondeo.
3. Si necesitas cotizaciones transportadas por el cliente, emite un identificador opaco almacenado en el servidor o firma los datos con una librería apropiada, incorporando usuario, audiencia, expiración y nonce. Verifica antes de usar y aplica controles de repetición.
4. Revalida condiciones relevantes al confirmar el pedido. Una firma sobre datos elegidos por el atacante no hace confiable el precio.

```java
// Ejemplo de catálogo bajo control del servidor:
int unitPrice = catalog.priceOf(sku);
if (quantity < 1 || quantity > 10) throw new IllegalArgumentException();
int total = Math.multiplyExact(unitPrice, quantity);
```

**Verificación:** cambiar `unitPrice` a 1 se rechaza o se ignora y el total sigue siendo 1000. SKU desconocido, cantidades negativas/excesivas y una cotización vencida se rechazan. Si implementas firma, modificar un byte o reutilizar una cotización consumida no debe generar un pedido.

## A09 — Fallas en registro y alertas de seguridad

**Ubicación:** `LabServer.login` con `silent=true`, `observedLoginFailures` y `/api/a09/telemetry`.

**Problema:** se omite emitir evidencia útil sobre fallos de acceso. El contador global didáctico no permite reconstruir quién intentó acceder, cuándo, desde dónde ni qué regla se activó. Las listas vacías representan un sistema de auditoría y alertas ausente.

**Cambios necesarios:**

1. Crea un servicio de auditoría que emita eventos estructurados para login, recuperación, denegaciones de autorización, actualizaciones de componentes y operaciones privilegiadas.
2. Incluye hora UTC, tipo, identificador de correlación, actor o cuenta objetivo, resultado y origen confiable. No confíes directamente en `X-Forwarded-For` si no procede de un proxy controlado.
3. No registres contraseñas, cookies, tokens ni datos personales innecesarios. Usa serialización estructurada para que caracteres de control no creen eventos falsos.
4. Envía eventos a almacenamiento central con control de acceso, retención y protección contra modificación. Monitorea también pérdida de eventos y fallos del canal de auditoría.
5. Conecta reglas de detección con un canal real de atención. Como criterio didáctico, ocho fallos para una cuenta en cinco minutos deben crear una alerta verificable. Ajusta umbrales reales con métricas y análisis del servicio.
6. En las pruebas usa un emisor en memoria con reloj controlable; en operación verifica la entrega al sistema de monitoreo y el procedimiento de respuesta.

```java
// Punto de integración conceptual antes de responder 401:
audit.emit(new SecurityEvent("LOGIN_FAILED", clock.instant(),
        correlationId, user, trustedSource, "DENIED"));
```

**Verificación:** ocho intentos fallidos producen ocho eventos sin secretos y al menos una alerta según la regla; el evento permite correlacionar la secuencia. Una contraseña con saltos de línea no genera entradas adicionales. Simula indisponibilidad del receptor y comprueba la política de búfer/aviso; no basta con que `docker compose logs` muestre cualquier texto.

## A10 — Manejo inadecuado de condiciones excepcionales

**Ubicación:** `LabServer.pay`, bloque `catch (IllegalStateException)`.

**Problema:** una excepción de una dependencia de seguridad se interpreta como aprobación. El pago de 1000, rechazado normalmente, se completa cuando el antifraude falla.

**Cambios necesarios:**

1. Sustituye `approved = true` en el `catch` por rechazo seguro o estado pendiente sin efectos financieros. No confundas fallo de evaluación con resultado aprobado.
2. Define un contrato explícito para `APPROVED`, `REJECTED` y `UNAVAILABLE`. Captura excepciones esperadas concretas y evita capturas amplias que oculten fallos de programación.
3. Aplica timeouts, reintentos limitados solo cuando sean seguros, circuit breaker e idempotencia. No generes duplicados al reintentar pagos.
4. Mantén consistencia transaccional: no incrementes pedidos ni alteres saldos antes de la aprobación válida; revierte cambios parciales.
5. Registra el fallo con correlación sin filtrar trazas internas al cliente. Devuelve un error temporal uniforme, por ejemplo 503, o un estado pendiente explícito según el contrato.
6. Retira `riskService=offline` de la API de producción; conserva la inyección de fallos en dobles de prueba o herramientas internas controladas.

```java
catch (RiskServiceUnavailableException exception) {
    audit.recordDependencyFailure("risk", correlationId);
    json(x, 503, Map.of("approved", false, "error", "No fue posible evaluar el pago"));
    return; // No modificar completedOrders ni efectuar cargos.
}
```

**Verificación:** la misma operación de 1000 nunca se aprueba durante caída, timeout o respuesta inválida del antifraude. `completedOrders` permanece igual. Un importe legítimo aprobado se completa una sola vez y un reintento con la misma clave de idempotencia no duplica la operación.

## Orden de trabajo y aceptación

Para una rama de correcciones de este laboratorio, aborda primero autorización, autenticación, SQL y decisiones ante fallos (A01/A07/A05/A10); después protege diagnóstico y almacenamiento de contraseñas (A02/A04), las reglas comerciales y los datos (A06/A08), y el proceso de actualización y la observabilidad (A03/A09). Esto es una secuencia pedagógica, no una priorización universal por riesgo.

Una corrección termina cuando funciona el caso legítimo, se rechaza el abuso documentado y existen pruebas de regresión del comportamiento esperado. Las medidas Docker actuales reducen exposición, pero no sustituyen ninguno de estos cambios. No publiques este proyecto como producto real sin completar una revisión de seguridad más amplia.
