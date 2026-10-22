# Mitigaciones listas para copiar y pegar — OWASP Top 10:2025

Esta guía contiene código completo para corregir **los diez escenarios de este laboratorio** durante una presentación. Los cambios se aplican manualmente; los archivos de la aplicación no se modifican al abrir la guía. Cada bloque indica el archivo y si debes reemplazar un método, agregar campos o cambiar un caso del enrutador.

## Preparación y orden de aplicación

- Copia el contenido de cada bloque, sin las marcas de Markdown. En HTML usa **Copiar**; si el navegador bloquea el portapapeles, el bloque quedará seleccionado para copiar con Ctrl+C.
- Un método se reemplaza **completo**, incluida su firma y sus llaves. Los campos y métodos nuevos van dentro de la clase, fuera de otros métodos. Los `case` van dentro del `switch` de `LabServer.route`.
- Los bloques usan los imports actuales o nombres de clase completos. Solo A04 crea un archivo Java nuevo, con sus imports incluidos. No hay que modificar `pom.xml`.
- Puedes presentar cada escenario por separado, excepto **A07, que requiere A04**. Para aplicar todos: **A01 → A02 → A03 → A04 → A05 → A06 → A07 → A08 → A09 → A10**.
- A01 puede estar ya corregido en tu copia: el método de esta guía conserva esa protección. A02 deshabilita admin; usa Alice como operadora al mostrar A09.
- El código sigue siendo un laboratorio con datos en memoria. A03 retira la actualización dinámica; A06 conserva una única billetera; A07 ofrece cambio de contraseña con identidad verificada; A09 ofrece auditoría local. Cada sección distingue su alcance de las ampliaciones necesarias.

## Compilar y presentar

Los cambios Java requieren reconstruir y reiniciar; recargar la página no los aplica. Reiniciar borra contraseñas cambiadas, sesiones, canjes, saldo y registros.

Las pruebas originales y `SmokeCheck` esperan vulnerabilidades: sus expectativas deben cambiar al aplicar mitigaciones. **No desactives las pruebas comentando todo el archivo.** Para una presentación puedes omitir temporalmente su ejecución mientras usas las comprobaciones de esta guía.

**Con Java 21+ y Maven instalados**, desde la raíz del proyecto:

```powershell
mvn -DskipTests clean package
java -jar target/owasp-lab.jar
```

En este caso el puerto es **8080**; cambia `$base` en los ejemplos PowerShell a `http://localhost:8080`.

**Con Docker**, para esta modalidad de presentación, reemplaza exclusivamente la línea `RUN mvn -B -ntp clean verify` del `Dockerfile` por:

```dockerfile
RUN mvn -B -ntp -DskipTests clean package
```

Luego reconstruye y abre **http://localhost:18080**:

```powershell
docker compose up --build -d --wait
docker compose logs lab
```

`-DskipTests` compila las pruebas pero omite ejecutarlas; **no certifica la mitigación**. Tras actualizar las pruebas a los resultados esperados, restaura `RUN mvn -B -ntp clean verify` y ejecuta `mvn clean verify` o reconstruye con Docker. Si las pruebas están comentadas, restáuralas y adapta las expectativas para recuperar esa validación.

Los botones de la página muestran las respuestas HTTP. Después de mitigar es normal ver 403, 404 o 409 en los intentos de abuso. A04 deja de exponer hashes, por lo que su botón antiguo ya no podrá ejecutar el diccionario; verifica hashes en el depurador. A09 requiere ahora una sesión autorizada para consultar telemetría: usa su bloque PowerShell.

## Índice de escenarios

- [A01 — Pérdida de control de acceso](#a01)
- [A02 — Configuración de seguridad incorrecta](#a02)
- [A03 — Fallas en la cadena de suministro de software](#a03)
- [A04 — Fallas criptográficas](#a04)
- [A05 — Inyección](#a05)
- [A06 — Diseño inseguro](#a06)
- [A07 — Fallas de autenticación](#a07)
- [A08 — Fallas en integridad de software o datos](#a08)
- [A09 — Fallas en registro y alertas de seguridad](#a09)
- [A10 — Manejo inadecuado de condiciones excepcionales](#a10)

<a id="a01"></a>

## A01 — Pérdida de control de acceso

**Cómo funciona la mitigación**

Autenticar significa identificar a quien hace la petición; autorizar significa decidir si esa persona puede acceder a la factura solicitada. Este método realiza ambas comprobaciones antes de enviar información.

1. `currentUser(x)` obtiene la identidad desde la sesión del servidor. Si no hay sesión válida, responde 401 y el `return` termina la operación.
2. El cliente puede elegir `id`, pero el propietario se consulta en el mapa definido por el servidor. El cliente no puede declarar que una factura ajena le pertenece.
3. `owner == null || !owner.equals(viewer)` rechaza tanto una factura inexistente como una que pertenece a otra persona. Ambas respuestas usan el mismo 404 y mensaje para no confirmar la existencia de facturas ajenas.
4. Solo después de superar esas condiciones se construye la respuesta con total y domicilio. El `return` es esencial: impide continuar hasta la respuesta que contiene los datos.

**Qué cambia:** Alice puede consultar su factura 1001, pero cambiar la URL a 1002 ya no le concede acceso. El control efectivo está en el servidor; ocultar botones o usar identificadores difíciles de adivinar no aplicaría esta regla de propiedad.

**Archivo:** `src/main/java/mx/demo/owasp/LabServer.java`. Reemplaza el método `invoice` completo. No requiere imports nuevos. Si ya agregaste la comparación de propietario, este método la incluye.

<!-- snippet:A01-invoice -->

```java
private void invoice(HttpExchange x, Map<String, String> p) throws IOException {
    String viewer = currentUser(x);
    if (viewer == null) {
        json(x, 401, Map.of("error", "Inicia sesión"));
        return;
    }
    String id = p.getOrDefault("id", "1001");
    String owner = Map.of("1001", "alice", "1002", "bob").get(id);
    if (owner == null || !owner.equals(viewer)) {
        json(x, 404, Map.of("error", "Factura no disponible"));
        return;
    }
    json(x, 200, Map.of("id", id, "owner", owner, "viewer", viewer,
            "total", 1500, "address", "Domicilio ficticio de " + owner));
}
```

**Comprobación:** inicia sesión como Alice: 1001 devuelve 200; 1002 y un ID inexistente devuelven el mismo 404. Sin sesión devuelve 401. Bob conserva acceso a 1002.

**Para ampliar:** aplica esta autorización también a modificación, listados y exportación; en una base de datos filtra por ID y propietario en la misma consulta.

<a id="a02"></a>

## A02 — Configuración de seguridad incorrecta

**Cómo funciona la mitigación**

La corrección actúa sobre la información expuesta, la cuenta comprometida y algunas protecciones del navegador. Son medidas complementarias: cada una resuelve un problema diferente.

1. El nuevo `debug` responde 404 sin construir el objeto con credenciales y configuración. La ruta continúa definida, pero su comportamiento pasa a ser una negativa deliberada.
2. `passwordHashes.remove("admin")` elimina del almacenamiento la cuenta cuya contraseña era pública. Así, conocer `admin123` deja de permitir iniciar sesión después de reconstruir y reiniciar el laboratorio. Ocultar la contraseña en la respuesta, por sí solo, no habría impedido su uso.
3. Al retirar el cuerpo anterior de `debug`, también se elimina `Access-Control-Allow-Origin: *`. La página usa el mismo origen y no necesita permitir que páginas de otros orígenes lean esa respuesta.
4. `X-Content-Type-Options: nosniff` indica al navegador que respete el tipo de contenido declarado; `X-Frame-Options: DENY` impide mostrar la página dentro de marcos que podrían usarse para engañar al usuario al hacer clic; `Referrer-Policy: no-referrer` evita enviar la URL de origen en la cabecera Referer.

**Qué cambia:** el diagnóstico deja de revelar información y la cuenta expuesta deja de autenticar. Las cabeceras añaden protección en el navegador, pero no reemplazan el cierre del diagnóstico ni la eliminación de la cuenta.

**Paso 1 — `LabServer.java`:** reemplaza el método `debug`. Al eliminar su cuerpo anterior también desaparece el CORS permisivo.

<!-- snippet:A02-debug -->

```java
private void debug(HttpExchange x) throws IOException {
    json(x, 404, Map.of("error", "Ruta o método no disponible"));
}
```

**Paso 2 — `LabState.java`:** agrega esta línea al final del constructor `LabState()`, después de crear los usuarios y las tablas. La cuenta expuesta deja de existir en cada arranque. Si A04 se aplica después, conserva esta línea.

<!-- snippet:A02-admin -->

```java
passwordHashes.remove("admin");
```

**Paso 3 — `LabServer.java`:** agrega estas cabeceras al principio del método `send`, antes de `sendResponseHeaders`.

<!-- snippet:A02-headers -->

```java
x.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
x.getResponseHeaders().set("X-Frame-Options", "DENY");
x.getResponseHeaders().set("Referrer-Policy", "no-referrer");
```

**Comprobación:** `GET /api/a02/debug` devuelve 404 sin credenciales ni permiso CORS; `admin/admin123` devuelve 401. Alice y Bob siguen disponibles para los demás ejercicios. Reconstruye y reinicia para que la eliminación del usuario surta efecto.

**Para ampliar:** las cuentas de Alice y Bob siguen siendo datos de demostración. En una aplicación real elimina cuentas de ejemplo, rota secretos expuestos y configura un gestor de secretos. Para una CSP estricta, extrae primero el JavaScript inline de la página a un recurso servido por el backend; estas cabeceras no sustituyen ese trabajo.

<a id="a03"></a>

## A03 — Fallas en la cadena de suministro de software

**Cómo funciona la mitigación**

En esta opción se elimina el punto donde una petición web podía provocar la ejecución de código de un proveedor. La regla de precio queda dentro del código revisado y compilado de la aplicación.

1. La nueva clase `SupplyChain` ya no crea archivos JAR temporales ni un `URLClassLoader`, y tampoco invoca `PriceRule.apply` mediante reflexión. Por tanto, ningún contenido de los JAR de demostración participa en el cálculo.
2. `quote` solo acepta el valor `trusted`; cualquier otro canal lanza `SecurityException`. Esa etiqueta es una entrada permitida de la demo, no una prueba criptográfica de confianza.
3. El precio procede del servidor: la ruta llama a `quote(..., 1000)`. La regla incorporada devuelve ese mismo importe y también rechaza precios negativos si se invoca desde otro punto del código.
4. La ruta captura el rechazo y responde 403. Para el caso permitido informa `dynamicLoading: false`, sin afirmar que se haya verificado una firma.

**Qué cambia:** seleccionar `compromised` deja de ejecutar la clase que rebajaba el precio a un peso. La protección principal es haber retirado la ejecución dinámica, no confiar en el nombre del canal. Si se recupera esa funcionalidad, harán falta los controles de aprobación y procedencia descritos al final del escenario.

**Opción de presentación:** retirar la carga dinámica y compilar la regla aprobada con la aplicación. El cliente ya no puede instalar ni ejecutar un JAR. Se conserva el precio legítimo de 1000. Esta opción reduce la funcionalidad de actualización; no pretende implementar firmas de artefactos.

**Paso 1:** reemplaza **todo** `src/main/java/mx/demo/owasp/SupplyChain.java` por:

<!-- snippet:A03-supply -->

```java
package mx.demo.owasp;

final class SupplyChain {
    private SupplyChain() { }

    static int quote(String channel, int price) {
        if (!"trusted".equals(channel)) {
            throw new SecurityException("Actualización no aprobada");
        }
        if (price < 0) throw new IllegalArgumentException("Precio inválido");
        // Regla revisada y compilada con la aplicación; no carga código externo.
        return price;
    }
}
```

**Paso 2 — `LabServer.route`:** reemplaza el bloque completo `case "POST /api/a03/update"` por:

<!-- snippet:A03-route -->

```java
case "POST /api/a03/update" -> {
    try {
        int price = SupplyChain.quote(p.getOrDefault("channel", "trusted"), 1000);
        json(x, 200, Map.of("component", "built-in.PriceRule",
                "channel", "trusted", "catalogPrice", 1000,
                "chargedPrice", price, "dynamicLoading", false));
    } catch (SecurityException exception) {
        json(x, 403, Map.of("error", "Actualización no aprobada"));
    }
}
```

**Comprobación:** `channel=trusted` devuelve 200 y `chargedPrice=1000`; `channel=compromised` y rutas arbitrarias devuelven 403. Ningún JAR de `fixtures` se carga ni se ejecuta, aunque Maven aún los genere. No se declara una firma verificada que no existe.

**Si necesitas conservar actualizaciones dinámicas:** requieren un flujo administrativo y validar digest aprobado, firma y procedencia antes de crear un cargador de clases. La referencia de confianza debe ser independiente de la descarga. Revisa dependencias, plugins, imágenes, SBOM y permisos de CI/CD; este parche resuelve el escenario de carga dinámica del laboratorio.

<a id="a04"></a>

## A04 — Fallas criptográficas

**Cómo funciona la mitigación**

Un hash de contraseña es un valor derivado que permite verificar una contraseña sin almacenarla directamente. La corrección cambia tanto la forma de obtener ese valor como los lugares donde se utiliza.

1. `Passwords.hash` genera un **salt**, una secuencia aleatoria nueva de 16 bytes, usando `SecureRandom`. El salt se guarda junto al resultado y no necesita ser secreto. Hace que dos cuentas con `demo123` obtengan hashes distintos y evita reutilizar directamente un cálculo contra todas las cuentas.
2. `derive` usa PBKDF2-HMAC-SHA256 con 600 000 iteraciones y una salida de 256 bits. Ese trabajo repetido encarece cada intento de adivinar una contraseña a partir de un hash robado. No vuelve imposible adivinar contraseñas débiles; aumenta el coste de probarlas.
3. El texto almacenado contiene algoritmo, iteraciones, salt y resultado, separados por `$`. Base64 solo representa los bytes del salt y del hash como texto; no aporta cifrado.
4. `verify` extrae el salt guardado y deriva el resultado de la contraseña introducida con los mismos parámetros. Después compara mediante `MessageDigest.isEqual`, en vez de generar otro salt o comparar contraseñas en claro. Un formato no reconocido se rechaza.
5. Tanto la creación de cuentas como `resetPassword` usan `Passwords.hash`; así el restablecimiento no vuelve a introducir MD5. Los dos endpoints de login comparten el método que usa `Passwords.verify`.
6. La ruta `/api/a04/hashes` responde 404 para dejar de publicar los hashes. Un atacante que consiguiera una copia por otra vía se enfrentaría además al nuevo mecanismo de almacenamiento.

**Qué cambia:** hay dos barreras distintas: no exponer hashes por HTTP y hacer más costoso atacar los que pudieran filtrarse. El 404 demuestra la primera; verificar los hashes distintos y el funcionamiento de `Passwords.verify` permite comprobar la segunda. El método antiguo `md5` puede existir sin utilizarse en estos flujos.

**Paso 1:** crea `src/main/java/mx/demo/owasp/Passwords.java` con el contenido completo siguiente. Usa PBKDF2-HMAC-SHA256 del JDK, salt aleatorio de 16 bytes, 600 000 iteraciones y una clave de 256 bits; no agrega dependencias Maven. Argon2id es la primera opción general de OWASP; aquí se elige PBKDF2 para facilitar una demostración con el JDK existente. El coste indicado coincide con la [guía de almacenamiento de contraseñas de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

<!-- snippet:A04-passwords -->

```java
package mx.demo.owasp;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

final class Passwords {
    private static final int ITERATIONS = 600_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Passwords() { }

    static String hash(String password) throws GeneralSecurityException {
        if (password == null || password.length() > 1024) {
            throw new IllegalArgumentException("Contraseña inválida");
        }
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] derived = derive(password, salt);
        return "pbkdf2-sha256$" + ITERATIONS + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(derived);
    }

    static boolean verify(String password, String stored) throws GeneralSecurityException {
        if (password == null || password.length() > 1024 || stored == null) return false;
        String[] parts = stored.split("\\$", -1);
        if (parts.length != 4 || !parts[0].equals("pbkdf2-sha256")
                || !parts[1].equals(Integer.toString(ITERATIONS))) return false;
        try {
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            return salt.length == 16 && expected.length == 32
                    && MessageDigest.isEqual(expected, derive(password, salt));
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static byte[] derive(String password, byte[] salt) throws GeneralSecurityException {
        char[] characters = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(characters, salt, ITERATIONS, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
            Arrays.fill(characters, '\0');
        }
    }
}
```

**Paso 2 — `LabState()`:** reemplaza las tres líneas que inicializan hashes con `md5` por:

<!-- snippet:A04-seed -->

```java
passwordHashes.put("alice", Passwords.hash("demo123"));
passwordHashes.put("bob", Passwords.hash("demo123"));
passwordHashes.put("admin", Passwords.hash("admin123"));
```

Si aplicaste A02, conserva `passwordHashes.remove("admin");` al final del constructor.

**Paso 3 — `LabServer.login`:** reemplaza exclusivamente estas dos líneas:

`String hash = LabState.md5(p.getOrDefault("password", ""));`\
`if (!hash.equals(state.passwordHashes.get(user))) {`

por el siguiente bloque. El resto del método se conserva, incluido su cierre de llave.

<!-- snippet:A04-login -->

```java
if (!Passwords.verify(p.getOrDefault("password", ""), state.passwordHashes.get(user))) {
```

**Paso 4 — `LabServer.resetPassword`:** sustituye la línea que guarda `LabState.md5(...)` por:

<!-- snippet:A04-reset -->

```java
state.passwordHashes.put(user, Passwords.hash(p.getOrDefault("password", "changed123")));
```

A07 reemplazará después el método completo para corregir la identidad y el token. Este paso solo evita volver a guardar MD5 mientras presentas A04.

**Paso 5 — `LabServer.route`:** reemplaza el caso completo de `GET /api/a04/hashes` por:

<!-- snippet:A04-route -->

```java
case "GET /api/a04/hashes" ->
        json(x, 404, Map.of("error", "Ruta o método no disponible"));
```

**Comprobación:** Alice y Bob siguen entrando con `demo123`; una contraseña incorrecta falla y el endpoint de hashes devuelve 404. En el depurador, sus hashes empiezan con `pbkdf2-sha256$600000$` y son distintos pese a compartir contraseña. La comprobación usa `Passwords.verify`, nunca compara dos resultados de `Passwords.hash`.

**Alcance:** reiniciar recrea las cuentas del laboratorio; no hay hashes persistentes que migrar. El método `LabState.md5` puede quedarse sin llamadas para que las pruebas didácticas antiguas sigan compilando. En un sistema persistente implementa migración durante un login válido o restablecimiento forzado; no habilites MD5 como alternativa indefinida.

<a id="a05"></a>

## A05 — Inyección

**Cómo funciona la mitigación**

El cambio separa las instrucciones de la consulta de los datos que aporta el usuario. El nombre buscado puede contener comillas sin convertirse en una parte ejecutable del SQL.

1. La consulta tiene una estructura fija: `WHERE name = ?`. El signo `?` reserva un lugar para un valor; el código no añade el texto recibido a la sintaxis SQL.
2. `connection.prepareStatement(query)` crea la consulta parametrizada y `statement.setString(1, name)` entrega el nombre como dato. El controlador JDBC mantiene esa separación al ejecutar la consulta.
3. Si se recibe `' OR '1'='1`, se busca un cliente cuyo nombre completo sea literalmente ese texto. No se añade una condición verdadera al `WHERE`, por lo que el ataque ya no devuelve todas las filas.
4. El límite de 80 caracteres respeta el tamaño del campo de la tabla. Es una validación adicional; la protección frente a inyección procede de los parámetros, no de ese límite.
5. La consulta y la respuesta solo incluyen `id` y `name`. Se dejan de devolver `private_note` y el texto SQL. Los bloques `try` cierran conexión, sentencia y resultados al terminar, incluso si hay un error.

**Qué cambia:** una búsqueda legítima sigue funcionando y una entrada con sintaxis SQL se trata como nombre. Este ejemplo mantiene público el catálogo de nombres; decidir quién puede consultar cada registro requiere autorización adicional.

**Archivo:** `LabServer.java`. Reemplaza `customers` completo. Utiliza los imports JDBC y de colecciones que ya existen. La respuesta deja de incluir SQL y notas privadas; el catálogo de nombres del ejercicio sigue siendo público.

<!-- snippet:A05-customers -->

```java
private void customers(HttpExchange x, Map<String, String> p) throws Exception {
    String name = p.getOrDefault("name", "Alice");
    if (name.length() > 80) {
        json(x, 400, Map.of("error", "Nombre demasiado largo"));
        return;
    }
    String query = "SELECT id, name FROM customers WHERE name = ?";
    var rows = new ArrayList<Map<String, Object>>();
    try (var connection = DriverManager.getConnection(state.databaseUrl);
         var statement = connection.prepareStatement(query)) {
        statement.setString(1, name);
        try (var results = statement.executeQuery()) {
            while (results.next()) {
                rows.add(Map.of("id", results.getInt("id"), "name", results.getString("name")));
            }
        }
    }
    json(x, 200, Map.of("count", rows.size(), "customers", rows));
}
```

**Comprobación:** `name=Alice` devuelve una fila; `name=' OR '1'='1` devuelve cero. Un nombre con apóstrofo se trata como dato sin provocar un error SQL.

**Para ampliar:** si estos datos requieren privacidad, agrega autenticación y filtrado por propietario. Los parámetros SQL evitan inyección, pero no implementan autorización. Usa una cuenta SQL con privilegios mínimos.

<a id="a06"></a>

## A06 — Diseño inseguro

**Cómo funciona la mitigación**

La regla «solo una vez» necesita memoria: el servidor debe recordar que el cupón ya se utilizó. También debe evitar que dos solicitudes lo consuman al mismo tiempo.

1. `welcomeRedeemed` empieza en `false` y representa si la única billetera de la demo ya recibió esta promoción. Un cupón incorrecto se rechaza antes de consultar o cambiar ese estado.
2. `synchronized (state)` permite que solo una solicitud a la vez ejecute el bloque de canje sobre ese objeto. La comprobación, el aumento de saldo y el cambio de la bandera ocurren bajo el mismo bloqueo.
3. Si la bandera ya es `true`, se prepara un 409, con crédito cero y el saldo actual. No se vuelve a sumar dinero.
4. En el primer canje, `Math.addExact` calcula el nuevo saldo y detecta un posible desbordamiento numérico. Después se actualiza la billetera y se marca el cupón como usado antes de liberar el bloqueo.
5. La respuesta HTTP se envía fuera del bloqueo, usando los valores capturados para esa operación. Si la respuesta se pierde en la red, repetir la petición no vuelve a acreditar el cupón.

**Qué cambia:** dos solicitudes que llegan juntas ya no pueden observar ambas el cupón como disponible. Esto funciona para la billetera compartida y el proceso único del laboratorio; la bandera no es un registro persistente ni una transacción entre varios servidores.

**Regla del laboratorio:** existe una sola billetera compartida de 100 pesos; WELCOME10 se canjea una vez por esa billetera durante la vida del servidor. El parche conserva ese modelo y los botones actuales. Reiniciar crea una billetera nueva.

**Paso 1 — `LabState.java`:** agrega este campo dentro de la clase, fuera del constructor y de cualquier método:

<!-- snippet:A06-field -->

```java
boolean welcomeRedeemed = false; // Leer y escribir únicamente bajo synchronized (state).
```

**Paso 2 — `LabServer.java`:** reemplaza `redeem` completo. El bloqueo protege tanto la comprobación como el crédito y el registro del canje; dos peticiones concurrentes no pueden acreditar dos veces.

<!-- snippet:A06-redeem -->

```java
private void redeem(HttpExchange x, Map<String, String> p) throws IOException {
    if (!"WELCOME10".equals(p.get("coupon"))) {
        json(x, 400, Map.of("error", "Cupón inválido"));
        return;
    }
    int status;
    Map<String, Object> response;
    synchronized (state) {
        if (state.welcomeRedeemed) {
            status = 409;
            response = Map.of("error", "Cupón ya utilizado",
                    "balance", state.wallet.get(), "credit", 0);
        } else {
            int balance = Math.addExact(state.wallet.get(), 10);
            state.wallet.set(balance);
            state.welcomeRedeemed = true;
            status = 200;
            response = Map.of("balance", balance, "credit", 10);
        }
    }
    json(x, status, response);
}
```

**Comprobación:** primer canje devuelve 200 y saldo 110; el segundo devuelve 409 y saldo 110. Repite con llamadas concurrentes: exactamente una se acepta. Un cupón incorrecto devuelve 400 sin cambiar el saldo.

**Para una billetera por usuario o varios procesos:** identifica al propietario por sesión y persiste canjes con clave única `(user_id, campaign_id)`; inserción y crédito deben ocurrir en una transacción. El bloqueo en memoria de este ejemplo solo cubre la instancia única del laboratorio; no persiste ante reinicios ni coordina réplicas.

<a id="a07"></a>

## A07 — Fallas de autenticación

**Cómo funciona la mitigación**

Un token de restablecimiento es una autorización temporal para cambiar una contraseña. Debe ser difícil de adivinar, corresponder a una cuenta, vencer y dejar de servir después de usarse.

1. `issueResetToken` exige una sesión válida y verifica `currentPassword`. Obtiene el usuario desde esa sesión, no de un nombre elegido en la petición. En este laboratorio la emisión sirve para un cambio autorizado; no recupera una cuenta cuya contraseña se olvidó.
2. `SecureRandom` genera 32 bytes aleatorios que se representan en Base64url. El valor deja de poder calcularse como `reset-bob`. En `resetGrants` se guarda su hash SHA-256, la cuenta y una caducidad de cinco minutos; un token nuevo reemplaza al anterior de esa cuenta.
3. Aquí SHA-256 se aplica a un token aleatorio de alta entropía, no a una contraseña humana que pueda aparecer en un diccionario. Para la contraseña se conserva PBKDF2 mediante `Passwords`.
4. `resetPassword` verifica cuenta, existencia de la autorización, vencimiento, longitud y coincidencia del hash antes de cambiar nada. Después exige una contraseña de entre 15 y 128 caracteres y calcula su hash.
5. Bajo `synchronized (state)`, se guarda la contraseña nueva, se elimina el token y se revocan las sesiones de esa cuenta. Al compartir el bloqueo con `login`, no se puede intercalar una autenticación con la contraseña anterior durante el cambio. Dos solicitudes con el mismo token no pueden consumirlo con éxito.
6. `sessionExpires` y `sessionUser` rechazan sesiones después de 30 minutos desde su emisión. Esto también limita su duración cuando no hay restablecimiento.

**Qué cambia:** conocer el nombre de Bob ya no autoriza a cambiar su contraseña. Los comandos legítimos primero demuestran identidad, solicitan el token y lo consumen. La pérdida de acceso por olvido necesita un canal de recuperación verificado que este laboratorio no incorpora.

**Dependencia: aplica A04 primero.** Los métodos siguientes usan `Passwords`. Aplica A09 después, porque modifica el bloque de fallo de este `login`.

El laboratorio no tiene correo verificado. Para mostrar un flujo legítimo sin inventar un servicio de entrega, se agrega **emisión de token solo con sesión válida y contraseña actual**. La recuperación de una cuenta cuya contraseña se olvidó queda pendiente de un canal verificado. Ningún solicitante anónimo obtiene tokens.

**Paso 1 — `LabState.java`:** agrega estos campos y el record dentro de la clase, fuera de los métodos:

<!-- snippet:A07-state -->

```java
record ResetGrant(String digest, long expiresAt) { }
final Map<String, ResetGrant> resetGrants = new ConcurrentHashMap<>();
final Map<String, Long> sessionExpires = new ConcurrentHashMap<>();
```

**Paso 2 — `LabServer.java`:** reemplaza `login` completo por este método. El bloqueo compartido con el restablecimiento impide crear una sesión con la contraseña anterior mientras se cambia. Mantiene las cookies locales HTTP del laboratorio; en HTTPS agrega `Secure`.

<!-- snippet:A07-login -->

```java
private void login(HttpExchange x, Map<String, String> p, boolean silent) throws Exception {
    String user = p.getOrDefault("user", "");
    String session;
    synchronized (state) {
        if (!Passwords.verify(p.getOrDefault("password", ""), state.passwordHashes.get(user))) {
            if (silent) state.observedLoginFailures.incrementAndGet();
            json(x, 401, Map.of("error", "Credenciales inválidas"));
            return;
        }
        session = UUID.randomUUID().toString();
        state.sessionExpires.put(session, System.currentTimeMillis() + 30 * 60_000L);
        state.sessions.put(session, user);
    }
    x.getResponseHeaders().add("Set-Cookie",
            "LABSESSION=" + session + "; Path=/; HttpOnly; SameSite=Lax");
    json(x, 200, Map.of("user", user, "token", session));
}
```

**Paso 3 — `LabServer.java`:** reemplaza `currentUser` por los dos métodos siguientes. Las sesiones caducan después de 30 minutos.

<!-- snippet:A07-current -->

```java
private String currentUser(HttpExchange x) {
    String auth = x.getRequestHeaders().getFirst("Authorization");
    if (auth != null && auth.startsWith("Bearer ")) return sessionUser(auth.substring(7));
    String cookies = x.getRequestHeaders().getFirst("Cookie");
    if (cookies != null) for (String cookie : cookies.split(";")) {
        String[] pair = cookie.trim().split("=", 2);
        if (pair.length == 2 && pair[0].equals("LABSESSION")) return sessionUser(pair[1]);
    }
    return null;
}

private String sessionUser(String token) {
    synchronized (state) {
        Long expiresAt = state.sessionExpires.get(token);
        if (expiresAt == null || expiresAt <= System.currentTimeMillis()) {
            state.sessions.remove(token);
            state.sessionExpires.remove(token);
            return null;
        }
        return state.sessions.get(token);
    }
}
```

**Paso 4 — `LabServer.route`:** agrega este caso junto al caso existente de `POST /api/a07/reset`. Conserva ese caso existente.

<!-- snippet:A07-route -->

```java
case "POST /api/a07/reset-token" -> issueResetToken(x, p);
```

**Paso 5 — `LabServer.java`:** agrega los métodos `tokenHash` y `issueResetToken` y reemplaza `resetPassword`. Los nombres de clases nuevos están cualificados para no necesitar imports.

<!-- snippet:A07-reset -->

```java
private static String tokenHash(String token) throws java.security.GeneralSecurityException {
    return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
            .digest(token.getBytes(StandardCharsets.UTF_8)));
}

private void issueResetToken(HttpExchange x, Map<String, String> p) throws Exception {
    synchronized (state) {
        String user = currentUser(x);
        if (user == null) {
            json(x, 401, Map.of("error", "Inicia sesión"));
            return;
        }
        if (!Passwords.verify(p.getOrDefault("currentPassword", ""), state.passwordHashes.get(user))) {
            json(x, 403, Map.of("error", "Credenciales inválidas"));
            return;
        }
        byte[] random = new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        long expiresAt = System.currentTimeMillis() + 5 * 60_000L;
        // Un token nuevo reemplaza al anterior de la misma cuenta.
        state.resetGrants.put(user, new LabState.ResetGrant(tokenHash(token), expiresAt));
        // Solo se entrega al usuario que acaba de demostrar sesión y contraseña.
        json(x, 200, Map.of("user", user, "token", token, "expiresInSeconds", 300));
    }
}

private void resetPassword(HttpExchange x, Map<String, String> p) throws Exception {
    String user = p.getOrDefault("user", "");
    String token = p.getOrDefault("token", "");
    synchronized (state) {
        LabState.ResetGrant grant = state.resetGrants.get(user);
        if (!state.passwordHashes.containsKey(user) || grant == null
                || grant.expiresAt() <= System.currentTimeMillis()
                || token.length() != 43
                || !java.security.MessageDigest.isEqual(
                        grant.digest().getBytes(StandardCharsets.US_ASCII),
                        tokenHash(token).getBytes(StandardCharsets.US_ASCII))) {
            json(x, 403, Map.of("error", "Token inválido o vencido"));
            return;
        }
        String password = p.getOrDefault("password", "");
        if (password.length() < 15 || password.length() > 128) {
            json(x, 400, Map.of("error", "Usa entre 15 y 128 caracteres"));
            return;
        }
        String hash = Passwords.hash(password);
        state.passwordHashes.put(user, hash);
        state.resetGrants.remove(user);
        state.sessions.entrySet().removeIf(entry -> {
            if (!entry.getValue().equals(user)) return false;
            state.sessionExpires.remove(entry.getKey());
            return true;
        });
    }
    json(x, 200, Map.of("reset", true, "user", user));
}
```

**Demostración legítima en PowerShell:** ejecuta después de reconstruir, con el estado recién iniciado. La variable de token solo vive en la sesión del presentador.

<!-- snippet:A07-demo -->

```powershell
$base = 'http://localhost:18080'
$loginBob = Invoke-RestMethod "$base/api/login" -Method Post -Body @{
    user = 'bob'; password = 'demo123'
}
$headersBob = @{ Authorization = "Bearer $($loginBob.token)" }
$grant = Invoke-RestMethod "$base/api/a07/reset-token" -Method Post -Headers $headersBob -Body @{
    currentPassword = 'demo123'
}
Invoke-RestMethod "$base/api/a07/reset" -Method Post -Body @{
    user = 'bob'; token = $grant.token; password = 'NuevaClaveDemo2026!'
}
Invoke-RestMethod "$base/api/login" -Method Post -Body @{
    user = 'bob'; password = 'NuevaClaveDemo2026!'
}
```

**Comprobación adicional:** `reset-bob` devuelve 403; el token válido solo funciona para Bob y una vez. Al repetirlo, usarlo para Alice o esperar más de cinco minutos, devuelve 403. El bearer anterior ya no sirve en `/api/me`, `demo123` deja de autenticar a Bob y la contraseña nueva sí funciona. Pedir un token sin sesión devuelve 401.

**Para ampliar:** entrega tokens mediante un canal previamente verificado para recuperación sin sesión, limita solicitudes e intentos, añade MFA donde corresponda y usa almacenamiento persistente con transacciones. El token aleatorio, su hash, la caducidad, el consumo y la revocación aquí sí están implementados. La serialización del login bajo un bloqueo global simplifica la demo; una aplicación real necesita control de concurrencia por cuenta y protección frente a saturación.

<a id="a08"></a>

## A08 — Fallas en integridad de software o datos

**Cómo funciona la mitigación**

El cliente puede pedir un producto y una cantidad, pero el precio válido lo decide el servidor. Esa separación evita que editar el carrito modifique cuánto se cobra.

1. El método decodifica Base64 y lee JSON, rechazando datos mal formados y contenidos decodificados de más de 4096 bytes. Estas comprobaciones permiten interpretar la entrada, pero todavía no la hacen confiable.
2. Comprueba que haya un objeto, un SKU de texto —el identificador del producto— y una cantidad entera que quepa en un `int`. Así no convierte silenciosamente una fracción en una cantidad válida.
3. Busca el SKU en el catálogo definido en el servidor. Para `LAPTOP-DEMO`, el precio es 1000 independientemente de cualquier `unitPrice` incluido por el cliente. Un producto desconocido se rechaza.
4. Limita la cantidad a entre una y diez unidades. Calcula el total con `Math.multiplyExact`, que detecta desbordamientos; con el catálogo y los límites actuales, el importe máximo es 10 000.
5. Devuelve el precio aplicado y `priceSource: server-catalog`. El campo informa de la decisión; la protección real es usar el valor del catálogo en el cálculo.

**Qué cambia:** el usuario todavía puede editar el Base64, pero el precio editado ya no influye en el cobro. Esta solución no necesita firmar el carrito para proteger ese precio, porque lo vuelve a obtener de una fuente controlada por el servidor.

**Archivo:** `LabServer.java`. Reemplaza `checkout` completo. Conserva el formato Base64 para que los botones actuales sigan funcionando, pero ignora `unitPrice` y calcula el precio desde el catálogo del servidor.

<!-- snippet:A08-checkout -->

```java
private void checkout(HttpExchange x, Map<String, String> p) throws IOException {
    com.fasterxml.jackson.databind.JsonNode cart;
    try {
        byte[] decoded = Base64.getDecoder().decode(p.getOrDefault("cart", ""));
        if (decoded.length > 4096) throw new IllegalArgumentException();
        cart = JSON.readTree(decoded);
    } catch (IllegalArgumentException | com.fasterxml.jackson.core.JsonProcessingException exception) {
        json(x, 400, Map.of("error", "Carrito inválido"));
        return;
    }
    if (cart == null || !cart.isObject() || !cart.path("sku").isTextual()
            || !cart.path("quantity").isIntegralNumber()
            || !cart.path("quantity").canConvertToInt()) {
        json(x, 400, Map.of("error", "Carrito inválido"));
        return;
    }
    String sku = cart.path("sku").asText();
    int quantity = cart.path("quantity").intValue();
    Integer unitPrice = Map.of("LAPTOP-DEMO", 1000).get(sku);
    if (unitPrice == null || quantity < 1 || quantity > 10) {
        json(x, 400, Map.of("error", "SKU o cantidad inválidos"));
        return;
    }
    int total = Math.multiplyExact(unitPrice, quantity);
    json(x, 200, Map.of("sku", sku, "quantity", quantity,
            "unitPrice", unitPrice, "charged", total, "priceSource", "server-catalog"));
}
```

**Comprobación:** el carrito original y uno con `unitPrice=1` cobran 1000 para una unidad. SKU desconocido, cantidad fraccionaria, cero, negativa, mayor de diez, Base64 inválido o JSON inválido devuelven 400. No se afirma que Base64 tenga una firma: la autoridad del precio es el servidor.

**Para ampliar:** resuelve también descuentos, impuestos y disponibilidad en el servidor. Si usas cotizaciones firmadas, valida propietario, audiencia, vencimiento y repetición antes de aceptar el pedido.

<a id="a09"></a>

## A09 — Fallas en registro y alertas de seguridad

**Cómo funciona la mitigación**

Rechazar una contraseña incorrecta protege ese intento de acceso. Registrar lo ocurrido y detectar repeticiones permite además investigar y reaccionar ante una secuencia sospechosa.

1. `recordLoginFailure` se invoca antes del 401 en ambos endpoints de login. Su ejecución deja de depender de `silent`, por lo que los intentos fallidos recorren el mismo camino de auditoría.
2. Cada evento contiene hora, cuenta intentada, resultado, dirección de la conexión e identificador de correlación. Este último permite relacionar la alerta con el evento que la disparó. La dirección es la del par conectado; detrás de un proxy puede ser la del proxy, no la del usuario final.
3. Jackson serializa el evento como JSON, escapando caracteres de control para que un salto de línea introducido por el cliente no simule otro registro. No se incluyen contraseña, cookie ni token, y los nombres excesivamente largos se sustituyen por una etiqueta.
4. Bajo un bloqueo se actualizan contador y colas. Se cuentan los eventos conservados para la misma cuenta durante los últimos cinco minutos: es una **ventana móvil**, no un contador que se borra periódicamente. Cuando el conteo es ocho se crea una alerta.
5. Eventos y alertas se imprimen en consola y se conservan con límites de 256 y 64 elementos. `telemetry` entrega una copia coherente solo a una sesión de Alice, la operadora elegida para la demo.

**Qué cambia:** los ocho 401 dejan evidencia consultable y una alerta local. El código no bloquea automáticamente al atacante ni envía avisos a un servicio externo. La retención limitada puede omitir eventos necesarios para detectar un patrón; por eso el alcance es didáctico.

**Orden:** puedes aplicar A09 sobre el login original, sobre A04, o después de A07. Si aplicas A07 posteriormente, vuelve a insertar la llamada del paso 3 porque reemplaza `login`.

**Paso 1 — `LabServer.java`:** agrega estos dos campos dentro de la clase, fuera de los métodos. No agregues imports: ya existe `java.util.*`.

<!-- snippet:A09-fields -->

```java
private final Deque<Map<String, Object>> securityEvents = new ArrayDeque<>();
private final Deque<Map<String, Object>> securityAlerts = new ArrayDeque<>();
```

**Paso 2 — `LabServer.java`:** agrega estos métodos. Cada fallo genera un evento JSON y el octavo para la misma cuenta en cinco minutos genera una alerta JSON. Ambos se imprimen en la salida del contenedor y se conservan en un búfer acotado para la presentación. Los valores del cliente se serializan y se limita su longitud.

<!-- snippet:A09-methods -->

```java
private void recordLoginFailure(HttpExchange x, String user) throws IOException {
    long now = System.currentTimeMillis();
    String actor = user.length() <= 80 ? user : "[usuario demasiado largo]";
    String correlationId = UUID.randomUUID().toString();
    Map<String, Object> event = Map.of(
            "type", "LOGIN_FAILED", "timestamp", java.time.Instant.ofEpochMilli(now).toString(),
            "epochMillis", now, "actor", actor, "result", "DENIED",
            "source", x.getRemoteAddress().getAddress().getHostAddress(),
            "correlationId", correlationId);
    synchronized (securityEvents) {
        state.observedLoginFailures.incrementAndGet();
        if (securityEvents.size() == 256) securityEvents.removeFirst();
        securityEvents.addLast(event);
        System.out.println(JSON.writeValueAsString(event));
        long count = securityEvents.stream()
                .filter(item -> actor.equals(item.get("actor")))
                .filter(item -> (long) item.get("epochMillis") >= now - 5 * 60_000L)
                .count();
        if (count == 8) {
            Map<String, Object> alert = Map.of(
                    "type", "LOGIN_FAILURE_THRESHOLD",
                    "timestamp", java.time.Instant.ofEpochMilli(now).toString(),
                    "actor", actor, "failures", count, "windowSeconds", 300,
                    "correlationId", correlationId);
            if (securityAlerts.size() == 64) securityAlerts.removeFirst();
            securityAlerts.addLast(alert);
            System.out.println(JSON.writeValueAsString(alert));
        }
    }
}

private void telemetry(HttpExchange x) throws IOException {
    if (!"alice".equals(currentUser(x))) {
        json(x, 403, Map.of("error", "Acceso no autorizado"));
        return;
    }
    Map<String, Object> snapshot;
    synchronized (securityEvents) {
        snapshot = Map.of("observedFailures", state.observedLoginFailures.get(),
                "securityEvents", List.copyOf(securityEvents),
                "alerts", List.copyOf(securityAlerts));
    }
    json(x, 200, snapshot);
}
```

**Paso 3 — `LabServer.login`:** dentro del bloque de credenciales incorrectas, reemplaza la línea `if (silent) state.observedLoginFailures.incrementAndGet();` por esta llamada. Conserva el 401 y el `return`. La misma regla aplica a ambos endpoints de login, sin depender de `silent`.

<!-- snippet:A09-hook -->

```java
recordLoginFailure(x, user);
```

**Paso 4 — `LabServer.route`:** reemplaza el caso completo de `GET /api/a09/telemetry` (incluida su continuación con listas vacías) por:

<!-- snippet:A09-route -->

```java
case "GET /api/a09/telemetry" -> telemetry(x);
```

**Demostración en PowerShell:** funciona también con A02, que elimina la cuenta admin. Alice es la operadora autorizada de esta demostración; se registran igualmente intentos contra cuentas inexistentes.

<!-- snippet:A09-demo -->

```powershell
$base = 'http://localhost:18080'
$loginAlice = Invoke-RestMethod "$base/api/login" -Method Post -Body @{
    user = 'alice'; password = 'demo123'
}
$headersAlice = @{ Authorization = "Bearer $($loginAlice.token)" }
1..8 | ForEach-Object {
    try {
        Invoke-RestMethod "$base/api/a09/login" -Method Post -Body @{
            user = 'admin'; password = 'wrong'
        } | Out-Null
        throw 'Se esperaba HTTP 401'
    } catch {
        if ($null -eq $_.Exception.Response -or
            [int]$_.Exception.Response.StatusCode -ne 401) { throw }
    }
}
Invoke-RestMethod "$base/api/a09/telemetry" -Headers $headersAlice |
    ConvertTo-Json -Depth 6
```

**Comprobación:** desde un servidor recién iniciado, ocho fallos generan `observedFailures=8`, ocho eventos y una alerta `LOGIN_FAILURE_THRESHOLD`. Revisa también `docker compose logs lab`. Un visitante recibe 403 en telemetría. No se registran contraseñas, cookies ni tokens. En cada fallo se cuentan los eventos conservados de esa cuenta ocurridos durante los últimos cinco minutos; se emite una alerta cuando ese conteo es ocho.

**Límite explícito:** el búfer conserva 256 eventos y 64 alertas y se pierde al reiniciar; la ventana se calcula sobre esos 256 eventos. Es una implementación verificable del escenario, no un SIEM: con mucho tráfico puede perder cobertura. En operación, envía el JSON a un receptor central con retención y control de acceso, configura entrega a responsables y monitorea fallos del canal. Sustituye el permiso fijo de Alice por un rol gestionado por el servidor.

<a id="a10"></a>

## A10 — Manejo inadecuado de condiciones excepcionales

**Cómo funciona la mitigación**

El método distingue tres situaciones: el antifraude aprueba, rechaza o no puede evaluar. La última no debe producir los efectos de una aprobación.

1. Primero convierte y valida el importe, que debe ser positivo y no superar 1 000 000. También acepta solo los estados `online` y `offline` del simulador. Entradas inválidas reciben 400.
2. Cuando el servicio está disponible, se conserva la regla del ejercicio: importes de hasta 500 se aprueban; los mayores se rechazan con 403.
3. Si el simulador lanza `IllegalStateException`, el `catch` registra un evento con hora e identificador de correlación. La respuesta es 503, `approved: false` y `reason: risk-unavailable`, indicando que faltó una evaluación válida.
4. El `return` del `catch` sale del método antes de la instrucción que incrementa `orders`. No basta con cambiar el texto del error: hay que impedir el efecto de completar la operación.
5. Fuera del `catch`, el contador solo aumenta si `approved` es verdadero. Una negativa conserva el contador y devuelve 403.

**Qué cambia:** apagar el antifraude ya no permite aprobar un pago que normalmente se rechaza. Este comportamiento se llama rechazo seguro ante fallos: la falta de evaluación no concede permiso. Los reintentos de pagos aprobados siguen necesitando idempotencia, es decir, reconocer una misma operación para no cobrarla dos veces.

**Archivo:** `LabServer.java`. Reemplaza `pay` completo. Usa la excepción que el simulador ya lanza (`IllegalStateException`), por lo que no necesitas inventar una clase de excepción. Se conserva el interruptor local `riskService=offline` para demostrar el fallo.

<!-- snippet:A10-pay -->

```java
private void pay(HttpExchange x, Map<String, String> p) throws IOException {
    int amount;
    try {
        amount = Integer.parseInt(p.getOrDefault("amount", "1000"));
    } catch (NumberFormatException exception) {
        json(x, 400, Map.of("error", "Importe inválido"));
        return;
    }
    if (amount <= 0 || amount > 1_000_000) {
        json(x, 400, Map.of("error", "Importe inválido"));
        return;
    }
    String riskService = p.getOrDefault("riskService", "online");
    if (!Set.of("online", "offline").contains(riskService)) {
        json(x, 400, Map.of("error", "Estado del servicio inválido"));
        return;
    }
    boolean approved;
    try {
        if ("offline".equals(riskService)) {
            throw new IllegalStateException("Antifraude no disponible");
        }
        approved = amount <= 500;
    } catch (IllegalStateException exception) {
        String correlationId = UUID.randomUUID().toString();
        System.err.println(JSON.writeValueAsString(Map.of(
                "type", "RISK_SERVICE_UNAVAILABLE",
                "timestamp", java.time.Instant.now().toString(),
                "correlationId", correlationId)));
        json(x, 503, Map.of("approved", false, "reason", "risk-unavailable",
                "amount", amount, "completedOrders", state.orders.get(),
                "correlationId", correlationId));
        return;
    }
    int count = approved ? state.orders.incrementAndGet() : state.orders.get();
    json(x, approved ? 200 : 403, Map.of("approved", approved,
            "reason", approved ? "risk-accepted" : "risk-rejected",
            "amount", amount, "completedOrders", count));
}
```

**Comprobación:** importe 1000 con servicio online devuelve 403; offline devuelve 503 y `approved=false`. En ambos casos `completedOrders` no aumenta. Un importe 100 con servicio online devuelve 200 e incrementa el contador una vez por llamada. Importes inválidos devuelven 400.

**Para ampliar:** este parche cierra el fallo ante indisponibilidad; no implementa deduplicación de solicitudes. Para pagos reales agrega claves de idempotencia persistentes, transacciones, timeouts y reintentos limitados; distingue rechazo de indisponibilidad y no produzcas efectos financieros antes de la aprobación. Retira el interruptor público de fallos.

## Aceptación de la presentación

Comprueba tanto el intento rechazado como el caso legítimo. A01 conserva la factura propia; A03 conserva el precio aprobado; A04 conserva el login; A05 conserva la búsqueda; A06 permite un primer canje; A07 permite el cambio autorizado; A08 conserva el checkout; A09 permite consultar auditoría a la operadora; A10 permite importes aprobados. A02 cierra deliberadamente el diagnóstico público.

Para regresión automatizada, adapta `src/test/java/mx/demo/owasp/LabServerTest.java` a las respuestas indicadas y agrega concurrencia en A06, token vencido/reutilizado y revocación en A07, y ausencia de incremento de pedidos en A10. Mantén las pruebas de casos legítimos. Ningún éxito de compilación equivale por sí solo a validar estos comportamientos.

Referencias: [OWASP Top 10:2025](https://top10.owasp.org/2025/es/), [almacenamiento de contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) y [recuperación de contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html). Los controles de tokens aleatorios, caducidad y consumo único de A07 siguen esta última guía; la entrega por correo verificado requiere un servicio adicional.
