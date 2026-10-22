# Demostraciones reproducibles

Esta guía explica el **código vulnerable original** de cada escenario y cómo los comandos permiten observar su fallo. Tu copia puede contener mitigaciones ya aplicadas: en ese caso los resultados de abuso deben cambiar. Cada ejemplo incluye una explicación paso a paso y una referencia a su corrección. En particular, un 404 deliberado en A04 indica que el servidor dejó de exponer hashes; no significa que falte un método Java.

`SmokeCheck` conserva expectativas de la versión vulnerable y puede fallar después de corregirla. Reiniciar restablece los datos en memoria, pero **no deshace cambios del código**. Para interpretar un resultado, distingue entre la versión vulnerable y la versión mitigada que compilaste.

Inicia con `docker compose up --build -d --wait`. Puedes ejecutar todos los ejercicios desde http://localhost:18080 o con `docker compose exec lab java -cp /app/owasp-lab.jar mx.demo.owasp.SmokeCheck`. Los comandos siguientes están escritos para **PowerShell** y usan `curl.exe` para evitar el alias `curl` de Windows PowerShell. En Linux/macOS, usa `curl` en su lugar; los pasos que usan objetos PowerShell se pueden sustituir por la página interactiva.

Los cuerpos POST usan `application/x-www-form-urlencoded`. Reinicia con `docker compose restart lab` para restablecer el laboratorio. Solo ejecuta estas peticiones contra tu propia instancia local.

## A01 — Pérdida de control de acceso

**Por qué este código es vulnerable**

1. En la versión vulnerable, `currentUser` demuestra que la petición pertenece a Alice. Esa comprobación responde «¿quién eres?», pero no «¿puedes leer esta factura?».
2. El parámetro `id` de la URL está bajo control del cliente. Cambiar 1001 por 1002 hace que el servidor seleccione la factura de Bob.
3. Aunque el método conoce `owner`, la versión vulnerable no lo compara con `viewer` antes de ejecutar `json(...)`. Por eso envía el domicilio y el total a cualquier usuario autenticado que solicite ese ID.

El ataque aprovecha una referencia directa a un objeto sin autorización por propietario; se conoce como IDOR. No exige robar una sesión de Bob: una sesión legítima de Alice basta. El dato que no debe aceptarse como permiso es el identificador elegido por el cliente.

**Cómo interpretar la mitigación:** después de agregar la comparación de propietario, Alice conserva el 200 para 1001 y recibe 404 para 1002. Ese rechazo es deliberado. La explicación y el código están en [A01 de mitigaciones](../MITIGACIONES.md#a01).

**Código:** `LabServer.invoice` y `currentUser`. La sesión identifica al usuario, pero no se compara con el propietario de la factura.

```powershell
$session = Invoke-RestMethod -Method Post http://localhost:18080/api/login -Body @{user='alice'; password='demo123'}
curl.exe -H "Authorization: Bearer $($session.token)" "http://localhost:18080/api/a01/invoice?id=1001"
curl.exe -H "Authorization: Bearer $($session.token)" "http://localhost:18080/api/a01/invoice?id=1002"
```

**Resultado:** la primera factura pertenece a Alice; la segunda devuelve `owner: bob` y `viewer: alice`, HTTP 200, incluyendo domicilio ficticio. Sin sesión devuelve 401. El fallo es autorización por objeto, aun con autenticación válida.

## A02 — Configuración de seguridad incorrecta

**Por qué este código es vulnerable**

1. La ruta de diagnóstico original llama a `debug` sin pedir sesión ni comprobar un rol. Cualquier cliente que conozca la URL puede ejecutarla, aunque la página no tenga un botón visible.
2. El método construye una respuesta que incluye configuración y `adminPassword`. Es información que el servidor debería reservar; serializarla como JSON la entrega al solicitante.
3. La cuenta `admin` existe en `LabState` con esa misma contraseña. Por eso la segunda petición convierte la filtración de información en un acceso autenticado.
4. `Access-Control-Allow-Origin: *` permite que una página de otro origen lea esta respuesta pública desde un navegador. Sin embargo, el endpoint ya es accesible directamente con curl: quitar CORS no cerraría por sí solo la exposición.

El fallo combina una función de diagnóstico pública con credenciales utilizables. No es necesario atacar la base de datos ni romper un hash, porque la aplicación revela directamente la contraseña ficticia.

**Cómo interpretar la mitigación:** se espera 404 en diagnóstico y 401 al intentar entrar con `admin/admin123` después de eliminar esa cuenta y reiniciar. Consulta [A02 de mitigaciones](../MITIGACIONES.md#a02).

**Código:** `LabServer.debug`. Una ruta de diagnóstico permanece habilitada y accesible sin autenticación.

```powershell
curl.exe -i http://localhost:18080/api/a02/debug
curl.exe -d "user=admin&password=admin123" http://localhost:18080/api/login
```

**Resultado:** configuración interna, `DEMO-NOT-A-REAL-SECRET` y credenciales administrativas ficticias en texto claro; el acceso posterior funciona. La respuesta de diagnóstico además lleva CORS `*`. No se exponen variables de entorno ni credenciales del equipo anfitrión.

## A03 — Fallas en la cadena de suministro de software

**Por qué este código es vulnerable**

1. El parámetro `channel` selecciona cuál de los dos JAR locales usará `SupplyChain.quote`. Ambos contienen una clase con el mismo nombre: `vendor.PriceRule`.
2. En la versión vulnerable, el método copia el recurso a un archivo temporal, crea un `URLClassLoader` y carga la clase elegida. Después invoca `apply`: no está leyendo simplemente un dato, está ejecutando código del componente.
3. La versión original devuelve el precio recibido. La versión alterada devuelve siempre 1. Como el servidor usa su resultado, el cambio del componente modifica realmente la lógica de cobro.
4. No hay una comprobación previa de que el contenido sea una versión revisada y aprobada. Limitar los nombres a `trusted` y `compromised` contiene la demo, pero no verifica la procedencia del código elegido.

El fallo consiste en otorgar confianza de ejecución a un componente sin validar el proceso por el que llega. Los fixtures hacen visible el problema con código pequeño y local; no representan una descarga libre de archivos.

**Cómo interpretar la mitigación:** la opción documentada elimina la carga dinámica, conserva 1000 para el canal permitido y rechaza `compromised` con 403. Véase [A03 de mitigaciones](../MITIGACIONES.md#a03).

**Código:** `SupplyChain.quote`, `fixtures/trusted/vendor/PriceRule.java`, `fixtures/compromised/vendor/PriceRule.java` y generación de artefactos en `pom.xml`.

```powershell
curl.exe -d "channel=trusted" http://localhost:18080/api/a03/update
curl.exe -d "channel=compromised" http://localhost:18080/api/a03/update
```

**Resultado:** `chargedPrice` pasa de 1000 a 1. Maven compila dos versiones de un JAR de proveedor. El cargador ejecuta `vendor.PriceRule.apply` sin comprobar firma ni procedencia. El selector representa qué actualización entrega el proveedor; no hace falta explotar una CVE real ni instalar malware.

Cada petición carga su propio artefacto y aplica la regla inmediatamente; no cambia permanentemente la siguiente petición. Los únicos canales permitidos son los dos fixtures locales. La falta de control del proceso de actualización es el foco A03; la integridad también se relaciona con A08.

## A04 — Fallas criptográficas

**Por qué este código es vulnerable**

1. La versión original obtiene los hashes llamando a MD5 directamente sobre la contraseña. No incorpora un **salt**, un valor aleatorio diferente por contraseña almacenada. Por eso Alice y Bob producen el mismo resultado mientras ambos usan `demo123`.
2. MD5 permite calcular candidatos con poco trabajo. Quien obtiene un hash puede tomar palabras de un diccionario, calcular su MD5 y compararlo con el valor robado.
3. El bucle de PowerShell hace exactamente esa comparación con tres palabras. Al encontrar `demo123`, identifica una contraseña que produce el hash observado. No descifra el hash ni necesita hallar una colisión entre entradas distintas.
4. El endpoint público `/api/a04/hashes` proporciona los valores al ejercicio. En una aplicación real, un volcado de almacenamiento o respaldo filtrado también podría proporcionar hashes: cerrar el endpoint no corrige por sí solo el algoritmo.

El ataque al diccionario ocurre localmente después de obtener los hashes; no requiere un intento de login por cada palabra. El salt dificulta reutilizar cálculos entre cuentas, y una función lenta para contraseñas encarece cada prueba.

**Cómo interpretar la mitigación:** con A04 aplicado, esta ruta devuelve 404 intencionalmente y `Invoke-RestMethod` interrumpe el ejemplo antes del diccionario. Eso confirma el cierre de la exposición, no demuestra por sí solo PBKDF2. Verifica además el almacenamiento y el login como explica [A04 de mitigaciones](../MITIGACIONES.md#a04).

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

**Por qué este código es vulnerable**

1. La versión vulnerable arma el texto SQL sumando el valor de `name` entre comillas. Así, la entrada del cliente acaba en el mismo texto que contiene las instrucciones de la consulta.
2. La comilla inicial de `' OR '1'='1` cierra el valor que debía representar el nombre. El resto añade una condición SQL: `OR '1'='1'`.
3. Esa igualdad es verdadera para todas las filas. Por tanto, basta con ella para que el `WHERE` acepte cada cliente, aunque su nombre no coincida con el solicitado.
4. `createStatement().executeQuery(query)` ejecuta la consulta ya manipulada. Además, la selección incluye `private_note` y la respuesta la publica como `privateNote`, ampliando la información expuesta.

El problema aparece cuando un dato externo puede cambiar las instrucciones que interpretará la base de datos. `--data-urlencode` solo transporta correctamente las comillas en HTTP; no es una defensa contra SQL.

**Cómo interpretar la mitigación:** con parámetros, ese texto se busca como nombre literal y devuelve cero registros; `Alice` sigue devolviendo uno. El código corregido también deja de publicar notas privadas y SQL. Consulta [A05 de mitigaciones](../MITIGACIONES.md#a05).

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

**Por qué este código es vulnerable**

1. `redeem` solo comprueba que el texto del cupón sea `WELCOME10`. Esa validación demuestra que el cupón existe, pero no que siga disponible para canje.
2. Cada llamada válida ejecuta `state.wallet.addAndGet(10)`. El programa no tiene una bandera ni un registro que indique que el crédito ya se concedió.
3. La segunda petición vuelve a superar exactamente la misma comprobación y vuelve a sumar diez pesos. La regla comercial «una vez» aparece en la descripción, pero no está representada en el estado ni en una condición del código.

`AtomicInteger` hace segura la suma individual entre hilos, pero no decide si esa suma está autorizada por las reglas del negocio. Incluso dos peticiones secuenciales, sin concurrencia, bastan para reproducir el abuso.

El problema no requiere falsificar el cupón: se repite una operación válida más veces de las permitidas. Si solo se añadiera una comprobación sin coordinarla con la actualización, dos solicitudes simultáneas todavía podrían pasarla.

**Cómo interpretar la mitigación:** el primer canje acredita diez; el segundo devuelve 409 sin aumentar el saldo. El registro y el bloqueo se explican en [A06 de mitigaciones](../MITIGACIONES.md#a06).

**Código:** `LabServer.redeem`. Regla de negocio: `WELCOME10` debe otorgar diez pesos solo una vez a la billetera de demostración. No existe registro de canjes.

```powershell
curl.exe http://localhost:18080/api/a06/wallet
curl.exe -d "coupon=WELCOME10" http://localhost:18080/api/a06/redeem
curl.exe -d "coupon=WELCOME10" http://localhost:18080/api/a06/redeem
```

**Resultado inicial:** saldo 100 → 110 → 120. No se necesita una carrera: repetir secuencialmente ya viola la regla. El identificador del cupón es válido; falta diseñar el control del ciclo de vida del canje.

## A07 — Fallas de autenticación

**Por qué este código es vulnerable**

1. La ruta acepta `user`, `token` y la contraseña nueva desde la petición. La comprobación original solo exige que la cuenta exista y que el token sea igual a `"reset-" + user`.
2. El nombre de usuario no es un secreto. Para Bob se puede construir `reset-bob` sin recibir un correo, conocer su contraseña ni iniciar sesión.
3. Superada esa comparación, `passwordHashes.put` reemplaza la contraseña de la cuenta. El siguiente login funciona con la elegida por quien hizo la petición.
4. El servidor no guarda una autorización emitida con fecha de vencimiento ni la consume. El mismo texto puede usarse repetidamente. Tampoco revoca las sesiones ya creadas al cambiar la contraseña.

El token debería demostrar que el solicitante obtuvo una autorización legítima. En este caso solo demuestra que conoce una regla de concatenación pública. Por eso se puede tomar control de una cuenta sin atacar el mecanismo de login.

**Cómo interpretar la mitigación:** almacenar la contraseña nueva con PBKDF2, como hace A04, no corrige esta comprobación de identidad. A07 debe rechazar `reset-bob` y aceptar únicamente una autorización válida de un solo uso. El flujo disponible para la demo está en [A07 de mitigaciones](../MITIGACIONES.md#a07).

**Código:** `LabServer.resetPassword`. Token de recuperación derivado directamente del usuario.

```powershell
curl.exe -d "user=bob&token=reset-bob&password=taken123" http://localhost:18080/api/a07/reset
curl.exe -d "user=bob&password=taken123" http://localhost:18080/api/login
```

**Resultado:** restablecimiento y login HTTP 200 sin haber acreditado acceso al correo ni a la cuenta de Bob. `reset-bob` se puede reutilizar y no caduca. La contraseña anterior deja de funcionar. Restablece el estado al terminar si quieres repetir otras prácticas desde cero.

## A08 — Fallas en la integridad del software o de los datos

**Por qué este código es vulnerable**

1. La respuesta inicial entrega un carrito con producto, cantidad y precio codificado en Base64. Base64 cambia la representación del JSON, pero cualquiera puede decodificarlo, editarlo y volver a codificarlo.
2. La petición de checkout devuelve el carrito desde el cliente. Aunque el servidor hubiera generado el original, ya no puede asumir que el contenido recibido sea el mismo.
3. La versión vulnerable calcula `unitPrice * quantity` usando directamente ambos valores recibidos. No consulta el precio del producto en una fuente controlada por el servidor.
4. El ejemplo conserva producto y cantidad, pero fija `unitPrice` en 1. Como la entrada se acepta como precio autorizado, el resultado del cálculo también es 1. Además, faltan controles de rango para cantidades y de desbordamiento del cálculo.

El fallo es confiar en una decisión económica aportada por el cliente. Ocultar el campo en la interfaz o codificarlo no impide editar la petición. `integrityVerified: false` solo describe la respuesta; no valida ni protege nada.

**Cómo interpretar la mitigación:** el carrito alterado puede aceptarse, pero cobra el precio del catálogo: 1000 por unidad. No todo intento de abuso necesita devolver un error si el dato manipulable se ignora de forma segura. Consulta [A08 de mitigaciones](../MITIGACIONES.md#a08).

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

**Por qué este código es vulnerable**

1. El endpoint de demostración llama a `login` con `silent=true`. Ante una contraseña incorrecta, la versión original incrementa un contador y responde 401.
2. Ese número permite observar cuántos fallos hubo en total, pero pierde cuenta intentada, hora, origen y relación entre intentos. No permite distinguir ocho fallos contra una cuenta de ocho errores independientes.
3. No se emite un evento por intento ni se evalúa una regla que genere una alerta. Las listas vacías de telemetría reflejan esa ausencia de implementación.
4. Sin registros suficientes, quien opera el sistema no puede reconstruir la secuencia ni recibir un aviso basado en ella. Que el intento se rechace correctamente no aporta por sí solo esa capacidad de detección.

Aquí el resultado del ataque no es un login exitoso: es una actividad sospechosa que el sistema no deja registrada de forma útil. El contador global y el mensaje de arranque de Docker no sustituyen una auditoría de eventos. La ausencia en consola por sí sola tampoco probaría el fallo en cualquier sistema; en este laboratorio se confirma revisando el método.

**Cómo interpretar la mitigación:** los ocho fallos siguen devolviendo 401, pero ahora producen eventos y una alerta local. La telemetría requiere sesión autorizada. Consulta [A09 de mitigaciones](../MITIGACIONES.md#a09).

**Código:** `LabServer.login` con `silent=true`. Se cuentan fallos para observarlos en clase, pero no se registra usuario, instante, origen, resultado ni correlación; no hay emisor de alertas.

```powershell
1..8 | ForEach-Object { curl.exe -s -d "user=admin&password=wrong" http://localhost:18080/api/a09/login }
curl.exe http://localhost:18080/api/a09/telemetry
docker compose logs lab
```

**Resultado:** todos los intentos fallan con 401; `observedFailures` aumenta ocho, `securityEvents` y `alerts` permanecen vacíos. En los logs solo aparece el mensaje de inicio, no los fallos de autenticación. Los arreglos vacíos son la representación didáctica de los sistemas de auditoría/alertas ausentes, no una consulta a un SIEM real. La evidencia incluye revisar la ausencia de escritura de eventos en el método.

El acceso con contraseña correcta aún funciona. El foco de este ejercicio es detectar y alertar, aunque la ausencia de límites de intentos también se relaciona con A07.

## A10 — Manejo inadecuado de condiciones excepcionales

**Por qué este código es vulnerable**

1. Con `riskService=online`, el simulador evalúa `amount <= 500`. Para 1000 el resultado es falso, por lo que el pago debería rechazarse.
2. Con `riskService=offline`, se lanza una excepción antes de completar esa evaluación. Esto significa «no fue posible decidir», no «el pago es seguro».
3. El `catch` vulnerable convierte la falta de evaluación en permiso mediante `approved = true` y `reason = "fail-open"`.
4. Después del `catch`, el flujo sigue hasta el incremento de `orders` porque `approved` quedó en verdadero. La excepción no solo cambia un mensaje: provoca que se complete una operación que normalmente se rechaza.

Este comportamiento se llama **fail-open**: el sistema concede permiso cuando falla un control. En la demo, el cliente puede activar el interruptor para mostrarlo; en un sistema real, un timeout o una caída del proveedor podría activar el mismo camino si el manejo de errores estuviera mal diseñado.

**Cómo interpretar la mitigación:** online conserva el rechazo 403; offline pasa a 503, sin aumentar pedidos. El código debe salir antes de los efectos de aprobación, como explica [A10 de mitigaciones](../MITIGACIONES.md#a10).

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

Continúa con [MITIGACIONES.md](../MITIGACIONES.md). Las demostraciones anteriores corresponden a la versión vulnerable original; las correcciones que hayas aplicado cambian sus resultados. Reiniciar crea datos nuevos con el código compilado actual, y los cambios Java requieren reconstruir la aplicación. No existe una opción de configuración que convierta este laboratorio en una aplicación apta para producción.
