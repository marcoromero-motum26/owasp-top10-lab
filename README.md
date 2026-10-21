# Laboratorio Java — OWASP Top 10:2025

Aplicación **deliberadamente vulnerable** para practicar los diez riesgos de seguridad de aplicaciones web de [OWASP Top 10:2025](https://top10.owasp.org/2025/es/). Todos los usuarios, contraseñas, cuentas y pagos son ficticios. No desplegar en producción ni publicar en Internet.

Incluye Java 21, Maven, servidor HTTP del JDK, H2 en memoria, API, página interactiva, pruebas de integración, imágenes Docker y guía independiente de mitigaciones. Las fallas están en el código y se pueden reproducir: no son respuestas de ejemplo prefabricadas.

## Ejecutar con Docker

Requisito: Docker Engine con Compose v2 o posterior; en Windows, Docker Desktop iniciado en modo de contenedores Linux. No necesitas instalar Java o Maven en el equipo.

```sh
docker compose up --build -d --wait
```

Abrir **http://localhost:18080** y ejecutar los botones A01–A10. La primera compilación necesita Internet para descargar imágenes y dependencias. Docker ejecuta las pruebas antes de generar la imagen final.

```sh
docker compose ps
docker compose logs lab
docker compose restart lab
docker compose down
```

`restart` restablece contraseñas, sesiones, base de datos, saldo y contadores. Los datos del laboratorio no se persisten. `down` elimina los contenedores y la red de esta composición.

### Editar la página sin reiniciar

Compose monta `src/main/resources` en `/app/resources` en modo de solo lectura y arranca Java con esa carpeta antes del JAR en el classpath. El servidor lee `index.html` en cada petición y responde con `Cache-Control: no-store`.

Después de guardar cambios en `src/main/resources/index.html` (incluidos su CSS y JavaScript integrados), recarga **http://localhost:18080**. No necesitas reconstruir la imagen ni reiniciar el contenedor, y se conserva el estado del laboratorio.

Si ya tenías un contenedor con la configuración anterior, aplica el nuevo Compose una sola vez:

```sh
docker compose up -d --wait
```

Esta actualización recrea el contenedor y restablece sus datos en memoria. Los cambios posteriores en la página solo requieren recargar el navegador. Los cambios en Java, dependencias o fixtures siguen requiriendo `docker compose up --build -d --wait`. El montaje no agrega rutas HTTP para archivos nuevos: actualmente la página se sirve en `/`. Al ejecutar la imagen directamente con `docker run`, se usa la página empaquetada en el JAR.

Solo se publica `127.0.0.1:18080`. El contenedor usa un usuario sin privilegios, sistema de archivos de solo lectura, `/tmp` efímero y una red Docker dedicada. Estas restricciones contienen el laboratorio; **no corrigen sus vulnerabilidades**. No montes carpetas sensibles ni el socket de Docker. Si ejecutas la imagen con `docker run`, conserva la publicación local: `-p 127.0.0.1:18080:8080 -e LAB_BIND=0.0.0.0`.

## Contenido

| Riesgo 2025 | Ejercicio | Evidencia |
|---|---|---|
| A01 — Pérdida de control de acceso | IDOR en facturas | Alice lee una factura de Bob |
| A02 — Configuración de seguridad incorrecta | Diagnóstico público | Credenciales administrativas ficticias expuestas y utilizables |
| A03 — Fallas en la cadena de suministro | Actualización de un JAR de proveedor | Código alterado cambia el precio de 1000 a 1 |
| A04 — Fallas criptográficas | MD5 sin salt | Contraseñas recuperables con diccionario; hashes repetidos |
| A05 — Inyección | Concatenación de SQL en H2 | La consulta manipulada devuelve tres clientes |
| A06 — Diseño inseguro | Cupón de un solo uso sin control de canje | Crédito repetido en la billetera |
| A07 — Fallas de autenticación | Recuperación de contraseña predecible | Toma de la cuenta de Bob con `reset-bob` |
| A08 — Fallas en la integridad de software o datos | Carrito Base64 sin integridad | Precio manipulado aceptado por el servidor |
| A09 — Fallas en registro y alertas de seguridad | Intentos fallidos sin auditoría | Ocho fallos sin eventos ni alertas |
| A10 — Manejo inadecuado de condiciones excepcionales | Excepción del servicio antifraude | Pago rechazado pasa a aprobado al fallar el servicio |

Un ejercicio representa un caso concreto de cada categoría, no todos sus posibles CWE. Existe solapamiento entre categorías; por ejemplo, A03 también implica integridad de código. El proyecto usa la numeración **2025**, distinta de la de 2021.

## Guías y código

- [Demostraciones paso a paso](docs/DEMOSTRACIONES.md): peticiones, resultados y restablecimiento.
- [MITIGACIONES.md](MITIGACIONES.md): cambios específicos, ejemplos de corrección y criterios de verificación para los diez riesgos.
- [LabServer.java](src/main/java/mx/demo/owasp/LabServer.java): rutas HTTP y métodos identificados con `VULNERABLE Axx`.
- [LabState.java](src/main/java/mx/demo/owasp/LabState.java): usuarios, hashes, estado y H2.
- [SupplyChain.java](src/main/java/mx/demo/owasp/SupplyChain.java) y [fixtures](fixtures): carga de JAR y versiones del proveedor ficticio.
- [LabServerTest.java](src/test/java/mx/demo/owasp/LabServerTest.java): doce pruebas HTTP, con servidor y datos nuevos para cada prueba.
- [SmokeCheck.java](src/main/java/mx/demo/owasp/SmokeCheck.java): demostración automatizada contra el contenedor real.

Usuarios iniciales: `alice/demo123`, `bob/demo123`, `admin/admin123`. El ejercicio A07 cambia la contraseña de Bob a `taken123`. A04 se observa mejor antes de A07. Las sesiones aceptan cookie `LABSESSION` o cabecera `Authorization: Bearer <token>`.

## Validación

```sh
# Con el contenedor iniciado, en cualquier terminal:
docker compose exec lab java -cp /app/owasp-lab.jar mx.demo.owasp.SmokeCheck
```

El verificador Java comprueba los diez ejercicios y falla si sus resultados no coinciden. Modifica únicamente los datos ficticios del laboratorio. Se puede repetir; toma los saldos y contadores actuales como referencia.

```sh
# Repetir la compilación y las pruebas dentro de Docker:
docker build --target build --no-cache -t owasp-2025-lab-tests .
```

Con JDK 21 y Maven 3.9 instalados, también puedes trabajar sin Docker:

```sh
mvn clean verify
java -jar target/owasp-lab.jar
```

Sin Docker, el JAR escucha en `127.0.0.1:8080` por defecto (http://localhost:8080). La variable `LAB_BIND` se cambia a `0.0.0.0` dentro de Compose para permitir la publicación del puerto.

**Interpretación de las pruebas:** pasar significa que las fallas didácticas siguen siendo reproducibles. No significa que la aplicación sea segura. Al implementar mitigaciones, cambia las pruebas por los criterios de rechazo documentados en `MITIGACIONES.md`.

## Límites del ejercicio

- A03 usa dos JAR locales compilados desde fuentes visibles; ejecuta realmente la clase del proveedor. El selector representa una actualización comprometida y no descarga ni permite cargar código arbitrario de Internet.
- A09 no integra un SIEM ni un proveedor de alertas. El contador didáctico registra cuántos fallos ocurrieron; el código omite expresamente emitir eventos de seguridad o alertas.
- A10 usa un interruptor de fallo local; no realiza cobros ni llamadas a un proveedor real.
- Los precios se expresan en pesos enteros ficticios. No hay persistencia ni un modo de producción seguro.
- Las versiones Maven están fijadas para repetir las prácticas; no constituyen una afirmación de ausencia de CVE. Las etiquetas base Docker pueden cambiar de digest; para una clase reproducible archiva la imagen o fija sus digests.

## Solución de problemas

- Error de conexión al motor: inicia Docker Desktop y verifica `docker version`.
- Puerto ocupado: define `LAB_PORT` antes de iniciar Compose (en PowerShell, `$env:LAB_PORT='18081'`) y abre `http://localhost:18081`. El puerto interno sigue siendo 8080.
- Fallo descargando dependencias: revisa conexión y proxy de Docker/Maven y repite la construcción.
- Resultados alterados después de las prácticas: ejecuta `docker compose restart lab` y espera a que `/health` devuelva `UP`.

## Referencias

Categorías y alcance contrastados con [OWASP Top 10:2025](https://top10.owasp.org/2025/es/), [A03: cadena de suministro](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/) y [A10: condiciones excepcionales](https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/). Este laboratorio es independiente y no implica respaldo de OWASP.
