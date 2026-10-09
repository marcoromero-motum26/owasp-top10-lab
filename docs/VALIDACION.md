# Validación realizada

Fecha: 8 de octubre de 2026.

## Compilación y pruebas

La construcción Docker ejecutó `mvn -B -ntp clean verify` con Java 21:

```text
Tests run: 12, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Las pruebas usan HTTP contra un servidor real y una base H2 nueva por caso. Verifican las diez vulnerabilidades, controles de referencia (por ejemplo acceso sin sesión y pago rechazado), página inicial, salud y límite de tamaño de entrada.

## Contenedor final

Se ejecutó el verificador incluido en el JAR empaquetado:

```sh
docker compose exec -T lab java -cp /app/owasp-lab.jar mx.demo.owasp.SmokeCheck
```

Resultado: **10/10 demostraciones verificadas**, incluidas la ejecución del JAR alterado y la inyección SQL real. Esto también comprueba que los artefactos del proveedor se empaquetaron y funcionan con el usuario sin privilegios y el sistema de archivos de solo lectura.

Desde el anfitrión se comprobó:

- `http://127.0.0.1:18080/health`: HTTP 200, `status=UP`, `edition=2025`.
- `http://127.0.0.1:18080/`: HTTP 200, página con los ejercicios A01–A10.
- Estado Docker: `healthy`.

Se eligió 18080 porque el puerto 8080 del anfitrión ya estaba ocupado. El puerto Java dentro del contenedor es 8080. La verificación final usa Java dentro de Docker y no depende de permisos de ejecución de scripts PowerShell.

No se realizó automatización visual de navegador ni un análisis exhaustivo de vulnerabilidades de dependencias. Las pruebas acreditan la reproducibilidad de los ejercicios, no la seguridad de la aplicación. Después de verificar, se reinicia el laboratorio para recuperar los datos iniciales.
