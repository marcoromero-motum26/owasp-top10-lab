FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY fixtures ./fixtures
COPY src ./src
RUN mvn -B -ntp clean verify

FROM eclipse-temurin:21-jre-jammy AS runtime
WORKDIR /app
COPY --from=build /build/target/owasp-lab.jar /app/owasp-lab.jar
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 CMD ["java", "-cp", "/app/owasp-lab.jar", "mx.demo.owasp.HealthCheck"]
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=65", "-jar", "/app/owasp-lab.jar"]
