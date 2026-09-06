# Multi-stage build for Keycloak Pinterest Broker Extension
FROM maven:3.9-eclipse-temurin-21-alpine AS builder

WORKDIR /build

COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -B

# Keycloak image with custom provider pre-augmented
FROM quay.io/keycloak/keycloak:26.7.3

COPY --from=builder /build/target/keycloak-broker-pinterest-1.0.0.jar /opt/keycloak/providers/

# Run Quarkus build to pre-optimize and verify SPI registration
RUN /opt/keycloak/bin/kc.sh build
