# ----------------------------------------------------------------------
# 1. BUILD STAGE: Used to compile the application and generate the JAR
# ----------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Copy the pom.xml and source code
COPY pom.xml .
COPY src /app/src

# Package the application (skipping tests for a cleaner build)
RUN mvn clean package -DskipTests

# ----------------------------------------------------------------------
# 2. FINAL STAGE: Lightweight JRE for runtime execution
# ----------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# Expose the port that the container will listen on (must match ALB target group port)
EXPOSE 8080

# Copy the generated executable JAR file from the builder stage
# The 'target/*.jar' wildcard is useful to catch the full auto-generated name.
COPY --from=builder /app/target/*.jar app.jar

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
