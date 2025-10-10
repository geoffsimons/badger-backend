# ----------------------------------------------------------------------
# 1. BUILD STAGE: Use a full JDK image to compile and package the application
# ----------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Copy the pom.xml and source code
COPY pom.xml .
COPY src /app/src

# Package the application; -DskipTests is often used for faster builds
RUN mvn clean package -DskipTests

# ----------------------------------------------------------------------
# 2. FINAL STAGE: Use a lightweight JRE image for the final runtime
# ----------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# Expose the application port defined in your Spring configuration (default is 8080)
EXPOSE 8080 

# Copy the generated JAR file from the build stage.
# Replace 'your-app-name-1.0.0.jar' with the actual file name produced by 'mvn package'
COPY --from=builder /app/target/*.jar app.jar

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]