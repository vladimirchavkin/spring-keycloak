# Этап 1: Сборка приложения
FROM gradle:8.10-jdk21 AS builder

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем только необходимые файлы для кэширования зависимостей
COPY gradle ./gradle
COPY gradlew ./
COPY build.gradle.kts settings.gradle.kts ./

# Загружаем зависимости (кэшируется, если не меняются build.gradle)
RUN ./gradlew dependencies --no-daemon || true

# Копируем исходный код
COPY src ./src

# Собираем JAR (пропускаем тесты для ускорения, если нужно — уберите -x test)
RUN ./gradlew clean bootJar -x test --no-daemon

# Этап 2: Создание финального образа
FROM bellsoft/liberica-openjre-alpine

WORKDIR /app

# Копируем JAR из этапа сборки
COPY --from=builder /app/build/libs/keycloak-demo-*.jar app.jar

# Открываем порт
EXPOSE 8088

# Метки
LABEL maintainer="chavkin.em@example.com"
LABEL description="Spring Boot + Keycloak Demo (Gradle)"
LABEL version="1.0"

# Запуск
ENTRYPOINT ["java", "-jar", "/app/app.jar"]