import org.springframework.boot.gradle.tasks.bundling.BootJar

plugins {
    id("org.springframework.boot") version "2.3.0.RELEASE"
    id("io.spring.dependency-management") version "1.0.9.RELEASE"
    kotlin("jvm") version "1.3.71"
}

group = "org.freshlegacycode"
version = "2.2.3.RELEASE"
extra["springCloudVersion"] = "Hoxton.SR5"
ext["spring-cloud-config.version"] = version

springBoot {
    mainClassName = "org.freshlegacycode.cloud.config.server.ConfigServerApplication"
}

tasks.getByName<BootJar>("bootJar") {
    layered()
    archiveFileName.value("${project.name}.jar")
    manifest {
        attributes("Implementation-Title" to project.name, "Implementation-Version" to archiveVersion)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.cloud:spring-cloud-config-server")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.cloud:spring-cloud-dependencies:${property("springCloudVersion")}")
    }
}
