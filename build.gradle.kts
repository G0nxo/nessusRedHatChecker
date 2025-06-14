plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation ("org.jsoup:jsoup:1.17.2")
    implementation ("org.json:json:20240303")
    implementation ("com.opencsv:opencsv:5.8")
}

tasks.test {
    useJUnitPlatform()
}