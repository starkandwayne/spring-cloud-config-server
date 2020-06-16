package org.freshlegacycode.cloud.config.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.cloud.config.server.EnableConfigServer;

import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;

@EnableConfigServer
@EnableResourceServer
@SpringBootApplication(exclude = {
        DataSourceAutoConfiguration.class,
        RedisAutoConfiguration.class,
        ManagementContextAutoConfiguration.class,
        ManagementWebSecurityAutoConfiguration.class,
        SecurityAutoConfiguration.class
})
public class ConfigServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ConfigServerApplication.class, args);
    }

    @Profile("!no-actuator")
    @Import(ManagementContextAutoConfiguration.class)
    static class ActuatorBackendConfiguration {}

    @Profile("jdbc")
    @Import(DataSourceAutoConfiguration.class)
    static class JdbcBackendConfiguration {}

    @Profile("redis")
    @Import(RedisAutoConfiguration.class)
    static class RedisBackendConfiguration {}

    @Profile("security")
    @Import({ManagementWebSecurityAutoConfiguration.class, SecurityAutoConfiguration.class})
    static class SecurityConfiguration {}
}
