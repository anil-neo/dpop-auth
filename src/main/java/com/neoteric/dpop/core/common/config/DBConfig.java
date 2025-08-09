package com.neoteric.dpop.core.common.config;

import com.neoteric.dpop.core.common.security.PropertyEDCrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class DBConfig {

    @Value("${neoteric.primary-db.user}")
    private String user;
    @Value("${neoteric.primary-db.pw}")
    private String pw;
    @Value("${neoteric.primary-db.url}")
    private String url;
    @Value("${neoteric.primary-db.driver-class-name}")
    private String driveClassName;
    @Value("${neoteric.crypto.mk}")
    private String masterKey;
    @Value("${neoteric.crypto.slt}")
    private String salt;

    @Bean("pgDatasource")
    public DataSource pgDatasource() {
        DataSourceBuilder<?> dataSourceBuilder = DataSourceBuilder.create();
        dataSourceBuilder.username(user);
        dataSourceBuilder.password(PropertyEDCrypt.decrypt(pw, masterKey, salt));
        dataSourceBuilder.url(url);
        dataSourceBuilder.driverClassName(driveClassName);
        return dataSourceBuilder.build();
    }

}
