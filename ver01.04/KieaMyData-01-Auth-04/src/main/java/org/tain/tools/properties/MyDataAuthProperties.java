package org.tain.tools.properties;

import java.io.FileInputStream;
import java.util.Properties;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class MyDataAuthProperties {

	private Properties prop = null;
	
	@Bean
	public void start() throws Exception {
		log.info(">>>>> START of MyDataAuthProperties <<<<< ");
		
		String propertiesFile = System.getProperty("mydata.config.file", "/Users/kang-air/KANG/mydata/MyDataAuth.properties");
		log.info(">>>>> propertiesFile: " + propertiesFile);
		
		this.prop = new Properties();
		this.prop.load(new FileInputStream(propertiesFile));
		String lstOrg = this.prop.getProperty("param.lstOrg");
		String daemon = this.prop.getProperty("param.daemon");
		String routeFile = this.prop.getProperty("file.route");
		String storeAuthUrl = this.prop.getProperty("store.auth.url");
		
		log.info(">>>>> lstOrg: " + lstOrg);
		log.info(">>>>> daemon: " + daemon);
		log.info(">>>>> routeFile: " + routeFile);
		log.info(">>>>> storeAuthUrl: " + storeAuthUrl);
	}
	
	public String get(String key) {
		return this.prop.getProperty(key);
	}
}
