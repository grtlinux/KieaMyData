package org.tain.tools.properties;

import java.io.File;
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
		
		prop = new Properties();
		prop.load(new FileInputStream(new File(propertiesFile)));
		String lstOrg = prop.getProperty("param.lstOrg");
		String daemon = prop.getProperty("param.daemon");
		String routeFile = prop.getProperty("file.route");
		
		log.info(">>>>> lstOrg: " + lstOrg);
		log.info(">>>>> daemon: " + daemon);
		log.info(">>>>> routeFile: " + routeFile);
	}
}
