package org.tain.tools.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Component
@ConfigurationProperties(prefix = "proj-env.param")
@Data
public class ProjEnvParam {

	private String name;  // default
	
	private List<String> lstOrg;
	private String daemon;
	
	private String dummy;  // null
}
