package org.tain.working.properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tain.tools.node.MonJsonNode;
import org.tain.tools.properties.ProjEnvBase;
import org.tain.tools.properties.ProjEnvJob;
import org.tain.tools.properties.ProjEnvJson;
import org.tain.tools.properties.ProjEnvParam;
import org.tain.tools.properties.ProjEnvUrl;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class PropertiesWork {

	@Autowired
	private ProjEnvBase projEnvBase;
	
	@Autowired
	private ProjEnvParam projEnvParam;
	
	@Autowired
	private ProjEnvJob projEnvJob;
	
	@Autowired
	private ProjEnvJson projEnvJson;
	
	@Autowired
	private ProjEnvUrl projEnvUrl;
	
	public void working() throws Exception {
		log.info(">>>>> {} {}", "- PARAM --", MonJsonNode.getPrettyJson(this.projEnvParam));
		
		if (Boolean.TRUE) {
			log.info(">>>>> {} {}", "- BASE --", MonJsonNode.getPrettyJson(this.projEnvBase));
			log.info(">>>>> {} {}", "- PARAM -", MonJsonNode.getPrettyJson(this.projEnvParam));
			log.info(">>>>> {} {}", "- JOB  --", MonJsonNode.getPrettyJson(this.projEnvJob));
			log.info(">>>>> {} {}", "- JSON --", MonJsonNode.getPrettyJson(this.projEnvJson));
			log.info(">>>>> {} {}", "- URL  --", MonJsonNode.getPrettyJson(this.projEnvUrl));
		}
	}
}
