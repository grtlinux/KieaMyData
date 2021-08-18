package org.tain.working;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tain.working.properties.PropertiesWork;

@Component
public class Work {

	public void working() throws Exception {
		if (Boolean.TRUE) propertiesWork();
	}
	
	///////////////////////////////////////////////////////////////////////////
	
	@Autowired
	private PropertiesWork propertiesWork;
	
	private void propertiesWork() throws Exception {
		if (Boolean.TRUE) this.propertiesWork.working();
	}
}
