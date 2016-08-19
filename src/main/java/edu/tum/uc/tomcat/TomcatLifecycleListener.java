package edu.tum.uc.tomcat;

import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;


public class TomcatLifecycleListener implements LifecycleListener{

	public void lifecycleEvent(LifecycleEvent arg0) {
		// TODO Auto-generated method stub
//		System.out.println("TOMCATLIFECYCLELISTENER: "+arg0.getType()+", "+arg0.getLifecycle().getStateName()+", "+arg0.getSource());
		System.out.println("TOMCATLIFECYCLELISTENER: "+arg0.getType()+", "+arg0.getLifecycle().toString()+", "+arg0.getSource());
	}

}
