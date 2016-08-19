package edu.tum.uc.tomcat;

import java.security.AccessControlException;

import org.springframework.instrument.classloading.tomcat.TomcatInstrumentableClassLoader;




public class TomcatClassLoader extends TomcatInstrumentableClassLoader{
	
	public TomcatClassLoader(){
		super();
		this.initLoader();
		this.addUCTransformer();
//		MirrorStack.runnable = true;
	}
	
	public TomcatClassLoader(ClassLoader parent){
		super(parent);
		this.addUCTransformer();
		this.regPxp();
	}
	
	public void regPxp(){
//		UcCommunicator.getInstance().regPxp();
	}

	private void initLoader(){
		this.setDelegate(false);
		this.setSearchExternalFirst(true);
	}
	
	private void addUCTransformer(){		
		//super.addTransformer(new UcTransformer(true));
//		super.addTransformer(new MyUcTransformer(true));
//	    System.out.println("[TCCL]: Added MyUcTransformer");
	}
	
//	@Override
	public Class<?> loadClasss(String name) throws ClassNotFoundException {
		
		Class<?> cl = loadClass(name, false);
        return cl;
	}
	
	/**
     * Load the class with the specified name, searching using the following
     * algorithm until it finds and returns the class.  If the class cannot
     * be found, returns <code>ClassNotFoundException</code>.
     * <ul>
     * <li>Call <code>findLoadedClass(String)</code> to check if the
     *     class has already been loaded.  If it has, the same
     *     <code>Class</code> object is returned.</li>
     * <li>If the <code>delegate</code> property is set to <code>true</code>,
     *     call the <code>loadClass()</code> method of the parent class
     *     loader, if any.</li>
     * <li>Call <code>findClass()</code> to find this class in our locally
     *     defined repositories.</li>
     * <li>Call the <code>loadClass()</code> method of our parent
     *     class loader, if any.</li>
     * </ul>
     * If the class was found using the above steps, and the
     * <code>resolve</code> flag is <code>true</code>, this method will then
     * call <code>resolveClass(Class)</code> on the resulting Class object.
     *
     * @param name Name of the class to be loaded
     * @param resolve If <code>true</code> then resolve the class
     *
     * @exception ClassNotFoundException if the class was not found
     */
//    @Override
    public synchronized Class<?> loadClasss(String name, boolean resolve)
        throws ClassNotFoundException {
//    	System.out.println("TOMCATCL: "+name);
//		this.printStr2File("LoadClass: "+name);  
    	
//        if (log.isDebugEnabled())
//            log.debug("loadClass(" + name + ", " + resolve + ")");
        Class<?> clazz = null;

        // Log access to stopped classloader
        if (!started) {
            try {
                throw new IllegalStateException();
            } catch (IllegalStateException e) {
//                log.info(sm.getString("webappClassLoader.stopped", name), e);
            }
        }

        // (0) Check our previously loaded local class cache
        clazz = findLoadedClass0(name);
        if (clazz != null) {
//    		this.printStr2File("findLoadedClass0: "+name);  
//            if (log.isDebugEnabled())
//                log.debug("  Returning class from cache");
            if (resolve)
                resolveClass(clazz);
            return (clazz);
        }

        // (0.1) Check our previously loaded class cache
        clazz = findLoadedClass(name);
        if (clazz != null) {
//    		this.printStr2File("findLoadedClass: "+name);  
//            if (log.isDebugEnabled())
//                log.debug("  Returning class from cache");
            if (resolve)
                resolveClass(clazz);
            return (clazz);
        }

//        // (0.2) Try loading the class with the system class loader, to prevent
//        //       the webapp from overriding J2SE classes
        try {
            clazz = system.loadClass(name);
            if (clazz != null) {
                if (resolve)
                    resolveClass(clazz);
                return (clazz);
            }
        } catch (ClassNotFoundException e) {
            // Ignore
        }

        // (0.5) Permission to access this class when using a SecurityManager
        if (securityManager != null) {
//    		this.printStr2File("SecurityManager: "+name);  
            int i = name.lastIndexOf('.');
            if (i >= 0) {
                try {
                    securityManager.checkPackageAccess(name.substring(0,i));
                } catch (SecurityException se) {
                    String error = "Security Violation, attempt to use " +
                        "Restricted Class: " + name;
//                    log.info(error, se);
                    throw new ClassNotFoundException(error, se);
                }
            }
        }

        boolean delegateLoad = delegate || filter(name);

        // (1) Delegate to our parent if requested
        if (delegateLoad) {
//    		this.printStr2File("DelegateLoad: "+name); 
//            if (log.isDebugEnabled())
//                log.debug("  Delegating to parent classloader1 " + parent);
            ClassLoader loader = parent;
            if (loader == null)
                loader = system;
            try {
                clazz = Class.forName(name, false, loader);
                if (clazz != null) {
//                    if (log.isDebugEnabled())
//                        log.debug("  Loading class from parent");
                    if (resolve)
                        resolveClass(clazz);
                    return (clazz);
                }
            } catch (ClassNotFoundException e) {
                // Ignore
            }
        }

        // (2) Search local repositories
//        if (log.isDebugEnabled())
//            log.debug("  Searching local repositories");
        try {
    		this.setSearchExternalFirst(true);
            clazz = findClass(name);
            if (clazz != null) {
//        		this.printStr2File("try2LoadFromlocRep: "+name);
//                if (log.isDebugEnabled())
//                    log.debug("  Loading class from local repository");
                if (resolve)
                    resolveClass(clazz);
                return (clazz);
            }
        } catch (ClassNotFoundException e) {
            // Ignore
//        	this.printStr2File("CNFE: "+e.getMessage());
        } finally{
        	this.setSearchExternalFirst(false);
        }
        
        // (0.2) Try loading the class with the system class loader, to prevent
        //       the webapp from overriding J2SE classes
//        try {
//            clazz = system.loadClass(name);
//            if (clazz != null) {
////        		this.printStr2File("systemLoad: "+name);
//                if (resolve)
//                    resolveClass(clazz);
//                return (clazz);
//            }
//        } catch (ClassNotFoundException e) {
//            // Ignore
//        }

        // (3) Delegate to parent unconditionally
        if (!delegateLoad) {
//            if (log.isDebugEnabled())
//                log.debug("  Delegating to parent classloader at end: " + parent);
            ClassLoader loader = parent;
            if (loader == null)
                loader = system;
            try {
                clazz = Class.forName(name, false, loader);
                if (clazz != null) {
//            		this.printStr2File("Delegate2Parent: "+name);
//                    if (log.isDebugEnabled())
//                        log.debug("  Loading class from parent");
                    if (resolve)
                        resolveClass(clazz);
                    return (clazz);
                }
            } catch (ClassNotFoundException e) {
                // Ignore
            }
        }

        throw new ClassNotFoundException(name);

    }
    
    /**
     * Find the specified class in our local repositories, if possible.  If
     * not found, throw <code>ClassNotFoundException</code>.
     *
     * @param name Name of the class to be loaded
     *
     * @exception ClassNotFoundException if the class was not found
     */
//    @Override
    public Class<?> findClasss(String name) throws ClassNotFoundException {
//    	this.printStr2File("FindClass :"+name);

//        if (log.isDebugEnabled())
//            log.debug("    findClass(" + name + ")");

        // Cannot load anything from local repositories if class loader is stopped
        if (!started) {
            throw new ClassNotFoundException(name);
        }

        // (1) Permission to define this class when using a SecurityManager
        if (securityManager != null) {
            int i = name.lastIndexOf('.');
            if (i >= 0) {
                try {
//                    if (log.isTraceEnabled())
//                        log.trace("      securityManager.checkPackageDefinition");
                    securityManager.checkPackageDefinition(name.substring(0,i));
                } catch (Exception se) {
//                    if (log.isTraceEnabled())
//                        log.trace("      -->Exception-->ClassNotFoundException", se);
                    throw new ClassNotFoundException(name, se);
                }
            }
        }

        // Ask our superclass to locate this class, if possible
        // (throws ClassNotFoundException if it is not found)
        Class<?> clazz = null;
        try {
//            if (log.isTraceEnabled())
//                log.trace("      findClassInternal(" + name + ")");

        	
            if (hasExternalRepositories && searchExternalFirst) {
                try {
                    clazz = super.findClass(name);
                } catch(ClassNotFoundException cnfe) {
                    // Ignore - will search internal repositories next
                } catch(AccessControlException ace) {
//                    log.warn("WebappClassLoader.findClassInternal(" + name
//                            + ") security exception: " + ace.getMessage(), ace);
                    throw new ClassNotFoundException(name, ace);
                } catch (RuntimeException e) {
//                	this.printStr2File("RuntimeException EXCEPTION "+name+"; "+e.getMessage()+", "+e.getClass().getName());
//                    if (log.isTraceEnabled())
//                        log.trace("      -->RuntimeException Rethrown", e);
                    throw e;
                }
            }
            if ((clazz == null)) {
                try {
                    clazz = findClassInternal(name);
                } catch(ClassNotFoundException cnfe) {
                    if (!hasExternalRepositories || searchExternalFirst) {
                        throw cnfe;
                    }
                } catch(AccessControlException ace) {
//                    log.warn("WebappClassLoader.findClassInternal(" + name
//                            + ") security exception: " + ace.getMessage(), ace);
                    throw new ClassNotFoundException(name, ace);
                } catch (RuntimeException e) {
//                    if (log.isTraceEnabled())
//                        log.trace("      -->RuntimeException Rethrown", e);
                    throw e;
                }
            }
            if ((clazz == null) && hasExternalRepositories && !searchExternalFirst) {
                try {
                    clazz = super.findClass(name);
                } catch(AccessControlException ace) {
//                    log.warn("WebappClassLoader.findClassInternal(" + name
//                            + ") security exception: " + ace.getMessage(), ace);
                    throw new ClassNotFoundException(name, ace);
                } catch (RuntimeException e) {
//                    if (log.isTraceEnabled())
//                        log.trace("      -->RuntimeException Rethrown", e);
                    throw e;
                }
            }
            if (clazz == null) {
//                if (log.isDebugEnabled())
//                    log.debug("    --> Returning ClassNotFoundException");
                throw new ClassNotFoundException(name);
            }
        } catch (ClassNotFoundException e) {
//            if (log.isTraceEnabled())
//                log.trace("    --> Passing on ClassNotFoundException");
            throw e;
        }

        // Return the class we have located
//        if (log.isTraceEnabled())
//            log.debug("      Returning class " + clazz);
        
//        if (log.isTraceEnabled()) {
//            ClassLoader cl;
//            if (Globals.IS_SECURITY_ENABLED){
//                cl = AccessController.doPrivileged(
//                    new PrivilegedGetClassLoader(clazz));
//            } else {
//                cl = clazz.getClassLoader();
//            }
//            log.debug("      Loaded by " + cl.toString());
//        }
        return (clazz);
    }
    
    public Class<?> findClassInternall(String name) throws ClassNotFoundException {
    	return super.findClassInternal(name);
    }
	
	
//	public void addTransformer(ClassFileTransformer transformer){
//		super.addTransformer(transformer);
//	}
//	
//	public ClassLoader getThrowawayClassLoader(){
//		return super.getThrowawayClassLoader();
//	}
//	
//	public String toString(){
//		return super.toString();
//	}
}
