package edu.tum.uc.transformer;


import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

public class MyClassWriter extends ClassWriter {
	
	public MyClassWriter(int arg1){
		super(arg1);
	}
	
	public MyClassWriter(ClassReader arg0, int arg1) {
		super(arg0, arg1);
	}

	@Override
	protected String getCommonSuperClass(final String type1, final String type2) {
		if(MainTransformer.getMyClassLoader() == null){
			return super.getCommonSuperClass(type1, type2);
		}
		
		Class<?> c, d;
        ClassLoader classLoader = MainTransformer.getMyClassLoader();
        
        
        try {
            c = Class.forName(type1.replace('/', '.'), false, classLoader);
            d = Class.forName(type2.replace('/', '.'), false, classLoader);
        } catch (Exception e) {
            throw new RuntimeException(e.toString());
        } 

        if (c.isAssignableFrom(d)) {
            return type1;
        }

        if (d.isAssignableFrom(c)) {
            return type2;
        }
        if (c.isInterface() || d.isInterface()) {
            return "java/lang/Object";
        } else {
            do {
                c = c.getSuperclass();
            } while (!c.isAssignableFrom(d));
            return c.getName().replace('.', '/');
        }
    }
}
