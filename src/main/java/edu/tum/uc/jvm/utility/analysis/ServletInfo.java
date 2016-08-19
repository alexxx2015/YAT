package edu.tum.uc.jvm.utility.analysis;

public class ServletInfo implements Comparable<ServletInfo> {
    public String classFQName;
    public boolean hasDoGet;
    public boolean hasDoPost;
    
    public String getClassName() {
	return classFQName.substring(classFQName.lastIndexOf('.')+1);
    }
    
    public String toString() {
	return classFQName + (hasDoGet ? " doGet" : "") + (hasDoPost ? " doPost" : "");
    }

    @Override
    public int compareTo(ServletInfo o) {
	return classFQName.compareTo(o.classFQName);
    }
    
    
}
