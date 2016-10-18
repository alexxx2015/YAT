package edu.tum.uc.jvm.utility;

import java.lang.management.ManagementFactory;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeDataSupport;

import sun.misc.Unsafe;

@SuppressWarnings("restriction")
/**
 * This class provides an interface to <code>the sun.misc.Unsafe</code>.
 * 
 * @author vladi
 *
 */
public class UnsafeUtil {

	/*
	 * Lengths of data types measured in bytes.
	 */
	public final static int NUM_BYTES_BOOLEAN = 1;
	public final static int NUM_BYTES_BYTE = 1;
	public final static int NUM_BYTES_CHAR = 2;
	public final static int NUM_BYTES_SHORT = 2;
	public final static int NUM_BYTES_INT = 4;
	public final static int NUM_BYTES_FLOAT = 4;
	public final static int NUM_BYTES_LONG = 8;
	public final static int NUM_BYTES_DOUBLE = 8;

	/**
	 * Sizes mapped to primitive data types
	 */
	private static final Map<Class<?>, Integer> primitiveSizes;

	static {
		primitiveSizes = new IdentityHashMap<Class<?>, Integer>();
		primitiveSizes.put(boolean.class, NUM_BYTES_BOOLEAN);
		primitiveSizes.put(byte.class, NUM_BYTES_BYTE);
		primitiveSizes.put(char.class, NUM_BYTES_CHAR);
		primitiveSizes.put(short.class, NUM_BYTES_SHORT);
		primitiveSizes.put(int.class, NUM_BYTES_INT);
		primitiveSizes.put(float.class, NUM_BYTES_FLOAT);
		primitiveSizes.put(double.class, NUM_BYTES_DOUBLE);
		primitiveSizes.put(long.class, NUM_BYTES_LONG);
	}

	/**
	 * A boolean indicating if the JVM is running in compressed OOps mode.
	 */
	private static boolean compressedOops;

	static {
		try {
			MBeanServer server = ManagementFactory.getPlatformMBeanServer();
			ObjectName mbean = new ObjectName("com.sun.management:type=HotSpotDiagnostic");
			CompositeDataSupport compressedOopsValue = (CompositeDataSupport) server.invoke(mbean, "getVMOption",
					new Object[] { "UseCompressedOops" }, new String[] { "java.lang.String" });
			compressedOops = Boolean.valueOf(compressedOopsValue.get("value").toString());
		} catch (Exception e) {
			compressedOops = false;
		}

	}

	/**
	 * Returns the address of a given object.
	 * 
	 * @param obj
	 *            The object to retrieve the address from.
	 * @return A long representation of the given object's address.
	 */
	public static long getObjectAddress(Object obj) {
		Object[] array = new Object[] { obj };
		long baseOffset = getUnsafe().arrayBaseOffset(Object[].class);
		int size = getUnsafe().addressSize();
		long address = getUnsafe().getInt(array, baseOffset);
		if(size == 8) 
			address = getUnsafe().getLong(array, baseOffset);
//		System.out.println("Size: "+getUnsafe().addressSize());
//		System.out.println("ADDR: "+address);
		return normalize(getUnsafe().getInt(array, baseOffset));
		// long address = normalize(getUnsafe().getInt(array, baseOffset));
		// long myaddr = getUnsafe().allocateMemory(50L);
		// int addressSize = getUnsafe().addressSize();
		// long address = getUnsafe().getInt(array, baseOffset);
		// if (addressSize == 8)
		// address = getUnsafe().getLong(array, baseOffset);
		// return address;
	}

	/**
	 * Resolves the given address and returns the object being stored at that
	 * address.
	 * 
	 * @param address
	 *            The address of an object.
	 * @return The object being at the address.
	 */
	public static Object objectFromAddress(long address) {
		Object[] array = new Object[] { null };
		long baseOffset = getUnsafe().arrayBaseOffset(Object[].class);
		getUnsafe().putLong(array, baseOffset, address);
		return array[0];
	}

	/**
	 * Replaces a given object by another one in memory. If they do not have the
	 * same size (e.g. being of different type, an
	 * <code>IllegalArgumentException</code> is thrown.
	 * 
	 * @param oldObject
	 *            The object to overwrite.
	 * @param newObject
	 *            The object to put in place of the old object.
	 */
	public static void replaceObject(Object oldObject, Object newObject) {
		long fromAddress = getObjectAddress(newObject);
		long toAddress = getObjectAddress(oldObject);
		long oldSize = sizeOf(oldObject);
		long newSize = sizeOf(newObject);
		if (oldSize == newSize) {
			getUnsafe().copyMemory(decode(fromAddress), decode(toAddress), oldSize);
		} else {
			throw new IllegalArgumentException("Objects must have the same size");
		}
	}

	/**
	 * Retrieves the singleton instance of <code>sun.misc.Unsafe</code>.
	 * 
	 * @return The Unsafe singleton.
	 */
	private static Unsafe getUnsafe() {
		try {
			Field f = Unsafe.class.getDeclaredField("theUnsafe");
			f.setAccessible(true);
			Unsafe unsafe = (Unsafe) f.get(null);
			return unsafe;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Shifts the given address by 3 bits to the left if compressed oops mode is
	 * on, otherwise returns the argument.
	 * 
	 * @param coopAddress
	 *            Address before conversion.
	 * @return The converted address.
	 */
	private static long decode(long coopAddress) {
		return compressedOops ? coopAddress << 3 : coopAddress;
	}

	/**
	 * Converts a given integer into a long by applying a shift and logical and
	 * operation. Used for addresses.
	 * 
	 * @param value
	 *            An integer value
	 * @return The converted long.
	 */
	public static long normalize(int value) {
		if (value >= 0)
			return value;
		return (~0L >>> 32) & value;
	}

	/**
	 * Computes the size of an object in memory.
	 * 
	 * @param o
	 *            The object to compute the memory size of. Must not be an
	 *            array.
	 * @return The memory size of the object.
	 */
	private static long sizeOfInstance(Object o) {
		Unsafe u = getUnsafe();
		HashSet<Field> fields = new HashSet<Field>();
		Class<?> c = o.getClass();
		// traverse class hierarchy to get all fields of the object
		while (c != Object.class) {
			for (Field f : c.getDeclaredFields()) {
				if ((f.getModifiers() & Modifier.STATIC) == 0) {
					fields.add(f);
				}
			}
			c = c.getSuperclass();
		}

		// get maximum offset of all fields
		long maxSize = 0;
		for (Field f : fields) {
			long offset = u.objectFieldOffset(f);
			if (offset > maxSize) {
				maxSize = offset;
			}
		}

		// pad the result
		return ((maxSize / 8) + 1) * 8;
	}

	/**
	 * Returns the size of a given object or array.
	 * 
	 * @param o
	 *            The object or array to compute the memory size of.
	 * @return The memory size of the object or array.
	 */
	public static long sizeOf(Object o) {
		if (o.getClass().isArray()) {
			return sizeOfArray(o);
		} else {
			return sizeOfInstance(o);
		}
	}

	/**
	 * Computes the size of an array in memory.
	 * 
	 * @param o
	 *            The array to compute the memory size of. Must not be an object
	 *            other than an array.
	 * @return The memory size of the array.
	 */
	private static long sizeOfArray(Object array) {
		long size = getUnsafe().arrayBaseOffset(array.getClass());
		final int len = Array.getLength(array);
		if (len > 0) {
			// length of array is determined by its size and element count
			Class<?> arrayElementClass = array.getClass().getComponentType();
			if (arrayElementClass.isPrimitive()) {
				size += (long) len * getUnsafe().arrayIndexScale(array.getClass());
			} else {
				size += (long) len * 8;
			}
		}
		// add padding
		return ((size / 8) + 1) * 8;
	}
}
