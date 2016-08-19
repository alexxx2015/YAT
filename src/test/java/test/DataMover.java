package test;

public class DataMover implements IDataMover {
	public byte[] inbuf;
	public byte[] outbuf;
	public int x;
	public static int staticx;
	
	public DataMover() {}
	
	public DataMover(int x) {
		this.x = x;
	}
	
	public void moveData() {
		long[] inbufLong = new long[inbuf.length];
		long[] outbufLong = new long[outbuf.length];
		byteArrayToLongArray(inbuf, inbufLong);
		byteArrayToLongArray(outbuf, outbufLong);
		
		for (int i = 0; i < Math.min(inbuf.length, outbuf.length); i++) {
			outbufLong[i] = inbufLong[i];
		}
		outbufLong[0] = (long)x;
		outbufLong[1] = (long)staticx;
		
		longArrayToByteArray(inbufLong, inbuf);
		longArrayToByteArray(outbufLong, outbuf);
	}
	
	// both arrays should have same length
	private void byteArrayToLongArray(byte[] input, long[] output) {
		for (int i = 0; i < input.length; i++) {
			output[i] = input[i];
		}
	}
	
	// both arrays should have same length
	private void longArrayToByteArray(long[] input, byte[] output) {
		for (int i = 0; i < input.length; i++) {
			output[i] = (byte)input[i];
		}
	}
}
