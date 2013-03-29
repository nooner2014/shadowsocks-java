/*  Shadowsocks-java - A java port of shadowsocks.
 *  Copyright (C) 2013 @xierch
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.security.MessageDigest;
import java.math.BigInteger;

public class Secret {
	private byte[] table; // Use for encrypt
	private byte[] rtable; // User for decrypt
	private BigInteger key = null;
	private int salt;

	public void encrypt(byte[] data) {
		translate(data, table);
	}

	public void decrypt(byte[] data) {
		translate(data, rtable);
	}

	private void translate(byte[] data, byte[] tranTable) {
		for (int i = 0; i < data.length; i++)
			data[i] = tranTable[data[i] & 255];
	}

	private int randomCompare(byte x, byte y) {
		// Compare (key % (x + salt)) and (key % (y + salt))
		byte[] ax = new byte[2], ay = new byte[2];
		ax[1] = x;
		ay[1] = y;
		BigInteger s = new BigInteger("" + salt);
		BigInteger m = new BigInteger(ax).add(s);
		BigInteger n = new BigInteger(ay).add(s);
		m = key.mod(m);
		n = key.mod(n);
		return m.compareTo(n);
	}

	private void mergeSort(byte[] list, byte[] temp, int low, int upper) {
		if (low == upper) {
			return;
		} else {
			int mid = (low + upper) / 2;
			mergeSort(list, temp, low, mid);
			mergeSort(list, temp, mid + 1, upper);
			merge(list, temp, low, mid + 1, upper);
		}
	}

	private void merge(byte[] list, byte[] temp, int left, int right, int last) {
		int j = 0;
		int lowIndex = left;
		int mid = right - 1;
		int n = last - lowIndex + 1;
		while (left <= mid && right <= last) {
			if (randomCompare(list[left], list[right]) <= 0) {
				temp[j++] = list[left++];
			} else {
				temp[j++] = list[right++];
			}
		}
		while (left <= mid) {
			temp[j++] = list[left++];
		}
		while (right <= last) {
			temp[j++] = list[right++];
		}
		for (j = 0; j < n; j++) {
			list[lowIndex + j] = temp[j];
		}
	}
	
	private byte[] getTable(String keyString) {
		// Get a key:
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5 = md.digest(keyString.getBytes("UTF-8"));

			byte[] bigInt = new byte[9];
			for (int i = 0; i < 8; i++)
				bigInt[i + 1] = md5[7 - i];
			key = new BigInteger(bigInt);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Get a table:
		byte[] table = new byte[256];
		byte b = 0;
		for (int i = 0; i < 256; i++, b++)
			table[i] = b;

		for (salt = 1; salt < 1024; salt++)
			mergeSort(table, new byte[256], 0, 255);

		return table;
	}


	Secret(String keyString) {
		table = getTable(keyString);
		rtable = new byte[256];
		byte b = 0;
		for (int i = 0; i < 256; i++)
			rtable[table[i] & 255] = b++;
	}
}