using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Schema;

namespace AES
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] key = Key.GenerateRandomKey(16);

            string str = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's" +
                " standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type " +
                "specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially " +
                "unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently " +
                "with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum";

           
            var result = AES.Encrypt(str, key);

            Console.WriteLine(AES.Decrypt(result, key));

        }

    }

    public class Key
    {
        static public byte[] GenerateRandomKey(int keySize)
        {
            byte[] key = new byte[keySize];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            return key;
        }
    }

    public class AES
    {
        private static byte[,] sBox =
        {
        // Linia 0
        { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
        // Linia 1
        { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
        // Linia 2
        { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
        // Linia 3
        { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
        // Linia 4
        { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
        // Linia 5
        { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
        // Linia 6
        { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
        // Linia 7
        { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
        // Linia 8
        { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
        // Linia 9
        { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
        // Linia 10
        { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
        // Linia 11
        { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
        // Linia 12
        { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
        // Linia 13
        { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
        // Linia 14
        { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
        // Linia 15
        { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
    };
        private static byte[,] InvSBox =  {
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

        private static int Nk = 4;
        private static int Nr = 10;

        private static byte[] Rcon = { 0x0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


        private const int modulus = 0x1B; // x^8 + x^4 + x^3 + x + 1

        // Multiply two numbers in GF(2^8)
        private static byte Multiply(byte a, byte b)
        {
            byte result = 0;
            byte carry;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                    result ^= a;
                carry = (byte)(a & 0x80);
                a <<= 1;
                if (carry != 0)
                    a ^= modulus;
                b >>= 1;
            }
            return result;
        }

        private static byte[] KeyExpansion(byte[] key)
        {
            byte[] w = new byte[16 * (Nr + 1)];

            int i = 0;

            while (i < 16)
                w[i] = key[i++];

            i = 4;

            while (i <= 4 * Nr + 3)
            {
                byte[] temp = new byte[4];
                int j = 0;
                while (j < 4)
                {
                    temp[j] = w[4 * (i - 1) + j];
                    j++;
                }

                if (i % Nk == 0)
                {
                    byte[] bytes = new byte[4];
                    bytes[0] = temp[1];
                    bytes[1] = temp[2];
                    bytes[2] = temp[3];
                    bytes[3] = temp[0];

                    bytes = SubWord(bytes);

                    byte[] CBYtes = { Rcon[i / Nk], 0x0, 0x0, 0x0 };

                    temp[0] = (byte)(bytes[0] ^ CBYtes[0]);
                    temp[1] = (byte)(bytes[1] ^ CBYtes[1]);
                    temp[2] = (byte)(bytes[2] ^ CBYtes[2]);
                    temp[3] = (byte)(bytes[3] ^ CBYtes[3]);
                }

                for (j = 0; j < 4; j++)
                    w[4 * i + j] = (byte)(temp[j] ^ w[4 * (i - Nk) + j]);

                i++;
            }

            return w;
        }

        private static byte[,] AddRoundKey(byte[,] input, byte[,] w)
        {
            //iterate a matrix
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    input[i, j] ^= w[i, j];

            return input;
        }

        private static byte[,] CopyWKey(byte[] wkey, int n)
        {
            byte[,] w = new byte[4, 4];
            for (int i = 0; i < 16; ++i)
            {
                w[i % 4, i / 4] = wkey[i + n];
            }
            return w;
        }

        private static byte[,] SubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = sBox[state[i, j] >> 4, state[i, j] & 0x0f];

            return state;
        }

        private static byte[] SubWord(byte[] bytes)
        {
            for (int i = 0; i < 4; ++i)
                bytes[i] = sBox[bytes[i] >> 4, bytes[i] & 0x0f];

            return bytes;
        }

        private static byte[,] InvSubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = InvSBox[state[i, j] >> 4, state[i, j] & 0x0f];

            return state;
        }

        private static byte[,] ShiftRows(byte[,] state)
        {
            byte[,] newState = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    newState[i, j] = state[i, (i + j) % 4];

            return newState;
        }

        private static byte[,] InvShiftRows(byte[,] state)
        {
            int n = state.GetLength(0); 

            for (int row = 1; row < n; row++)
            {
                int shiftAmount = row; 
                byte[] tempRow = new byte[n]; 

                for (int col = 0; col < n; col++)
                {
                    int shiftedIndex = (col + shiftAmount) % n;
                    tempRow[shiftedIndex] = state[row, col];
                }

                for (int col = 0; col < n; col++)
                {
                    state[row, col] = tempRow[col];
                }
            }
            return state;
        }


        private static byte[,] MixColumns(byte[,] state)
        {
            byte[,] newState = new byte[4, 4];

            for (int c = 0; c < 4; c++)
            {
                newState[0, c] = (byte)(Multiply(state[0, c], 0x02) ^ Multiply(state[1, c], 0x03) ^ state[2, c] ^ state[3, c]);
                newState[1, c] = (byte)(state[0, c] ^ Multiply(state[1, c], 0x02) ^ Multiply(state[2, c], 0x03) ^ state[3, c]);
                newState[2, c] = (byte)(state[0, c] ^ state[1, c] ^ Multiply(state[2, c], 2) ^ Multiply(state[3, c], 3));
                newState[3, c] = (byte)(Multiply(state[0, c], 0x03) ^ state[1, c] ^ state[2, c] ^ Multiply(state[3, c], 0x02));
            }

            return newState;
        }

        private static byte[,] InvMixColumns(byte[,] state)
        {
            byte[,] newState = new byte[4, 4];

            for (int c = 0; c < 4; c++)
            {
                newState[0, c] = (byte)(Multiply(state[0, c], 0x0e) ^ Multiply(state[1, c], 0x0b) ^ Multiply(state[2, c], 0x0d) ^ Multiply(state[3, c], 0x09));
                newState[1, c] = (byte)(Multiply(state[0, c], 0x09) ^ Multiply(state[1, c], 0x0e) ^ Multiply(state[2, c], 0x0b) ^ Multiply(state[3, c], 0x0d));
                newState[2, c] = (byte)(Multiply(state[0, c], 0x0d) ^ Multiply(state[1, c], 0x09) ^ Multiply(state[2, c], 0x0e) ^ Multiply(state[3, c], 0x0b));
                newState[3, c] = (byte)(Multiply(state[0, c], 0x0b) ^ Multiply(state[1, c], 0x0d) ^ Multiply(state[2, c], 0x09) ^ Multiply(state[3, c], 0x0e));
            }

            return newState;
        }

        private static byte[] Cipher(byte[] input, int Nr, byte[] wkey)
        {
            byte[,] state = new byte[4, 4];
            byte[,] w = new byte[4, 4];

            for (int i = 0; i < 4; ++i)
                for (int j = 0; j < 4; ++j)
                    state[i, j] = input[i + 4 * j];

            w = CopyWKey(wkey, 0);

            state = AddRoundKey(state, w);

            int round;
            for (round = 1; round < Nr; ++round)
            {
                var state1 = SubBytes(state);
                state = ShiftRows(state1);
                state = MixColumns(state);
                w = CopyWKey(wkey, 16 * round);
                state = AddRoundKey(state, w);
            }

            var state2 = SubBytes(state);
            state = ShiftRows(state2);
            w = CopyWKey(wkey, 16 * round);
            state = AddRoundKey(state, w);

            byte[] output = new byte[16];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    output[i + 4 * j] = state[i, j];

            return output;
        }

        private static byte[] InvChipher(byte[] input, int Nr, byte[] wkey)
        {
            byte[,] state = new byte[4, 4];
            byte[,] w;

            for (int i = 0; i < 4; ++i)
                for (int j = 0; j < 4; ++j)
                    state[i, j] = input[i + 4 * j];

            int round = Nr;
            w = CopyWKey(wkey, 16 * round);
            state = AddRoundKey(state, w);

            for (round = Nr - 1; round > 0; round--)
            {
                var state2 = InvShiftRows(state);
                state = InvSubBytes(state2);
                w = CopyWKey(wkey, 16 * round);
                state = AddRoundKey(state, w);
                state = InvMixColumns(state);
            }

            var state1 = InvShiftRows(state);
            state = InvSubBytes(state1);
            w = CopyWKey(wkey, 16 * round);
            state = AddRoundKey(state, w);

            byte[] output = new byte[16];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    output[i + 4 * j] = state[i, j];

            return output;
        }

        public static byte[] Encrypt(string input, byte[] key)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(input);

            int len = bytes.Length;

            if (bytes.Length % 16 != 0)
                len = bytes.Length + (16 - bytes.Length % 16);

            byte[] byt = new byte[len];

            Console.WriteLine(len);

            for (int i = 0; i < byt.Length; i++)
                if (i < bytes.Length)
                    byt[i] = bytes[i];
                else
                    byt[i] = (byte)'\0';

            var wkey = KeyExpansion(key);

            var output = new byte[len];

            for (int i = 0; i < byt.Length; i += 16)
            {
                byte[] text = new byte[16];
                for (int j = 0; j < 16; j++)
                    text[j] = byt[j + i];

                byte[] result = AES.Cipher(text, 10, wkey);

                for(int j = 0;j < 16; j++)
                    output[i + j] = result[j];

            }

            return output;
        }

        public static string Decrypt(byte[] input, byte[] key)
        {
            if (input.Length % 16 != 0) throw new Exception();
            string output = "";

            var wkey = KeyExpansion(key);

            for (int i = 0; i < input.Length; i += 16)
            {
                byte[] text = new byte[16];
                for (int j = 0; j < 16; j++)
                    text[j] = input[j + i];

                byte[] result = AES.InvChipher(text, 10, wkey);

                output += Encoding.ASCII.GetString(result);
            }

            return output;
        }
    }
}
