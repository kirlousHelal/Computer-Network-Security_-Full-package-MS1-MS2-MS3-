using System;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        // FastPower method calculates baseValue raised to the power of exponent modulo modulus
        public int FastPower(int baseValue, int exponent, int modulus)
        {
            if (exponent == 1)
                return baseValue;
            long temp = FastPower(baseValue, exponent / 2, modulus);
            temp = ((temp % modulus) * (temp % modulus)) % modulus;
            if (exponent % 2 != 0)
                temp = ((temp % modulus) * (baseValue % modulus)) % modulus;
            return (int)temp;
        }

        // CalculateD method calculates the multiplicative inverse of 'e' modulo 'phi'
        public int CalculateD(int e, int phi)
        {
            int i = 0;
            while (true)
            {
                if ((e * i) % phi == 1)
                    return i;
                i++;
            }
        }

        // Encrypt method performs RSA encryption on a message 'M'
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int c = FastPower(M, e, n);
            return c;
        }

        // Decrypt method performs RSA decryption on a ciphertext 'C'
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = CalculateD(e, phi);
            int M = FastPower(C, d, n);
            return M;
        }
    }
}
