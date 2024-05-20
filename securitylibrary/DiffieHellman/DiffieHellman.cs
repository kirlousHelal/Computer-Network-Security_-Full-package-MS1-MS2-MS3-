using System;
using System.Collections.Generic;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>();
            int ya = ModuloPower(alpha, xa, q);
            int yb = ModuloPower(alpha, xb, q);
            int k1 = ModuloPower(ya, xb, q);
            int k2 = ModuloPower(yb, xa, q);
            keys.Add(k1);
            keys.Add(k2);
            return keys;
        }

        private int ModuloPower(int num, int pow, int q)
        {
            int result = 1;
            for (int i = 0; i < pow; i++)
            {
                result = (result * num) % q;
            }
            return result;
        }
    }
}
