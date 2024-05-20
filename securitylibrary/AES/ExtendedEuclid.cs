using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int[] A = { 1, 0, baseN };
            int[] B = { 0, 1, number };
            while (true)
            {
                if (B[2] == 0)
                {
                    return -1;
                }
                else if (B[2] == 1)
                {
                    int res = B[1];
                    while (res < 0)
                    {
                        res += baseN;
                    }
                    return res;
                }
                int Q = A[2] / B[2];
                int[] temp = { A[0] - Q * B[0], A[1] - Q * B[1], A[2] - Q * B[2] };
                for (int i = 0; i < 3; i++)
                {
                    A[i] = B[i];
                    B[i] = temp[i];
                }
            }
            return 0;
            //throw new NotImplementedException();
        }
    }
}
