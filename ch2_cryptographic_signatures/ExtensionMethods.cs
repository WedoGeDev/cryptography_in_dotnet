using System.Text;
using System.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ch2_cryptographic_signatures
{
    public static class ExtensionMethods
    {
        public static byte[] ComputeMessageHash(this string value)
            => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    }
}