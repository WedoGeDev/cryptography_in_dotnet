using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Console;
using System.Security.Cryptography;

namespace ch2_cryptographic_signatures;
class Program
{

    public static RSAParameters SharedParameters { get; private set; }
    static void Main(string[] args)
    {
        using var rsa = RSA.Create();
        SharedParameters = rsa.ExportParameters(true);

        var message = $"Este mensaje fué generado en {DateTime.Now}";
        var signature = SignMessage(message);

        WriteLine(message);

        if (VerifySiignedMessage(message.ComputeMessageHash(), signature))
        {
            WriteLine($"El mensaje '{message}' es válido.");
        }
        else
        {
            WriteLine($"El mensaje '{message}' es inválido.");
        }

        // sender
        var secureMessage = $"Transfer $500 into account number 8c806e2b-969b-46d6-9fd9-3b72821a8ee5 on {DateTime.Now}";
        var digitalSignature = SignMessage(secureMessage);
        // message intercepted
        secureMessage = $"Transfer $5000 into account number 8c806e2b-969b-46d6-9fd9-3b72821a8ee5 on {DateTime.Now}";

        if (VerifySiignedMessage(secureMessage.ComputeMessageHash(), digitalSignature))
        {
            WriteLine($"El mensaje '{secureMessage}' es válido.");
        }
        else
        {
            WriteLine($"El mensaje '{secureMessage}' es inválido.");
        }
        ReadLine();
    }

    private static byte[] SignMessage(string message)
    {
        byte[] hashValue = SHA256.HashData(Encoding.UTF8.GetBytes(message));

        using var rsa = RSA.Create();
        rsa.ImportParameters(SharedParameters);
        var formatter = new RSAPKCS1SignatureFormatter(rsa);
        formatter.SetHashAlgorithm("SHA256");

        return formatter.CreateSignature(hashValue);
    }

    private static bool VerifySiignedMessage(
        byte[] hash,
        byte[] signature)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportParameters(SharedParameters);
            var deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter.VerifySignature(hash, signature);
        }
    }
}
