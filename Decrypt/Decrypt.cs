using System;
using System.IO;
using System.Web;
using System.Web.Security;

namespace Decrypt;

/// <summary>
///     This class serves as a decryption oracle that decrypts an ASP.NET ticket and then lets the user change the username
///     and user data in said ticket.  When it recreates the ticket, it sets the expiry significantly into the future.
/// </summary>
internal static class Decrypt
{
    private static void Main(string[] args)
    {
        // Sometimes these are pretty large, so let's open things up to 8KB
        Console.SetIn(new StreamReader(Console.OpenStandardInput(), Console.InputEncoding, false,
            1024 * 8));

        while (true) GetTicket();
    }

    /// <summary>
    ///     This method decrypts the ticket and returns the decrypted ticket.
    /// </summary>
    /// <param name="encryptedTicket">The encrypted ticket (either base64 or hex)</param>
    /// <returns><c>true</c> iff the ticket was decrypted</returns>
    private static bool DecryptTicket(string encryptedTicket)
    {
        FormsAuthenticationTicket? decryptedTicket;
        try
        {
            decryptedTicket = FormsAuthentication.Decrypt(encryptedTicket);
            if (decryptedTicket is not null)
            {
                Console.WriteLine("The original ticket contains the following data:");
                Console.WriteLine($"Username: {decryptedTicket.Name}");
                Console.WriteLine($"User Data: {decryptedTicket.UserData}");
                Console.WriteLine($"Issue Date: {decryptedTicket.IssueDate}");
                Console.WriteLine($"Expiry: {decryptedTicket.Expiration}");
                Console.WriteLine($"Persistent?: {decryptedTicket.IsPersistent}");
                Console.WriteLine($"Path: {decryptedTicket.CookiePath}");
                Console.WriteLine($"Version: {decryptedTicket.Version}");
                return true;
            }

            Console.WriteLine("The decrypted ticket is null/empty... ignoring");
        }
        catch (ArgumentException)
        {
            Console.WriteLine(
                "Nope... that's not a valid ticket... like a poltroon, I shall flee from the battlefield");
            decryptedTicket = null;
        }
        catch (Exception e) when (e is HttpException or FormatException)
        {
            Console.WriteLine(
                $"{e.Message}... the craven Microsoft decrypter has failed us... or maybe it was YOU?  Perhaps try another string.");
            decryptedTicket = null;
        }

        return false;
    }

    /// <summary>
    ///     This method asks the user to provide us a .NET token (encrypted token).
    /// </summary>
    private static void GetTicket()
    {
        string? line;
        do
        {
            do
            {
                Console.Write(
                    "Please enter the string to decrypt (or 'q' to quit): ");
                line = Console.ReadLine();
            } while (string.IsNullOrEmpty(line));

            switch (line)
            {
                case "q":
                case "Q":
                    Console.WriteLine("Thank you for decrypting with us today");
                    Console.Write("Goodbye!");
                    Environment.Exit(0);
                    break;
            }
        } while (Not(DecryptTicket(line)));
    }

    /// <summary>
    ///     This method negates its input and is designed to make visible negations so as to prevent bugs, especially on
    ///     maintenance.
    /// </summary>
    /// <param name="valueToNegate">The variable to negate</param>
    /// <returns>A boolean of opposite value from the one provided to the method</returns>
    /// <example>
    ///     <c>true</c>-&gt;<c>false</c>
    ///     <c>false</c>-&gt;<c>true</c>
    /// </example>
    private static bool Not(bool valueToNegate)
    {
        return !valueToNegate;
    }
}