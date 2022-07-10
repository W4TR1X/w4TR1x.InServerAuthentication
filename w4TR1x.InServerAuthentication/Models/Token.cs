namespace w4TR1x.InServerAuthentication.Models;

public class Token : IToken
{
    public DateTime? ExpireAt { get; set; }
    public string Username { get; set; }
    public string TokenIdentifier { get; set; }
    public List<string> RoleClaims { get; set; } = new();
    public List<Claim> TokenClaims { get; set; } = new();

    public Token(string username, string tokenIdentifier)
    {
        Username = username;
        TokenIdentifier = tokenIdentifier;
    }
}