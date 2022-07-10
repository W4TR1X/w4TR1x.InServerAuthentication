using System.Security.Claims;

namespace w4TR1x.InServerAuthentication.Interfaces;

public interface IToken
{
    public DateTime? ExpireAt { get; set; }
    public string Username { get; set; }
    public string TokenIdentifier { get; set; }

    public List<string> RoleClaims { get; set; }
    public List<Claim> TokenClaims { get; set; }
}