namespace w4TR1x.InServerAuthentication.Models;

public class InServerConfigurationOptions
{
    public string? SchemeName { get; set; }
    public string? CookieName { get; set; }
    public string? JwtAuthorizationHeader { get; set; }
    public string? TokenIdentifierClaimName { get; set; }

    public string JwtIssuer { get; set; }
    public string JwtAudience { get; set; }
    public string JwtSigningKey { get; set; }

    public InServerConfigurationOptions(string jwtIssuer, string jwtAudience, string jwtSigningKey)
    {
        JwtIssuer = jwtIssuer;
        JwtAudience = jwtAudience;
        JwtSigningKey = jwtSigningKey;
    }

}