using System.IdentityModel.Tokens.Jwt;

namespace w4TR1x.InServerAuthentication.Models.AuthenticationSystems;

internal class JwtAuthenticationSystem : AuthenticationSystemBase
{
    public async Task<string> Authentication(IToken token)
    {
        var secretBytes = Encoding.UTF8.GetBytes(InServerAuthenticationManager.Options.JwtSigningKey);
        var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(secretBytes), SecurityAlgorithms.HmacSha256);

        var jwtToken = new JwtSecurityToken(
            issuer: InServerAuthenticationManager.Options.JwtIssuer,
            audience: InServerAuthenticationManager.Options.JwtAudience,
            claims: token.TokenClaims,
            expires: DateTime.UtcNow.AddDays(2),
            signingCredentials: signingCredentials);

        var tokenHandler = new JwtSecurityTokenHandler();

        var tokenContent = tokenHandler.WriteToken(jwtToken);

        return await Task.FromResult(tokenContent);
    }

    public override async Task<AuthenticateResult> ReadAuthenticationRequest()
    {
        if (!Request.Headers.ContainsKey(InServerAuthenticationManager.Options.JwtAuthorizationHeader!))
            return AuthenticateResult.Fail("Unauthorized");

        string authenticationHeader = Request.Headers[InServerAuthenticationManager.Options.JwtAuthorizationHeader!];

        if (string.IsNullOrWhiteSpace(authenticationHeader)
            || !authenticationHeader.StartsWith("bearer ", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.Fail("Unauthorized");

        var jwt = authenticationHeader[7..];

        try
        {
            var handler = new JwtSecurityTokenHandler();

            handler.ValidateToken(jwt, InServerAuthenticationManager.TokenValidationParameters, out var validateToken);

            var jwtSecurityToken = handler.ReadJwtToken(jwt);

            var tokenIdentifier = jwtSecurityToken.Claims
                .Where(x => x.Type == InServerAuthenticationManager.Options.TokenIdentifierClaimName)
                .FirstOrDefault()?.Value;

            if (string.IsNullOrWhiteSpace(tokenIdentifier))
                return AuthenticateResult.Fail("Unauthorized");

            var token = InServerAuthenticationManager.GetToken(tokenIdentifier);

            if (token == null) return AuthenticateResult.Fail("Unauthorized");

            var identity = new ClaimsIdentity(token.TokenClaims, Scheme.Name);

            var principle = new GenericPrincipal(identity, token.RoleClaims.ToArray());

            var ticket = new AuthenticationTicket(principle, Scheme.Name);

            return await Task.FromResult(AuthenticateResult.Success(ticket));
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, ex.Message);
            return AuthenticateResult.Fail("Unauthorized");
        }
    }
}