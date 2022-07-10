namespace w4TR1x.InServerAuthentication.Models.AuthenticationSystems;

internal class CookieAuthenticationSystem : AuthenticationSystemBase
{
    public string PathToRedirect { get; set; }
    public CookieAuthenticationSystem(string pathToRedirect)
    {
        PathToRedirect = pathToRedirect;
    }

    internal async Task Authentication(IToken token, bool remember)
    {
        var identity = new ClaimsIdentity(token.TokenClaims, Scheme.Name);

        var authProperties = new AuthenticationProperties
        {
            ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7),
            IsPersistent = remember,
            IssuedUtc = DateTime.UtcNow,
            RedirectUri = PathToRedirect
        };

        await Request.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity), authProperties);
    }

    public override async Task<AuthenticateResult> ReadAuthenticationRequest()
    {
        if (!Request.Cookies.ContainsKey(InServerAuthenticationManager.Options.CookieName!))
            return AuthenticateResult.Fail("Unauthorized");

        string? authenticationCookie = Request.Cookies[InServerAuthenticationManager.Options.CookieName!];

        if (string.IsNullOrWhiteSpace(authenticationCookie))
        {
            await Logout();
            return AuthenticateResult.Fail("Unauthorized");
        }

        try
        {
            var opt = Request.HttpContext.RequestServices
                .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
                .Get(CookieAuthenticationDefaults.AuthenticationScheme);

            var cookieTicket = opt.TicketDataFormat.Unprotect(authenticationCookie);
            if (cookieTicket == null)
            {
                await Logout();
                return AuthenticateResult.Fail("Unauthorized");
            }

            var tokenIdentity = cookieTicket.Principal.Claims
                .Where(x => x.Type == InServerAuthenticationManager.Options.TokenIdentifierClaimName)
                .FirstOrDefault()?.Value;

            if (tokenIdentity == null)
            {
                await Logout();
                return AuthenticateResult.Fail("Unauthorized");
            }

            var token = InServerAuthenticationManager.GetToken(tokenIdentity);
            if (token == null)
            {
                await Logout();
                return AuthenticateResult.Fail("Unauthorized");
            }

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

    public async Task Logout()
    {
        await Request.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
