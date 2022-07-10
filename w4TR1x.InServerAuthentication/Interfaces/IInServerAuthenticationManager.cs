namespace w4TR1x.InServerAuthentication.Interfaces;

public interface IInServerAuthenticationManager
{
    InServerConfigurationOptions Options { get; }
    TokenValidationParameters TokenValidationParameters { get; }

    List<IAuthenticationSystem> AuthenticationSystems { get; set; }
    ConcurrentDictionary<string, IToken> Tokens { get; }

    IToken? GetToken(string tokenIdentifier);

    Task<IToken?> GetTokenFromHttpContext(HttpContext httpContext);

    Task<string?> AuthenticateByJwt(HttpContext httpContext, string username, string password);
    Task<bool> AuthenticateByCookie(HttpContext httpContext, string username, string password, bool rememberMe);
    Task CookieLogout(HttpContext httpContext);
}