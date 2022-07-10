namespace w4TR1x.InServerAuthentication;

public abstract class InServerAuthenticationManager : IInServerAuthenticationManager
{
    public List<IAuthenticationSystem> AuthenticationSystems { get; set; } = new()
    {
        new CookieAuthenticationSystem("/index"),
        new JwtAuthenticationSystem()
    };

    ConcurrentDictionary<string, IToken> tokens = new ConcurrentDictionary<string, IToken>();

    private readonly ILoggerFactory _logger;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    public InServerConfigurationOptions Options { get; }
    public TokenValidationParameters TokenValidationParameters { get; }

    public ConcurrentDictionary<string, IToken> Tokens => tokens;

    public InServerAuthenticationManager(ILoggerFactory logger,
        IAuthenticationSchemeProvider schemeProvider,
        InServerConfigurationOptions inServerConfigurationOptions,
        TokenValidationParameters tokenValidationParameters)
    {
        _logger = logger;
        _schemeProvider = schemeProvider;
        Options = inServerConfigurationOptions;
        TokenValidationParameters = tokenValidationParameters;
    }

    public abstract IToken? AuthenticateUser(string username, string password);

    public async Task<string?> AuthenticateByJwt(HttpContext httpContext, string username, string password)
    {
        var token = AuthenticateUser(username, password);

        if (token != null)
        {
            tokens.TryAdd(token.TokenIdentifier, token);

            var authenticationSystem = (JwtAuthenticationSystem)AuthenticationSystems[1];

            var logger = _logger.CreateLogger(authenticationSystem.GetType().Name);

            authenticationSystem.Logger = logger;
            authenticationSystem.Request = httpContext.Request;
            authenticationSystem.InServerAuthenticationManager = this;
            authenticationSystem.Scheme = _schemeProvider
                .GetDefaultChallengeSchemeAsync().GetAwaiter().GetResult()!;

            return await authenticationSystem.Authentication(token);
        }

        return null;
    }

    public async Task<bool> AuthenticateByCookie(HttpContext httpContext, string username, string password, bool rememberMe)
    {
        var token = AuthenticateUser(username, password);

        if (token != null)
        {
            tokens.TryAdd(token.TokenIdentifier, token);

            var authenticationSystem = (CookieAuthenticationSystem)AuthenticationSystems[0];

            var logger = _logger.CreateLogger(authenticationSystem.GetType().Name);

            authenticationSystem.Logger = logger;
            authenticationSystem.Request = httpContext.Request;
            authenticationSystem.InServerAuthenticationManager = this;
            authenticationSystem.Scheme = _schemeProvider
                .GetDefaultChallengeSchemeAsync().GetAwaiter().GetResult()!;

            await authenticationSystem.Authentication(token, rememberMe);

            return true;
        }

        return false;
    }

    public async Task<IToken?> GetTokenFromHttpContext(HttpContext httpContext)
    {
        if (httpContext.User.Identity?.IsAuthenticated != true) return null;

        var tokenIdentifier = httpContext.User.Claims
            .FirstOrDefault(x => x.Type == Options.TokenIdentifierClaimName)?.Value;
        if (tokenIdentifier == null) return null;

        if (!tokens.Where(x => x.Key == tokenIdentifier).Any()) return null;

        return await Task.FromResult(GetToken(tokenIdentifier));
    }

    public IToken? GetToken(string tokenIdentifier)
    {
        if (!tokens.ContainsKey(tokenIdentifier)) return null;

        var token = tokens[tokenIdentifier];

        if (token?.ExpireAt != null && token?.ExpireAt <= DateTime.UtcNow)
        {
            tokens.Remove(tokenIdentifier, out _);
            return null;
        }

        return token;
    }

    public async Task CookieLogout(HttpContext httpContext)
    {
        var authenticationSystem = (CookieAuthenticationSystem)AuthenticationSystems[0];

        var logger = _logger.CreateLogger(authenticationSystem.GetType().Name);

        authenticationSystem.Logger = logger;
        authenticationSystem.Request = httpContext.Request;
        authenticationSystem.InServerAuthenticationManager = this;
        authenticationSystem.Scheme = _schemeProvider
            .GetDefaultChallengeSchemeAsync().GetAwaiter().GetResult()!;

        await authenticationSystem.Logout();
    }
}