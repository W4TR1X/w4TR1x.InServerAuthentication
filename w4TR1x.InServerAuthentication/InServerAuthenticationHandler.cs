namespace w4TR1x.InServerAuthentication;

public class InServerAuthenticationHandler : AuthenticationHandler<InServerAuthenticationOptions>
{
    private readonly IInServerAuthenticationManager _inServiceAuthenticationManager;

    public InServerAuthenticationHandler(IOptionsMonitor<InServerAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock,
        IInServerAuthenticationManager inServiceAuthenticationManager)
        : base(options, logger, encoder, clock)
    {
        _inServiceAuthenticationManager = inServiceAuthenticationManager;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // COOKIE
        IAuthenticationSystem authenticationSystem = _inServiceAuthenticationManager.AuthenticationSystems[0];

        if (IsJwtAuth())
        {
            // JWT
            authenticationSystem = _inServiceAuthenticationManager.AuthenticationSystems[1];
        }

        authenticationSystem.Logger = Logger;
        authenticationSystem.InServerAuthenticationManager = _inServiceAuthenticationManager;
        authenticationSystem.Scheme = Scheme;
        authenticationSystem.Request = Request;

        var result = await authenticationSystem.ReadAuthenticationRequest();

        if (result.Succeeded)
        {
            return result;
        }

        return AuthenticateResult.Fail("Unauthorized");
    }

    bool IsJwtAuth()
    {
        string authorization = Request.Headers[_inServiceAuthenticationManager.Options.JwtAuthorizationHeader!];
        if (!string.IsNullOrWhiteSpace(authorization) && authorization.StartsWith("Bearer "))
            return true; // "Bearer";

        return false; // "Cookies";
    }
}