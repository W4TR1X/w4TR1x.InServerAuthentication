namespace w4TR1x.InServerAuthentication.Models.AuthenticationSystems;

internal abstract class AuthenticationSystemBase : IAuthenticationSystem
{
    public ILogger Logger { get; set; } = null!;
    public IInServerAuthenticationManager InServerAuthenticationManager { get; set; } = null!;
    public AuthenticationScheme Scheme { get; set; } = null!;
    public HttpRequest Request { get; set; } = null!;

    public abstract Task<AuthenticateResult> ReadAuthenticationRequest();
}