namespace w4TR1x.InServerAuthentication.Interfaces;

public interface IAuthenticationSystem
{
    ILogger Logger { get; set; }
    IInServerAuthenticationManager InServerAuthenticationManager { get; set; }
    AuthenticationScheme Scheme { get; set; }
    HttpRequest Request { get; set; }

    Task<AuthenticateResult> ReadAuthenticationRequest();
}