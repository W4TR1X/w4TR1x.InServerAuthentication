using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using w4TR1x.InServerAuthentication;
using w4TR1x.InServerAuthentication.Interfaces;
using w4TR1x.InServerAuthentication.Models;

namespace SampleApp.Services
{
    public class TestInServerAuthenticationManager : InServerAuthenticationManager
    {
        public TestInServerAuthenticationManager(ILoggerFactory logger,
            IAuthenticationSchemeProvider schemeProvider,
            InServerConfigurationOptions inServerConfigurationOptions,
            TokenValidationParameters tokenValidationParameters)
            : base(logger, schemeProvider, inServerConfigurationOptions, tokenValidationParameters) { }

        public override IToken? AuthenticateUser(string username, string password)
        {
            if (username != "john" || password != "doe123") return null;

            var token = new Token("john.doe", Guid.NewGuid().ToString())
            {
                ExpireAt = DateTime.UtcNow.AddMinutes(30),
                RoleClaims = new()
                {
                    "App.User.Permission",

                    "App.Privacy.View",

                    "App.Project.1.View",
                    "App.Project.1.Create",
                    "App.Project.1.Edit",
                    "App.Project.1.Delete",
                },
                TokenClaims = new()
                {
                    new Claim(ClaimTypes.GivenName, "john.doe"),
                    new Claim(ClaimTypes.Name, "John"),
                    new Claim(ClaimTypes.Surname, "Doe"),
                    new Claim(ClaimTypes.Role, "Sample App Manager"),
                }
            };

            token.TokenClaims.Add(new Claim(Options.TokenIdentifierClaimName!, token.TokenIdentifier));

            return token;
        }
    }
}