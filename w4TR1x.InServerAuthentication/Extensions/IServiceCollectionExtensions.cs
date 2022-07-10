namespace w4TR1x.InServerAuthentication.Extensions;

public static class IServiceCollectionExtensions
{
    public static void AddInServerAuthentication<TImplementation>(this IServiceCollection services,
        InServerConfigurationOptions inServerOptions) where TImplementation : InServerAuthenticationManager
    {
        inServerOptions.SchemeName ??= "InServer";
        inServerOptions.CookieName ??= "InServerCookie";
        inServerOptions.JwtAuthorizationHeader ??= "InServerToken";
        inServerOptions.TokenIdentifierClaimName ??= "InServerAuthentication.Token.Identifier";

        services.AddSingleton(inServerOptions);

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role,
            ClockSkew = TimeSpan.Zero,

            ValidIssuer = inServerOptions.JwtIssuer,
            ValidAudience = inServerOptions.JwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(inServerOptions.JwtSigningKey))
        };

        services.AddSingleton(tokenValidationParameters);

        services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(@"C:\temp-keys\"));

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = inServerOptions.SchemeName;
            options.DefaultChallengeScheme = inServerOptions.SchemeName;
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/account/login";
            options.LogoutPath = "/account/logout";
            options.Cookie.Name = inServerOptions.CookieName;


        })
        .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
        {
#if DEBUG
            options.RequireHttpsMetadata = false;
#endif
            options.TokenValidationParameters = tokenValidationParameters;
        })
        .AddScheme<InServerAuthenticationOptions, InServerAuthenticationHandler>(inServerOptions.SchemeName, null);

        services.AddSingleton<IInServerAuthenticationManager, TImplementation>();
    }
}