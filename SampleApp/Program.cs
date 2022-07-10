using SampleApp.Services;
using w4TR1x.InServerAuthentication.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddRazorPages();

builder.Services.AddSwaggerGen();

builder.Services.AddInServerAuthentication<TestInServerAuthenticationManager>(new(
    jwtIssuer: "server.localhost",
    jwtAudience: "user.localhost",
    jwtSigningKey: "ABCDEFGHIJKLMNOPRSTUVYZ0123456789"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseStatusCodePages();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseSwagger()
    .UseSwaggerUI();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseCookiePolicy();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();

app.Run();