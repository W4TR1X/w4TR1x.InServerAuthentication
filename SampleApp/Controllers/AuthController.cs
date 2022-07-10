using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using w4TR1x.InServerAuthentication.Interfaces;

namespace SampleApp.Controllers;

[ApiController]
[Route("api/[controller]/[action]")]
public class AuthController : ControllerBase
{
    private readonly IInServerAuthenticationManager _inServerAuthenticationManager;

    public AuthController(IInServerAuthenticationManager inServerAuthenticationManager)
    {
        _inServerAuthenticationManager = inServerAuthenticationManager;
    }

    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginModel userInfo)
    {
        if (!ModelState.IsValid) return BadRequest();

        var token = await _inServerAuthenticationManager
            .AuthenticateByJwt(HttpContext, userInfo.Username, userInfo.Password);

        if (token == null) return BadRequest();

        return Ok(token);
    }

    public class LoginModel
    {
        [Required]
        [Display(Name = "Username")]
        public string Username { get; set; } = "john";

        [Required]
        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = "doe123";
    }
}