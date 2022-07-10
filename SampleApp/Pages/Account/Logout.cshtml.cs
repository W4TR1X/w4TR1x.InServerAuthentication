using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using w4TR1x.InServerAuthentication.Interfaces;
using w4TR1x.InServerAuthentication.Models.AuthenticationSystems;

namespace SampleApp.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly IInServerAuthenticationManager _authenticationManager;

        public LogoutModel(IInServerAuthenticationManager authenticationManager)
        {
            _authenticationManager = authenticationManager;
        }

        public async Task<IActionResult> OnPost(string? returnUrl)
        {
            await _authenticationManager.CookieLogout(HttpContext);

            return this.RedirectToPage(returnUrl ?? "/Index");
        }
    }
}
