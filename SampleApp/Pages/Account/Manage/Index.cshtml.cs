using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using w4TR1x.InServerAuthentication.Interfaces;

namespace SampleApp.Pages.Account.Manage
{
    public class IndexModel : PageModel
    {
        private readonly IInServerAuthenticationManager _authenticationManager;

        public IToken? Token { get; set; }

        public IndexModel(IInServerAuthenticationManager authenticationManager)
        {
            _authenticationManager = authenticationManager;
        }

        public async Task OnGet()
        {
            Token = await _authenticationManager.GetTokenFromHttpContext(HttpContext);
        }
    }
}
