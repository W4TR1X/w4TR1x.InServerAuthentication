using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using w4TR1x.InServerAuthentication.Interfaces;

namespace SampleApp.Pages.Account
{
    public class LoginModel : PageModel
    {
        [Required]
        [Display(Name = "Username")]
        public string Username { get; set; } = "john";

        [Required]
        [Display(Name = "Password")]
        //[DataType(DataType.Password)]
        public string Password { get; set; } = "doe123";

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }

        private readonly IInServerAuthenticationManager _authenticationManager;

        public LoginModel(IInServerAuthenticationManager authenticationManager)
        {
            _authenticationManager = authenticationManager;
        }

        public IActionResult OnGet()
        {
            try
            {
                // Verification.
                if (User?.Identity?.IsAuthenticated == true)
                {
                    // Home Page.
                    return this.RedirectToPage("/Index");
                }
            }
            catch (Exception ex)
            {
                // Info
                Console.Write(ex);
            }

            // Info.
            return Page();
        }

        public async Task<IActionResult> OnPost()
        {
            try
            {
                if (ModelState.IsValid)
                {
                    if (!await _authenticationManager.AuthenticateByCookie(HttpContext, Username, Password, RememberMe))
                    {
                        ModelState.AddModelError(string.Empty, "Invalid username or password.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Write(ex);
            }

            return this.Page();
        }
    }
}
