using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using GB.IdentityServer.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using static Duende.IdentityServer.IdentityServerConstants;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;

namespace GB.IdentityServer.Controllers
{
	[SecurityHeaders]
    public class AccountController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly IEmailManager _emailManager;

        public AccountController(
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IEmailManager emailManager)
        {
            _configuration = configuration;
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _emailManager = emailManager;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
            }
                
            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            try
            {
                // check if we are in the context of an authorization request
                if (model.ReturnUrl != null && model.ReturnUrl.StartsWith("http"))
                {
                    var uri = new UriBuilder(model.ReturnUrl);
                    if (uri.Host == this.Request.Host.Host && uri.Port == this.Request.Host.Port)
                    {
                        model.ReturnUrl = uri.Path + uri.Query;
                    }
                }

                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

                // the user clicked the "cancel" button
                if (button != "login")
                {
                    if (context != null)
                    {
                        // if the user cancels, send a result back into IdentityServer as if they 
                        // denied the consent (even if this client does not require consent).
                        // this will send back an access denied OIDC error response to the client.
                        await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        return Redirect(model.ReturnUrl);
                    }
                    else
                    {
                        // since we don't have a valid context, then we just go back to the home page
                        return Redirect("~/");
                    }
                }

                if (ModelState.IsValid)
                {
                    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberLogin, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        var successfulClaimValidation = false;

                        var user = await _userManager.FindByNameAsync(model.Email);
                        IList<Claim> claims = await _userManager.GetClaimsAsync(user);

                        string clientName = GetRequestClientName();

                        var claim = claims.FirstOrDefault(x => x.Type == clientName);

                        if (claim != null && claim.Value == true.ToString().ToLower())
                        {
                            successfulClaimValidation = true;
                            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
                        }

                        if (successfulClaimValidation)
                        {
                            if (context != null)
                            {
                                if (context.IsNativeClient())
                                {
                                    // The client is native, so this change in how to
                                    // return the response is for better UX for the end user.
                                    return this.LoadingPage("Redirect", model.ReturnUrl);
                                }

                                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                                return Redirect(model.ReturnUrl);
                            }

                            // request for a local page
                            if (Url.IsLocalUrl(model.ReturnUrl))
                            {
                                return Redirect(model.ReturnUrl);
                            }
                            else if (string.IsNullOrEmpty(model.ReturnUrl))
                            {
                                return Redirect("~/");
                            }
                            else
                            {
                                // user might have clicked on a malicious link - should be logged
                                throw new Exception("invalid return URL");
                            }
                        }
                    }

                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Email, "invalid credentials", clientId: context?.Client.ClientId));
                    ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
                }

                // something went wrong, show form with error
                var vm = await BuildLoginViewModelAsync(model);
                return View(vm);
            }
            catch (Exception ex)
            {
                return Ok(ex.ToString());
            }
        }

        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
		{
            if (ModelState.IsValid)
			{
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
				{
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var passwordResetLink = Url.Action("ResetPassword", "Account",
                        new { email = model.Email, token = token }, Request.Scheme);

					this._emailManager.SendPasswordResetEmail(user, passwordResetLink);

                    return View("ForgotPasswordConfirmation");
				}
                return View("ForgotPasswordConfirmation");
			}
            return View(model);
		}

		[HttpGet]
        public IActionResult ForgotPassword()
		{
            return View();
		}

        [HttpGet]
        public IActionResult ResetPassword(string email, string token)
		{
            var vm = new ResetPasswordViewModel();

            // build a model so the logout page knows what to display
            //var vm = await BuildLoggedOutViewModelAsync(logoutId);
            bool valid = false;
            if (!string.IsNullOrEmpty(token) && ! string.IsNullOrEmpty(email))
            {
                var user = this._userManager.FindByEmailAsync(email).Result;
                valid = (user != null) && this._userManager.VerifyUserTokenAsync(user, "Default", "ResetPassword", token).Result;
            }

            if (! valid)
			{
                ModelState.AddModelError("", "Invalid password reset token, possibly expired. Resend Link to try again.");
			}
            return View(vm);
		}

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
		{
            if (ModelState.IsValid)
			{
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
				{
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                    if (result.Succeeded)
					{
                        //if the user successfully sets their password, they are confirming their email address.
                        user.EmailConfirmed = true;
                        await _userManager.UpdateAsync(user);

                        return View("ResetPasswordConfirmation", 
                            new ResetPasswordConfirmationViewModel() 
                            {
                                LoginRedirectAddress = _configuration["LoginRedirectAddress"].ToString() }
                            );

                    }
                    foreach(var error in result.Errors)
					{
                        ModelState.AddModelError("", error.Description);
					}
                    return View(model);
				}
                return View("ResetPasswordConfirmation", 
                    new ResetPasswordConfirmationViewModel()
                        {
                            LoginRedirectAddress = _configuration["LoginRedirectAddress"].ToString()
                        }
                    );
			}
            return View(model);
		}

        [HttpPost]
        [Authorize(LocalApi.PolicyName)]
        public async Task<IActionResult> CreateUser([FromBody] ApplicationUser user)
		{
            bool userIsInDb = true;
            var dbUser = await this._userManager.FindByEmailAsync(user.Email);
            if (dbUser == null)
			{
                var result = await _userManager.CreateAsync(user);
                userIsInDb = result.Succeeded;
            }
            else
			{
                user = dbUser;
			}

            if (userIsInDb)
			{
                string clientName = GetRequestClientName();

                if (string.IsNullOrEmpty(clientName))
				{
                    return BadRequest();
				}

                await _userManager.AddClaimAsync(user, new Claim(clientName, true.ToString().ToLower()));

                var t = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { email = user.Email, token = t }, protocol: "https");

                //send a link for the user to set their password.
                this._emailManager.SendWelcomeEmail(user, callbackUrl);

                return Ok(user.Email);
            }
            else
			{
                return BadRequest();
			}
		}

        [HttpDelete]
        [Authorize(LocalApi.PolicyName)]
        public async Task<IActionResult> DeleteUser(string email)
		{
            var user = await this._userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return BadRequest();
            }

            string clientName = GetRequestClientName();
            if (string.IsNullOrEmpty(clientName))
			{
                return BadRequest();
			}

            IList<Claim> claims = await _userManager.GetClaimsAsync(user);
			IEnumerable<Claim> thisClaim = claims.Where(x => x.Type == clientName);

            if (thisClaim.Count() <= 0)
			{
                return BadRequest();
			}

            if (claims.Count == thisClaim.Count())
			{
                await _userManager.DeleteAsync(user);
			}
            else
			{
                foreach(var claim in thisClaim)
				{
                    await _userManager.RemoveClaimAsync(user, claim);
                }
            }

            return Ok();
        }

        [HttpPost]
        [Authorize(LocalApi.PolicyName)]
        public async Task<IActionResult> EditUser([FromBody] ApplicationUser user)
		{
           //we currently only support changing First and Last Name from here.  To change email, you need to use special "ChangeEmail" endpoint.
           var dbUser = await _userManager.FindByEmailAsync(user.Email);

            if(dbUser != null)
			{
                dbUser.FirstName = user.FirstName;
                dbUser.LastName = user.LastName;

                var result = await _userManager.UpdateAsync(dbUser);
                if (result.Succeeded)
                {
                    return Ok(result);
                }
                else
                {
                    return BadRequest(result);
                }
            }
            return BadRequest();
        }

        [HttpGet]
        [Authorize(LocalApi.PolicyName)]
        public async Task<IActionResult> ChangeUsersEmail(string oldEmail, string newEmail)
		{
            var dbUser = await _userManager.FindByEmailAsync(oldEmail);

            if (dbUser != null)
            {
                dbUser.Email = newEmail;
                dbUser.UserName = newEmail;

                var result = await _userManager.UpdateAsync(dbUser);
                if (result.Succeeded)
                {
                    return Ok(this._emailManager.SendEmailAddressChangedEmail(dbUser, oldEmail));
                }
                else
                {
                    return BadRequest(result);
                }
            }
            return BadRequest();
        }

        [HttpGet]
        [Authorize(LocalApi.PolicyName)]
        public async Task<IActionResult> GetUserEmail(string userId)
		{
            var dbUser = await _userManager.FindByIdAsync(userId);

            if (dbUser == null) return BadRequest();

            return Ok(dbUser.Email);
        }

        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/

        private string GetRequestClientName()
		{
            //first try through the identity server interaction service.
            string returnUrl = this.Request.Query["ReturnUrl"];
            if (!string.IsNullOrEmpty(returnUrl))
			{
                if (returnUrl.StartsWith("http"))
				{
                    var uri = new UriBuilder(returnUrl);
                    if (uri.Host == this.Request.Host.Host && uri.Port == this.Request.Host.Port)
                    {
                        returnUrl = uri.Path + uri.Query;
                    }
                }
                var clientContext = this._interaction.GetAuthorizationContextAsync(returnUrl).Result;

                if (clientContext != null)
                {
                    return clientContext.Client?.ClientName ?? string.Empty;
                }
            }

            //else try through the httpcontext
            if (this.Request.HttpContext != null && this.Request.HttpContext.User != null && this.Request.HttpContext.User.HasClaim(c => c.Type == "client_id"))
            {
                var client = this.Request.HttpContext.User.Claims.First(c => c.Type == "client_id");
                var product = Config.Clients.FirstOrDefault(x => x.ClientId == client.Value);

                return product?.ClientName ?? string.Empty;
            }

            //else we can't determine a client name for this request.
            return string.Empty;
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Email = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Email = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Email = model.Email;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}