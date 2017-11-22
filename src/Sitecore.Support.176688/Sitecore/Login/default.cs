namespace Sitecore.Support.Sitecore.Login
{
    using Configuration;
    using Diagnostics;
    using Globalization;
    using Pipelines;
    using Pipelines.LoggedIn;
    using Pipelines.LoggingIn;
    using Pipelines.PasswordRecovery;
    using Security.Accounts;
    using Security.Authentication;
    using SecurityModel.Cryptography;
    using SecurityModel.License;
    using Text;
    using Web;
    using Web.Authentication;
    using System;
    using System.Text.RegularExpressions;
    using System.Web.UI.HtmlControls;
    using SitecoreContext = Context;

    public class Default : System.Web.UI.Page
    {
        private string fullUserName = string.Empty;

        private string startUrl = string.Empty;

        /// <summary>
        /// LoginForm control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.HtmlControls.HtmlForm LoginForm;

        /// <summary>
        /// FailureHolder control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.PlaceHolder FailureHolder;

        /// <summary>
        /// FailureText control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.Literal FailureText;

        /// <summary>
        /// SuccessHolder control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.PlaceHolder SuccessHolder;

        /// <summary>
        /// SuccessText control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.Literal SuccessText;

        /// <summary>
        /// loginLbl control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.Label loginLbl;

        /// <summary>
        /// UserName control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.TextBox UserName;

        /// <summary>
        /// UserNameRequired control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.RequiredFieldValidator UserNameRequired;

        /// <summary>
        /// passLabel control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.Label passLabel;

        /// <summary>
        /// Password control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.TextBox Password;

        /// <summary>
        /// RequiredFieldValidator1 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.RequiredFieldValidator RequiredFieldValidator1;

        /// <summary>
        /// PlaceHolder3 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.PlaceHolder PlaceHolder3;

        /// <summary>
        /// PlaceHolder2 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.PlaceHolder PlaceHolder2;

        /// <summary>
        /// RememberMe control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.CheckBox RememberMe;

        /// <summary>
        /// PlaceHolder4 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.PlaceHolder PlaceHolder4;

        /// <summary>
        /// PlaceHolder1 control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.PlaceHolder PlaceHolder1;

        /// <summary>
        /// UserNameForgot control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected System.Web.UI.WebControls.TextBox UserNameForgot;

        /// <summary>
        /// StartPage control.
        /// </summary>
        /// <remarks>
        /// Auto-generated field.
        /// To modify move field declaration from designer file to code-behind file.
        /// </remarks>
        protected HtmlIframe StartPage;

        /// <summary>
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        protected void ForgotPasswordClicked(object sender, EventArgs e)
        {
            string text = this.UserNameForgot.Text;
            this.fullUserName = WebUtil.HandleFullUserName(text);
            if (Sitecore.Security.Accounts.User.Exists(this.fullUserName))
            {
                PasswordRecoveryArgs args = new PasswordRecoveryArgs(this.Context)
                {
                    Username = text
                };
                Pipeline.Start("passwordRecovery", args);
            }
            this.RenderSuccess("Your password has been sent to you. If you do not receive an e-mail with your password, please check that you've typed your user name correctly or contact your administrator.");
        }

        /// <summary>
        /// Returns the path to the background image for use on the login page
        /// </summary>
        /// <returns>Image url</returns>
        protected string GetBackgroundImageUrl()
        {
            return Settings.Login.BackgroundImageUrl;
        }

        /// <summary>
        /// Gets the login page URL.
        /// </summary>
        /// <returns></returns>
        protected string GetLoginPageUrl()
        {
            string loginPage = Client.Site.LoginPage;
            if (string.IsNullOrEmpty(loginPage))
            {
                return "/sitecore/login";
            }
            return loginPage;
        }

        /// <summary>
        /// </summary>
        protected virtual void LoggedIn()
        {
            User user = Sitecore.Security.Accounts.User.FromName(this.fullUserName, false);
            State.Client.UsesBrowserWindows = true;
            LoggedInArgs loggedInArgs = new LoggedInArgs
            {
                Username = this.fullUserName,
                StartUrl = this.startUrl,
                Persist = this.ShouldPersist()
            };
            Pipeline.Start("loggedin", loggedInArgs);
            string @string = StringUtil.GetString(new string[]
            {
                user.Profile.ClientLanguage,
                Settings.ClientLanguage
            });
            string url = loggedInArgs.StartUrl;
            UrlString urlString = new UrlString(url);
            if (string.IsNullOrEmpty(urlString["sc_lang"]))
            {
                urlString["sc_lang"] = @string;
            }
            this.startUrl = urlString.ToString();
            using (new UserSwitcher(user))
            {
                Log.Audit(this, "Login", new string[0]);
            }
        }

        /// <summary>
        /// </summary>
        protected virtual bool LoggingIn()
        {
            if (string.IsNullOrWhiteSpace(this.UserName.Text))
            {
                return false;
            }
            this.fullUserName = WebUtil.HandleFullUserName(this.UserName.Text);
            this.startUrl = WebUtil.GetQueryString("returnUrl");
            this.FailureHolder.Visible = false;
            this.SuccessHolder.Visible = false;
            if (Settings.Login.RememberLastLoggedInUserName)
            {
                Default.WriteCookie(WebUtil.GetLoginCookieName(), this.UserName.Text);
            }
            LoggingInArgs loggingInArgs = new LoggingInArgs
            {
                Username = this.fullUserName,
                Password = this.Password.Text,
                StartUrl = this.startUrl
            };
            Pipeline.Start("loggingin", loggingInArgs);
            bool flag = UIUtil.IsIE() || UIUtil.IsIE11();
            if (flag && !Regex.IsMatch(WebUtil.GetHostName(), Settings.HostNameValidationPattern, RegexOptions.ECMAScript))
            {
                this.RenderError(Translate.Text("Your login attempt was not successful because the URL hostname contains invalid character(s) that are not recognized by IE. Please check the URL hostname or try another browser."));
                return false;
            }
            if (!loggingInArgs.Success)
            {
                Log.Audit(string.Format("Login failed: {0}.", loggingInArgs.Username), this);
                if (!string.IsNullOrEmpty(loggingInArgs.Message))
                {
                    this.RenderError(Translate.Text(StringUtil.RemoveLineFeeds(loggingInArgs.Message)));
                }
                return false;
            }
            this.startUrl = loggingInArgs.StartUrl;
            return true;
        }

        /// <summary>
        /// </summary>
        protected virtual bool Login()
        {
            if (AuthenticationManager.Login(this.fullUserName, this.Password.Text, this.ShouldPersist()))
            {
                return true;
            }
            this.RenderError("Your login attempt was not successful. Please try again.");
            return false;
        }

        /// <summary>
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        protected void LoginClicked(object sender, EventArgs e)
        {
            if (!this.LoggingIn())
            {
                return;
            }
            if (!this.Login())
            {
                return;
            }
            this.LoggedIn();
            this.CheckDomainGuard();
            WebUtil.Redirect(this.startUrl);
        }

        /// <summary>
        /// </summary>
        /// <param name="e"></param>
        protected override void OnInit(EventArgs e)
        {
            if (Sitecore.Context.User.IsAuthenticated)
            {
                if (WebUtil.GetQueryString("inv") == "1")
                {
                    Boost.Invalidate();
                }
                if (!DomainAccessGuard.GetAccess())
                {
                    this.LogMaxEditorsExceeded();
                    base.Response.Redirect(WebUtil.GetFullUrl("/sitecore/client/Applications/LicenseOptions/StartPage"));
                    return;
                }
            }
            this.DataBind();
            if (Settings.Login.DisableRememberMe || Settings.Login.DisableAutoComplete)
            {
                this.LoginForm.Attributes.Add("autocomplete", "off");
            }
            if (!base.IsPostBack && Settings.Login.RememberLastLoggedInUserName && !Settings.Login.DisableAutoComplete)
            {
                string cookieValue = WebUtil.GetCookieValue(WebUtil.GetLoginCookieName());
                if (!string.IsNullOrEmpty(cookieValue))
                {
                    MachineKeyEncryption.TryDecode(cookieValue, out cookieValue);
                    this.UserName.Text = cookieValue;
                    this.UserNameForgot.Text = cookieValue;
                }
            }
            try
            {
                base.Response.Headers.Add("SC-Login", "true");
            }
            catch (PlatformNotSupportedException exception)
            {
                Log.Error("Setting response headers is not supported.", exception, this);
            }
            this.RenderSdnInfoPage();
            base.OnInit(e);
        }

        /// <summary>
        /// Logs that the maximum number of simultaneously active (logged-in) editors was exceeded. 
        /// </summary>
        private void LogMaxEditorsExceeded()
        {
            string format = "The maximum number of simultaneously active (logged-in) editors exceeded. The User {0} cannot be logged in to the system. The maximum of editors allowed by license is {1}.";
            Log.Warn(string.Format(format, this.fullUserName, DomainAccessGuard.MaximumSessions), this);
        }

        private static void WriteCookie(string name, string value)
        {
            Assert.ArgumentNotNull(name, "name");
            Assert.ArgumentNotNull(value, "value");
            if (name == WebUtil.GetLoginCookieName())
            {
                value = MachineKeyEncryption.Encode(value);
            }
            System.Web.HttpCookie cookie = new System.Web.HttpCookie(name, value)
            {
                Expires = DateTime.UtcNow.AddMonths(3),
                Path = "/sitecore/login",
                HttpOnly = true
            };
            System.Web.HttpContext.Current.Response.AppendCookie(cookie);
            System.Web.HttpCookie httpCookie = System.Web.HttpContext.Current.Request.Cookies[name];
            if (httpCookie != null)
            {
                httpCookie.Value = value;
            }
        }

        private void CheckDomainGuard()
        {
            if (!DomainAccessGuard.GetAccess())
            {
                this.LogMaxEditorsExceeded();
                this.startUrl = WebUtil.GetFullUrl("/sitecore/client/Applications/LicenseOptions/StartPage");
            }
        }

        /// <summary>
        /// Renders the start page.
        /// </summary>
        private void RenderSdnInfoPage()
        {
            string text = Settings.Login.SitecoreUrl;
            if (base.Request.IsSecureConnection)
            {
                text = text.Replace("http:", "https:");
            }
            UrlString urlString = new UrlString(text);
            urlString["id"] = License.LicenseID;
            urlString["host"] = WebUtil.GetHostName();
            urlString["licensee"] = License.Licensee;
            urlString["iisname"] = WebUtil.GetIISName();
            urlString["st"] = WebUtil.GetCookieValue("sitecore_starttab", string.Empty);
            urlString["sc_lang"] = Sitecore.Context.Language.Name;
            urlString["v"] = About.GetVersionNumber(true);
            this.StartPage.Attributes["src"] = urlString.ToString();
            this.StartPage.Attributes["onload"] = "javascript:this.style.display='block'";
        }

        private void RenderError(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            this.FailureHolder.Visible = true;
            this.FailureText.Text = text;
        }

        private void RenderSuccess(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            this.SuccessHolder.Visible = true;
            this.SuccessText.Text = text;
        }

        private bool ShouldPersist()
        {
            return !Settings.Login.DisableRememberMe && this.RememberMe.Checked;
        }
    }
}