using AspNet.Security.OpenIdConnect.Server;
using Century.Services.IdentityService.Extensions;
using Century.Services.IdentityService.Models;
using Century.Services.IdentityService.Providers;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Century.Services.IdentityService
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {

        }



        public void ConfigureServices(IServiceCollection services)
        {


            services.AddEntityFramework()
           .AddInMemoryStore()
           .AddDbContext<ApplicationContext>();

            services.Configure<ExternalAuthenticationOptions>(options =>
            {
                options.SignInScheme = "ServerCookie";
            });

            services.AddAuthentication();

            services.AddMvc();
            // Uncomment the following line to add Web API services which makes it easier to port Web API 2 controllers.
            // You will also need to add the Microsoft.AspNet.Mvc.WebApiCompatShim package to the 'dependencies' section of project.json.
            //services.AddWebApiConventions();
        }

        // Configure is called after ConfigureServices is called.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            var certificate = LoadCertificate();
            var key = new X509SecurityKey(certificate);

            var credentials = new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest);

            // Create a new branch where the registered middleware will be executed only for API calls.
            app.UseWhen(context => context.Request.Path.StartsWithSegments(new PathString("/api")), branch =>
            {
                branch.UseOAuthBearerAuthentication(options =>
                {
                    options.AutomaticAuthentication = true;
                    options.Audience = "http://localhost:8526/";
                    options.Authority = "http://localhost:8526/";
                    

                    options.SecurityTokenValidators = new[] { new UnsafeJwtSecurityTokenHandler() };
                });
            });

            // Create a new branch where the registered middleware will be executed only for non API calls.
            app.UseWhen(context => !context.Request.Path.StartsWithSegments(new PathString("/api")), branch =>
            {
                // Insert a new cookies middleware in the pipeline to store
                // the user identity returned by the external identity provider.
                branch.UseCookieAuthentication(options =>
                {
                    options.AutomaticAuthentication = true;
                    options.AuthenticationScheme = "ServerCookie";
                    options.CookieName = CookieAuthenticationDefaults.CookiePrefix + "ServerCookie";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                    options.LoginPath = new PathString("/signin");
                });

                branch.UseGoogleAuthentication(options =>
                {
                    options.ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com";
                    options.ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f";
                });

                branch.UseTwitterAuthentication(options =>
                {
                    options.ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g";
                    options.ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI";
                });
            });


            app.UseInMemorySession();

            app.UseOpenIdConnectServer(options =>
            {
                options.AuthenticationScheme = OpenIdConnectDefaults.AuthenticationScheme;

                options.Issuer = "http://localhost:8526/";
                options.SigningCredentials = credentials;

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;

                options.Provider = new AuthorizationProvider();

                options.AccessTokenHandler = new UnsafeJwtSecurityTokenHandler();
                options.IdentityTokenHandler = new UnsafeJwtSecurityTokenHandler();
            });

            // Configure the HTTP request pipeline.
            app.UseStaticFiles();

            // Add MVC to the request pipeline.
            app.UseMvc();
            // Add the following route for porting Web API 2 controllers.
            // routes.MapWebApiRoute("DefaultApi", "api/{controller}/{id?}");

            app.UseWelcomePage();

            using (var database = app.ApplicationServices.GetService<ApplicationContext>())
            {
                database.Applications.Add(new Application
                {
                    ApplicationID = "myClient",
                    DisplayName = "My client application",
                    RedirectUri = "http://localhost:53507/oidc",
                    LogoutRedirectUri = "http://localhost:53507/",
                    Secret = "secret_secret_secret"
                });

                database.SaveChanges();
            }
        }

        private static X509Certificate2 LoadCertificate()
        {
            // Note: in a real world app, you'd probably prefer storing the X.509 certificate
            // in the user or machine store. To keep this sample easy to use, the certificate
            // is extracted from the Certificate.cer file embedded in this assembly.
            using (var stream = typeof(Startup).GetTypeInfo().Assembly.GetManifestResourceStream("Mvc.Server.Certificate.cer"))
            using (var buffer = new MemoryStream())
            {
                stream.CopyTo(buffer);
                buffer.Flush();

                return new X509Certificate2(buffer.ToArray())
                {
                    PrivateKey = LoadPrivateKey()
                };
            }
        }

        private static RSA LoadPrivateKey()
        {
            // Note: CoreCLR doesn't support .pfx files yet. To work around this limitation, the private key
            // is stored in a different - an totally unprotected/unencrypted - .keys file and attached to the
            // X509Certificate2 instance in LoadCertificate : NEVER do that in a real world application.
            // See https://github.com/dotnet/corefx/issues/424
            using (var stream = typeof(Startup).GetTypeInfo().Assembly.GetManifestResourceStream("Mvc.Server.Certificate.keys"))
            using (var reader = new StreamReader(stream))
            {
                var key = new RSACryptoServiceProvider();

                key.ImportParameters(new RSAParameters
                {
                    D = Convert.FromBase64String(reader.ReadLine()),
                    DP = Convert.FromBase64String(reader.ReadLine()),
                    DQ = Convert.FromBase64String(reader.ReadLine()),
                    Exponent = Convert.FromBase64String(reader.ReadLine()),
                    InverseQ = Convert.FromBase64String(reader.ReadLine()),
                    Modulus = Convert.FromBase64String(reader.ReadLine()),
                    P = Convert.FromBase64String(reader.ReadLine()),
                    Q = Convert.FromBase64String(reader.ReadLine())
                });

                return key;
            }
        }

        // There's currently a bug on CoreCLR that prevents ValidateSignature from working correctly.
        // To work around this bug, signature validation is temporarily disabled: of course,
        // NEVER do that in a real world application as it opens a huge security hole.
        // See https://github.com/aspnet/Security/issues/223
        private class UnsafeJwtSecurityTokenHandler : JwtSecurityTokenHandler
        {
            protected override JwtSecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
            {
                return ReadToken(token) as JwtSecurityToken;
            }
        }


    }
}
