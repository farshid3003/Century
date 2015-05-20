/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when issuing an access token.
    /// </summary>
    public sealed class CreateAccessTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateAccessTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateAccessTokenNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context, options) {
            TokenRequest = request;
            TokenResponse = response;
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; }

        /// <summary>
        /// Gets the authorization or token response.
        /// </summary>
        public OpenIdConnectMessage TokenResponse { get; }

        /// <summary>
        /// Gets or sets the access token
        /// returned to the client application.
        /// </summary>
        public string AccessToken { get; set; }

        /// <summary>
        /// Serialize and protect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AccessTokenFormat"/>.
        /// </summary>
        /// <returns>The serialized and protected ticket.</returns>
        public string SerializeTicket() => Options.AccessTokenFormat.Protect(AuthenticationTicket);
    }
}
