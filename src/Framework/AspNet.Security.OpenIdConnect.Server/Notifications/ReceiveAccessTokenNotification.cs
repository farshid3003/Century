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
    /// Provides context information used when receiving an access token.
    /// </summary>
    public sealed class ReceiveAccessTokenNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ReceiveAccessTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="token"></param>
        internal ReceiveAccessTokenNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            string token)
            : base(context, options) {
            TokenRequest = request;
            AccessToken = token;
        }

        /// <summary>
        /// Gets the authorization or token request.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; }

        /// <summary>
        /// Gets the access token used by the client application.
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AuthorizationCodeFormat"/>.
        /// </summary>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket() => DeserializeTicket(AccessToken);

        /// <summary>
        /// Deserialize and unprotect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AuthorizationCodeFormat"/>.
        /// </summary>
        /// <param name="ticket">The serialized ticket.</param>
        /// <returns>The authentication ticket.</returns>
        public AuthenticationTicket DeserializeTicket(string ticket) => Options.AuthorizationCodeFormat.Unprotect(ticket);
    }
}
