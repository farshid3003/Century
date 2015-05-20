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
    /// Provides context information used when issuing an authorization code.
    /// </summary>
    public sealed class CreateAuthorizationCodeNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateAuthorizationCodeNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <param name="ticket"></param>
        internal CreateAuthorizationCodeNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response,
            AuthenticationTicket ticket)
            : base(context, options) {
            AuthorizationRequest = request;
            AuthorizationResponse = response;
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets the authorization request.
        /// </summary>
        public OpenIdConnectMessage AuthorizationRequest { get; }

        /// <summary>
        /// Gets the authorization response.
        /// </summary>
        public OpenIdConnectMessage AuthorizationResponse { get; }

        /// <summary>
        /// Gets or sets the authorization code
        /// returned to the client application.
        /// </summary>
        public string AuthorizationCode { get; set; }

        /// <summary>
        /// Serialize and protect the authentication ticket using
        /// <see cref="OpenIdConnectServerOptions.AuthorizationCodeFormat"/>.
        /// </summary>
        /// <returns>The serialized and protected ticket.</returns>
        public string SerializeTicket() => Options.AuthorizationCodeFormat.Protect(AuthenticationTicket);
    }
}
