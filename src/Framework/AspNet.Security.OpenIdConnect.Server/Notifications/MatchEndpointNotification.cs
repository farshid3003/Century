/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when determining the OpenIdConnect flow type based on the request.
    /// </summary>
    public sealed class MatchEndpointNotification : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="MatchEndpointNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        internal MatchEndpointNotification(
            HttpContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
        }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OAuth2/OpenID Connect authorization endpoint.
        /// </summary>
        public bool IsAuthorizationEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OpenID Connect configuration metadata endpoint.
        /// </summary>
        public bool IsConfigurationEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OpenID Connect JWKS endpoint.
        /// </summary>
        public bool IsCryptographyEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is an
        /// OAuth2/OpenID Connect token endpoint.
        /// </summary>
        public bool IsTokenEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is a validation endpoint.
        /// </summary>
        public bool IsValidationEndpoint { get; private set; }

        /// <summary>
        /// Gets whether or not the endpoint is a logout endpoint.
        /// </summary>
        public bool IsLogoutEndpoint { get; private set; }

        /// <summary>
        /// Sets the endpoint type to the authorization endpoint.
        /// </summary>
        public void MatchesAuthorizationEndpoint() {
            IsAuthorizationEndpoint = true;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsValidationEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the configuration endpoint.
        /// </summary>
        public void MatchesConfigurationEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = true;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsValidationEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to the JWKS endpoint.
        /// </summary>
        public void MatchesCryptographyEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = true;
            IsTokenEndpoint = false;
            IsValidationEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to token endpoint.
        /// </summary>
        public void MatchesTokenEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = true;
            IsValidationEndpoint = false;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to validation endpoint.
        /// </summary>
        public void MatchesValidationEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsValidationEndpoint = true;
            IsLogoutEndpoint = false;
        }

        /// <summary>
        /// Sets the endpoint type to logout endpoint.
        /// </summary>
        public void MatchesLogoutEndpoint() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsValidationEndpoint = false;
            IsLogoutEndpoint = true;
        }

        /// <summary>
        /// Sets the endpoint type to unknown.
        /// </summary>
        public void MatchesNothing() {
            IsAuthorizationEndpoint = false;
            IsConfigurationEndpoint = false;
            IsCryptographyEndpoint = false;
            IsTokenEndpoint = false;
            IsValidationEndpoint = false;
            IsLogoutEndpoint = false;
        }
    }
}
