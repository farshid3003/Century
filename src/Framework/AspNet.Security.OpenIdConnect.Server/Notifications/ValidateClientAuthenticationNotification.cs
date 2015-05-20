/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Microsoft.IdentityModel.Protocols;
using Microsoft.AspNet;
using Microsoft.AspNet.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Contains information about the client credentials.
    /// </summary>
    public sealed class ValidateClientAuthenticationNotification : BaseValidatingClientNotification {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateClientAuthenticationNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        internal ValidateClientAuthenticationNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options, request) {
        }

        /// <summary>
        /// Sets the client id and marks the context as validated by the application.
        /// </summary>
        /// <param name="clientId"></param>
        /// <returns></returns>
        public bool Validated(string clientId) {
            ClientId = clientId;

            return Validated();
        }

        /// <summary>
        /// Extracts HTTP basic authentication credentials from the HTTP authenticate header.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        [SuppressMessage("Microsoft.Design", "CA1021:AvoidOutParameters", MessageId = "0#", Justification = "Optimized for usage")]
        public bool TryGetBasicCredentials(out string clientId, out string clientSecret) {
            // Client Authentication http://tools.ietf.org/html/rfc6749#section-2.3
            // Client Authentication Password http://tools.ietf.org/html/rfc6749#section-2.3.1
            string authorization = Request.Headers.Get("Authorization");
            if (!string.IsNullOrWhiteSpace(authorization) && authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) {
                try {
                    byte[] data = Convert.FromBase64String(authorization.Substring("Basic ".Length).Trim());
                    string text = Encoding.UTF8.GetString(data);
                    int delimiterIndex = text.IndexOf(':');
                    if (delimiterIndex >= 0) {
                        clientId = text.Substring(0, delimiterIndex);
                        clientSecret = text.Substring(delimiterIndex + 1);
                        ClientId = clientId;

                        return true;
                    }
                }
                catch (FormatException) {
                    // Bad Base64 string
                }
                catch (ArgumentException) {
                    // Bad utf-8 string
                }
            }

            clientId = null;
            clientSecret = null;
            return false;
        }

        /// <summary>
        /// Extracts forms authentication credentials from the HTTP request body.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        [SuppressMessage("Microsoft.Design", "CA1021:AvoidOutParameters", MessageId = "0#", Justification = "Optimized for usage")]
        public bool TryGetFormCredentials(out string clientId, out string clientSecret) {
            clientId = ClientId;
            if (!string.IsNullOrEmpty(clientId)) {
                clientSecret = AuthorizationRequest.ClientSecret;
                return true;
            }
            clientId = null;
            clientSecret = null;
            return false;
        }
    }
}
