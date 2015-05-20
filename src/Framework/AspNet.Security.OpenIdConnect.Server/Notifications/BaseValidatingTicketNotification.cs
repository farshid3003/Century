/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Base class used for certain event contexts
    /// </summary>
    public abstract class BaseValidatingTicketNotification<TOptions> : BaseValidatingNotification<TOptions> where TOptions : AuthenticationOptions {
        /// <summary>
        /// Initializes base class used for certain event contexts
        /// </summary>
        protected BaseValidatingTicketNotification(
            HttpContext context,
            TOptions options,
            AuthenticationTicket ticket)
            : base(context, options) {
            Ticket = ticket;
        }

        /// <summary>
        /// Contains the identity and properties for the application to authenticate. If the Validated method
        /// is invoked with an AuthenticationTicket or ClaimsIdentity argument, that new value is assigned to 
        /// this property in addition to changing IsValidated to true.
        /// </summary>
        public AuthenticationTicket Ticket { get; private set; }

        /// <summary>
        /// Replaces the ticket information on this context and marks it as as validated by the application. 
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <param name="ticket">Assigned to the Ticket property</param>
        /// <returns>True if the validation has taken effect.</returns>
        public bool Validated(AuthenticationTicket ticket) {
            Ticket = ticket;
            return Validated();
        }

        /// <summary>
        /// Alters the ticket information on this context and marks it as as validated by the application. 
        /// IsValidated becomes true and HasError becomes false as a result of calling.
        /// </summary>
        /// <param name="principal">Assigned to the Ticket.Principal property</param>
        /// <returns>True if the validation has taken effect.</returns>
        public bool Validated(ClaimsPrincipal principal) {
            var properties = Ticket?.Properties ?? new AuthenticationProperties();
            return Validated(new AuthenticationTicket(principal, properties, Options.AuthenticationScheme));
        }
    }
}
