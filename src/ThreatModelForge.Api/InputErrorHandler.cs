namespace ThreatModelForge.Api
{
    using System;
    using System.IO;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Diagnostics;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;

    /// <summary>
    /// Answers 400 for the failures that mean the caller sent something unusable, instead of letting
    /// them surface as 500. The distinction matters to anyone driving this API: a 500 says the server
    /// broke and invites a retry, while these are all cases where retrying the same request cannot
    /// help — an unknown format id, an unreadable body, malformed base64.
    /// <para>
    /// Classification is by exception type, and deliberately narrow: anything not listed here is left
    /// alone and still becomes a 500, because an unexpected failure really is the server's fault and
    /// should not be reported as the caller's.
    /// </para>
    /// </summary>
    internal sealed class InputErrorHandler : IExceptionHandler
    {
        /// <summary>Writes a problem response when the failure was caused by the request.</summary>
        /// <param name="httpContext">The request context.</param>
        /// <param name="exception">The unhandled exception.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>True when the exception was handled.</returns>
        public async ValueTask<bool> TryHandleAsync(
            HttpContext httpContext,
            Exception exception,
            CancellationToken cancellationToken)
        {
            if (httpContext == null || exception == null || !IsCallerInput(exception))
            {
                return false;
            }

            // Model binding already decides a status for the requests it rejects (a malformed body, a
            // missing required query value). Keep it: installing this handler must not downgrade a
            // request the framework had already classified correctly.
            httpContext.Response.StatusCode = exception is BadHttpRequestException badRequest
                ? badRequest.StatusCode
                : StatusCodes.Status400BadRequest;

            // The message is echoed because for these types it describes the caller's own input (the
            // format id they named, where their JSON stopped parsing). No stack trace is ever included.
            await httpContext.Response.WriteAsJsonAsync(
                new ProblemDetails
                {
                    Status = httpContext.Response.StatusCode,
                    Title = "The request could not be processed as sent.",
                    Detail = exception.Message,
                    Instance = httpContext.Request.Path,
                },
                options: null,
                contentType: "application/problem+json",
                cancellationToken).ConfigureAwait(false);
            return true;
        }

        /// <summary>Reports whether a failure was caused by the request rather than by the server.</summary>
        /// <param name="exception">The unhandled exception.</param>
        /// <returns>True when the caller's input caused it.</returns>
        private static bool IsCallerInput(Exception exception)
        {
            switch (exception)
            {
                // Model binding rejected the request before it reached an endpoint: a body that is not
                // JSON, or a missing required query value. It carries its own status code.
                case BadHttpRequestException:

                // An unregistered format id, on ?to=, ?format=, or a read request.
                case NotSupportedException:

                // A missing or empty required value that reached the engine.
                case ArgumentException:

                // Content that is not valid base64.
                case FormatException:

                // Uploaded bytes that are not the model document they claim to be.
                case JsonException:
                case InvalidDataException:
                    return true;
                default:
                    return false;
            }
        }
    }
}
