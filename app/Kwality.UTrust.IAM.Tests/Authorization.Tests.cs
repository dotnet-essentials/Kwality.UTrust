// =====================================================================================================================
// = LICENSE:       Copyright (c) 2022 Kevin De Coninck
// =
// =                Permission is hereby granted, free of charge, to any person
// =                obtaining a copy of this software and associated documentation
// =                files (the "Software"), to deal in the Software without
// =                restriction, including without limitation the rights to use,
// =                copy, modify, merge, publish, distribute, sublicense, and/or sell
// =                copies of the Software, and to permit persons to whom the
// =                Software is furnished to do so, subject to the following
// =                conditions:
// =
// =                The above copyright notice and this permission notice shall be
// =                included in all copies or substantial portions of the Software.
// =
// =                THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// =                EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// =                OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// =                NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// =                HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// =                WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// =                FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// =                OTHER DEALINGS IN THE SOFTWARE.
// =====================================================================================================================
namespace Kwality.UTrust.IAM.Tests;

using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Net;

using Kwality.UTrust.IAM.Abstractions.Abstractions;
using Kwality.UTrust.IAM.Extensions;
using Kwality.UTrust.IAM.Tests.Support;
using Kwality.UTrust.IAM.Tests.Support.Xunit.Traits.Attributes;
using Kwality.UTrust.IAM.Tests.Support.Xunit.Traits.Enumerations;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.IdentityModel.Tokens;

using Xunit;

public sealed class AuthorizationTests
{
    private const string defaultRoute = "/";

    [Fact(DisplayName = "Request an HTTP endpoint succeeds.")]
    [AuthorizationComponent(ComponentProvider.None)]
    internal async Task Request_endpoint_succeeds()
    {
        // ACT / ASSERT.
        await new HttpRequestValidator
            {
                ConfigureServices = static services =>
                {
                    services.AddUTrust()
                            .Build();
                },
                ConfigureApplication = static application => { application.UseUTrust(); },
                ConfigureRoutes = static routes =>
                {
                    routes.MapGet(
                        defaultRoute, static context =>
                        {
                            context.Response.StatusCode = 200;

                            return Task.CompletedTask;
                        });
                },
                ExpectedHttpStatusCode = HttpStatusCode.OK,
            }.SendHttpRequestAsync(defaultRoute)
             .ConfigureAwait(false);
    }

    [Fact(DisplayName = "Request a secured HTTP endpoint without a `JWT` fails.")]
    [AuthorizationComponent(ComponentProvider.Custom)]
    internal async Task Request_secured_endpoint_without_jwt_fails()
    {
        // ACT / ASSERT.
        await new HttpRequestValidator
            {
                ConfigureServices = static services =>
                {
                    services.AddUTrust()
                            .UseJwtValidator<JwtValidator>()
                            .Build();
                },
                ConfigureApplication = static application => { application.UseUTrust(); },
                ConfigureRoutes = static routes =>
                {
                    routes.MapGet(
                        defaultRoute,
                        [ExcludeFromCodeCoverage(Justification = "The user is NOT allowed to visit this endpoint.")]
                        [Authorize]
                        static (context) =>
                        {
                            context.Response.StatusCode = 200;

                            return Task.CompletedTask;
                        });
                },
                ExpectedHttpStatusCode = HttpStatusCode.Unauthorized,
            }.SendHttpRequestAsync(defaultRoute)
             .ConfigureAwait(false);
    }

    [Fact(DisplayName = "Request a secured HTTP endpoint with an empty `JWT` fails.")]
    [AuthorizationComponent(ComponentProvider.Custom)]
    internal async Task Request_secured_endpoint_with_empty_jwt_fails()
    {
        // ACT / ASSERT.
        await new HttpRequestValidator
            {
                ConfigureServices = static services =>
                {
                    services.AddUTrust()
                            .UseJwtValidator<JwtValidator>()
                            .Build();
                },
                ConfigureApplication = static application => { application.UseUTrust(); },
                ConfigureRoutes = static routes =>
                {
                    routes.MapGet(
                        defaultRoute,
                        [ExcludeFromCodeCoverage(Justification = "The user is NOT allowed to visit this endpoint.")]
                        [Authorize]
                        static (context) =>
                        {
                            context.Response.StatusCode = 200;

                            return Task.CompletedTask;
                        });
                },
                Jwt = string.Empty,
                ExpectedHttpStatusCode = HttpStatusCode.Unauthorized,
            }.SendHttpRequestAsync(defaultRoute)
             .ConfigureAwait(false);
    }

    [Fact(DisplayName = "Request a secured HTTP endpoint with a valid `JWT` succeeds.")]
    [AuthorizationComponent(ComponentProvider.Custom)]
    internal async Task Request_secured_endpoint_with_valid_jwt_succeeds()
    {
        // ARRANGE.
        const string jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        const string jwtPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        const string jwtSignature = "T7sFpO0XoaJ9JWsu2J1ormK99zs4zIr2s25jjl8RVSw";

        // ACT / ASSERT.
        await new HttpRequestValidator
            {
                ConfigureServices = static services =>
                {
                    services.AddUTrust()
                            .UseJwtValidator<JwtValidator>()
                            .Build();
                },
                ConfigureApplication = static application => { application.UseUTrust(); },
                ConfigureRoutes = static routes =>
                {
                    routes.MapGet(
                        defaultRoute, [Authorize] static (context) =>
                        {
                            context.Response.StatusCode = 200;

                            return Task.CompletedTask;
                        });
                },
                Jwt = $"{jwtHeader}.{jwtPayload}.{jwtSignature}",
                ExpectedHttpStatusCode = HttpStatusCode.OK,
            }.SendHttpRequestAsync(defaultRoute)
             .ConfigureAwait(false);
    }

    private sealed class JwtValidator : IJwtValidator
    {
        public Action<JwtBearerOptions> Options
            => static options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
#pragma warning disable CA5404 // "Do not disable token validation checks" - By design.
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
#pragma warning restore CA5404
                    ValidateIssuerSigningKey = false,
                    RequireSignedTokens = false,
                    SignatureValidator = static (token, _) =>
                    {
                        var jwt = new JwtSecurityToken(token);

                        return jwt;
                    },
                };
            };
    }
}
