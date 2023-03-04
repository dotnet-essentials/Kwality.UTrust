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
namespace Kwality.UTrust.IAM.Builders;

using JetBrains.Annotations;

using Kwality.UTrust.IAM.Abstractions.Abstractions;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

public sealed class UTrustBuilder
{
    private readonly string authenticationScheme;
    private readonly IServiceCollection services;

    internal UTrustBuilder(IServiceCollection services, string authenticationScheme)
    {
        this.services = services;
        this.authenticationScheme = authenticationScheme;
    }

    private IJwtValidator? JwtValidator { get; set; }

    [PublicAPI]
    public UTrustBuilder UseJwtValidator<TJwtValidator>()
        where TJwtValidator : IJwtValidator, new()
    {
        this.JwtValidator = new TJwtValidator();

        return this;
    }

    [PublicAPI]
    public UTrustBuilder UseJwtValidator(IJwtValidator jwtValidator)
    {
        this.JwtValidator = jwtValidator;

        return this;
    }

    [PublicAPI]
    public IServiceCollection Build()
    {
        AuthenticationBuilder builder = this.services.AddAuthentication(this.authenticationScheme);

        if (this.JwtValidator != null)
        {
            builder.AddJwtBearer(this.JwtValidator.Options);
        }

        this.services.AddAuthorization();

        return this.services;
    }
}
