// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Duende.IdentityServer.Models;
using System.Collections.Generic;

namespace IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            { 
                new IdentityResources.OpenId()
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new List<ApiScope>
            {
                new ApiScope("sampleApi", "Sample API")
            };

        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                // machine to machine client
                new Client
                {
                    ClientId = "sampleClient",
                    ClientSecrets = { new Secret("sampleSecret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    // scopes that client has access to
                    AllowedScopes = { "sampleApi" }
                }
            };
    }
}