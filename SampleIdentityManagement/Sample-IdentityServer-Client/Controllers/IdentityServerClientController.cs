using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Sample_IdentityServer_Client.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class IdentityServerClientController: ControllerBase
    {

        private readonly IConfiguration _configuration;

        public IdentityServerClientController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [Route("discovery")]
        [HttpGet]
        public async Task<JsonElement> GetDiscoveryDocument()
        {
            var url = _configuration.GetValue<string>("IdentityServerSampleUrl");
            var disco = new DiscoveryDocumentResponse();
            
            try
            {
                var client = new HttpClient();
                disco = await client.GetDiscoveryDocumentAsync(url);
                
            }
            catch (Exception ex)
            {
                Console.WriteLine(disco.Error);
            }

            return disco.Json;
        }
        
        [Route("token")]
        [HttpGet]
        public async Task<JsonElement> RequestClientCredentialsToken()
        {
            var url = _configuration.GetValue<string>("IdentityServerSampleUrl");
            var clientSection = _configuration.GetSection("Clients");
            var disco = new DiscoveryDocumentResponse();
            TokenResponse tokenResponse = new TokenResponse();
            
            try
            {
                var client = new HttpClient();
                disco = await client.GetDiscoveryDocumentAsync(url);
                
                tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
                {
                    Address = disco.TokenEndpoint,

                    ClientId = clientSection.GetValue<string>("ClientId"),
                    ClientSecret = clientSection.GetValue<string>("ClientSecret"),
                    Scope = clientSection.GetValue<string>("Scope")
                });
                
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            return tokenResponse.Json;
        }
        
        [Route("identity")]
        [HttpGet]
        public async Task<JsonElement> GetIdentity()
        {
            var url = _configuration.GetValue<string>("IdentityServerSampleUrl");
            var clientSection = _configuration.GetSection("Clients");
            var apiUrl = _configuration.GetValue<string>("IdentityServerApiUrl");
            var identity = new JsonElement();
            var disco = new DiscoveryDocumentResponse();
            TokenResponse tokenResponse = new TokenResponse();
            HttpResponseMessage response = new HttpResponseMessage();
            
            try
            {
                var client = new HttpClient();
                disco = await client.GetDiscoveryDocumentAsync(url);
                
                tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
                {
                    Address = disco.TokenEndpoint,

                    ClientId = clientSection.GetValue<string>("ClientId"),
                    ClientSecret = clientSection.GetValue<string>("ClientSecret"),
                    Scope = clientSection.GetValue<string>("Scope")
                });
                
                var apiClient = new HttpClient();
                apiClient.SetBearerToken(tokenResponse.AccessToken);
                response = await apiClient.GetAsync(apiUrl + "/identity");
                
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine(response.StatusCode);
                }
                else
                {
                    identity = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            return identity;
        }
    }
}