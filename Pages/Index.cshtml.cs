using System;
using Jeto.SslPinning.WebSite.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Jeto.SslPinning.WebSite.Pages
{
    public class IndexModel : PageModel
    {
        [BindProperty]
        public IFormFile UploadedFile { get; set; }
        [BindProperty]
        public string WebsiteUrl { get; set; }

        public void OnGet()
        {

        }

        public async Task OnPostAsync()
        {
            try
            {
                if (UploadedFile != null && UploadedFile.Length > 0)
                {
                    using (var ms = new MemoryStream())
                    {
                        UploadedFile.CopyTo(ms);
                        var fileBytes = ms.ToArray();
                        X509Certificate2 x509 = new X509Certificate2(fileBytes);
                        string publicKeyPinningHash = await SslPinUtility.GetPublicKeyPinningHash(x509);
                        ViewData["pin"] = publicKeyPinningHash;
                    }
                }
                else if (!string.IsNullOrEmpty(WebsiteUrl))
                {
                    ViewData["pin"] = GetServerCertificatePinAsync().Result;
                }
            }
            catch
            {
                ViewData["pin"] = "Pin not found.";
            }
        }

        public async Task<string> GetServerCertificatePinAsync()
        {
            X509Certificate2 x509 = null;

            var handler = new HttpClientHandler
            {
                UseDefaultCredentials = true,
                ServerCertificateCustomValidationCallback = (sender, cert, chain, error) =>
                {
                    x509 = new X509Certificate2(cert);
                    return true;
                }
            };

            using (HttpClient client = new HttpClient(handler))
            {
                using (await client.GetAsync(WebsiteUrl))
                {
                    return await SslPinUtility.GetPublicKeyPinningHash(x509);
                }
            }
        }
    }
}
