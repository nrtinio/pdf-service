using iText.IO.Image;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using pdf_service.Models;

namespace pdf_service.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class PDFServiceController : ControllerBase
    {
        private readonly ILogger<PDFServiceController> _logger;

        public PDFServiceController(ILogger<PDFServiceController> logger)
        {
            _logger = logger;
        }

        [HttpPost("SignPdf")]
        public IActionResult SignPdf(IFormFile? file, IFormFile? certificate, IFormFile? signatureImage,
            [FromForm] string? certificatePassword, [FromForm] int? scale, [FromForm] string? signatures)
        {
            if (file == null)
            {
                _logger.LogError("File missing");

                return BadRequest("File missing");
            }

            if (certificate == null)
            {
                _logger.LogError("Certificate missing");

                return BadRequest("Certificate missing");
            }

            if (signatureImage == null)
            {
                _logger.LogError("Signature Image missing");

                return BadRequest("Signature Image missing");
            }

            if (certificatePassword == null)
            {
                _logger.LogError("Certificate Password missing");

                return BadRequest("Certificate Password missing");
            }

            if (scale == null)
            {
                _logger.LogError("Scale missing");

                return BadRequest("Scale missing");
            }

            if (signatures == null)
            {
                _logger.LogError("Signature(s) missing");

                return BadRequest("Signature(s) missing");
            }

            try
            {
                SignatureLocation[]? signatureLocations = JsonConvert.DeserializeObject<SignatureLocation[]>(signatures);
             
                Stream pdfInStream = file.OpenReadStream();
                PdfReader reader = new PdfReader(pdfInStream);
                PdfDocument pdfDoc = new PdfDocument(reader);
                SignatureUtil signatureUtil = new SignatureUtil(pdfDoc);
                int existingSignatureCount = 0;

                existingSignatureCount = signatureUtil.GetSignatureNames().Count;

                foreach (SignatureLocation signatureLocation in signatureLocations)
                {
                    PdfPage page = pdfDoc.GetPage(signatureLocation.Page);

                    signatureLocation.Y = page.GetPageSize().GetHeight() - signatureLocation.Y - signatureLocation.Height;
                }

                    pdfDoc.Close();
                reader.Close();
                pdfInStream.Close();

                pdfInStream = file.OpenReadStream();
                reader = new PdfReader(pdfInStream);

                MemoryStream pdfOutStream = new MemoryStream();
                PdfWriter writer = new PdfWriter(pdfOutStream);

                PdfSigner signer = new PdfSigner(reader, pdfOutStream, new StampingProperties().UseAppendMode());
                Pkcs12Store pk12 = new Pkcs12Store(certificate.OpenReadStream(), certificatePassword.ToCharArray());
                string alias = "";

                foreach (var a in pk12.Aliases)
                {
                    alias = ((string)a);
                    if (pk12.IsKeyEntry(alias))
                        break;
                }

                ICipherParameters pk = pk12.GetKey(alias).Key;
                X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
                X509Certificate[] chain = new X509Certificate[ce.Length];
                for (int k = 0; k < ce.Length; ++k)
                {
                    chain[k] = ce[k].Certificate;
                }

                IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256);

                Stream signatureImageStream = signatureImage.OpenReadStream();
                byte[] signatureImageBytes = new byte[file.Length];
                signatureImageStream.Read(signatureImageBytes, 0, (int)file.Length);

                ImageData signatureImageData = ImageDataFactory.Create(signatureImageBytes);

                if (signatureLocations != null)
                {
                    foreach (SignatureLocation signatureLocation in signatureLocations)
                    {
                        Rectangle rect = new Rectangle(signatureLocation.X, signatureLocation.Y, signatureLocation.Width, signatureLocation.Height);
                        PdfSignatureAppearance appearance = signer.GetSignatureAppearance();

                        appearance
                            .SetSignatureGraphic(signatureImageData)
                            .SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC)
                            .SetReason("I approve of this document")
                            .SetPageRect(new Rectangle(signatureLocation.X, signatureLocation.Y, signatureLocation.Width, signatureLocation.Height))
                            .SetPageNumber(signatureLocation.Page);

                        signer.SetFieldName("Signature" + ++existingSignatureCount);

                        signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
                    }
                }
                else
                {
                    return BadRequest("No signature found");
                }

                byte[] pdfBytes = pdfOutStream.ToArray();

                return File(pdfBytes, "application/pdf", "result.pdf");
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in signing PDF");

                return StatusCode(500, e.Message);
            }
        }
    }
}