using iText.IO.Image;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Kernel.Pdf.Canvas;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using pdf_service.Models;
using iText.Layout.Element;
using iText.Layout;
using iText.Kernel.Pdf.Xobject;
using iText.Kernel.Font;

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
            [FromForm] string? certificatePassword, [FromForm] string? signatures)
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

            try
            {
                MemoryStream pdfOutStream = new MemoryStream();
                Stream signatureImageStream = signatureImage.OpenReadStream();
                byte[] signatureImageBytes = new byte[file.Length];
                signatureImageStream.Read(signatureImageBytes, 0, (int)file.Length);
                ImageData signatureImageData = ImageDataFactory.Create(signatureImageBytes);
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

                pdfOutStream = Sign(file.OpenReadStream(), pks, chain, signatureImageData);

                byte[] pdfBytes = pdfOutStream.ToArray();

                pdfOutStream.Close();

                return File(pdfBytes, "application/pdf", "result.pdf");
            }
            catch(IOException e)
            {
                if(e.Message == "PKCS12 key store MAC invalid - wrong password or corrupted file.")
                {
                    _logger.LogError(e, "Error in signing PDF due to Incorrect Password or Corrupted File");

                    return StatusCode(401);

                } else
                {
                    throw e;
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error in signing PDF due to system error");

                return StatusCode(500, e.Message);
            }
        }

        private MemoryStream Sign(Stream fileStream, IExternalSignature pks, X509Certificate[] chain,
            ImageData signatureImageData)
        {
            PdfReader reader = new PdfReader(fileStream);
            MemoryStream pdfOutStream = new MemoryStream();
            PdfSigner signer = new PdfSigner(reader, pdfOutStream, new StampingProperties().UseAppendMode());
            PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
            PdfDocument pdf = signer.GetDocument();

            PdfPage page = pdf.GetPage(1);

            appearance
                    .SetSignatureGraphic(signatureImageData)
                    .SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION)
                    .SetLocationCaption("")
                    .SetReasonCaption("")
                    //.SetLocation("Manila")
                    //.SetReason("I approve of this document")
                    .SetPageRect(new Rectangle(page.GetPageSize().GetWidth() - 200, 0,
                    200, 100))
                    .SetPageNumber(1);

            signer.SetFieldName("Signature0");

            signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

            return pdfOutStream;
        }
    }
}