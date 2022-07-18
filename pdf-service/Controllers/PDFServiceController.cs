using iText.Forms;
using iText.Forms.Fields;
using iText.IO.Image;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Annot;
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

        [HttpPost("AddSignaturePlaceholder")]
        public IActionResult AddSignaturePlaceholder([FromForm]IFormFile? file, [FromForm]int? scale, [FromForm]string? signatures)
        {
            if(file == null)
            {
                return BadRequest();
            }

            if(scale == null)
            {
                return BadRequest();
            }

            if(signatures == null)
            {
                return BadRequest();
            }

            try
            {
                SignatureLocation[] signatureLocations = JsonConvert.DeserializeObject<SignatureLocation[]>(signatures);
                MemoryStream pdfOutStream = new MemoryStream();
                Stream pdfInStream = file.OpenReadStream();
                PdfReader reader = new PdfReader(pdfInStream);
                PdfWriter writer = new PdfWriter(pdfOutStream);
                PdfDocument pdfDoc = new PdfDocument(reader, writer);
                PdfAcroForm form = PdfAcroForm.GetAcroForm(pdfDoc, true);

                if (signatureLocations != null)
                {
                    foreach (SignatureLocation signatureLocation in signatureLocations)
                    {
                        PdfFormField signatureField = PdfFormField.CreateSignature(pdfDoc, new Rectangle(signatureLocation.X,
                            signatureLocation.Y, signatureLocation.Width, signatureLocation.Height));

                        signatureField.SetFieldName(signatureLocation.SignatureName)
                        .SetPage(signatureLocation.Page + 1)
                        .SetFieldFlags(PdfAnnotation.PRINT);

                        form.AddField(signatureField);
                    }
                } else
                {
                    return BadRequest();
                }

                pdfDoc.Close();

                byte[] pdfBytes = pdfOutStream.ToArray();

                return File(pdfBytes, "application/pdf", "result.pdf");
            }
            catch (Exception e)
            {
                return StatusCode(500, e.Message);
            }
        }


        [HttpPost("SignPdf")]
        public IActionResult SignPdf([FromForm] IFormFile? file, [FromForm] int? scale, [FromForm] string? signatures)
        {
            if (file == null)
            {
                return BadRequest("File missing");
            }

            if (scale == null)
            {
                return BadRequest("Scale missing");
            }

            if (signatures == null)
            {
                return BadRequest("Signature missing");
            }

            try
            {
                SignatureLocation[] signatureLocations = JsonConvert.DeserializeObject<SignatureLocation[]>(signatures);
                MemoryStream pdfOutStream = new MemoryStream();
                Stream pdfInStream = file.OpenReadStream();
                PdfReader reader = new PdfReader(pdfInStream);
                PdfWriter writer = new PdfWriter(pdfOutStream);

                PdfSigner signer = new PdfSigner(reader, pdfOutStream, new StampingProperties().UseAppendMode());
                Pkcs12Store pk12 = new Pkcs12Store(new FileStream("D:\\Downloads\\nikko_tinio_signing_cert.p12", FileMode.Open, FileAccess.Read), "TIniosign08@^".ToCharArray());
                string alias = null;

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
                ImageData signatureImage = ImageDataFactory.Create("D:\\Downloads\\sample_sig.png");

                if (signatureLocations != null)
                {
                    foreach (SignatureLocation signatureLocation in signatureLocations)
                    {
                        Rectangle rect = new Rectangle(signatureLocation.X, signatureLocation.Y, signatureLocation.Width, signatureLocation.Height);
                        PdfSignatureAppearance appearance = signer.GetSignatureAppearance();

                        appearance
                            .SetSignatureGraphic(signatureImage)
                            .SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC)
                            .SetReason("I approve of this document")
                            .SetPageRect(new Rectangle(signatureLocation.X, signatureLocation.Y, signatureLocation.Width, signatureLocation.Height))
                            .SetPageNumber(signatureLocation.Page + 1);

                        signer.SetFieldName(signatureLocation.SignatureName);

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