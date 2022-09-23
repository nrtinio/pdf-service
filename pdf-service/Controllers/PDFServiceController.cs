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
                Array.Sort(signatureLocations, new SignatureComparer());
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

                if (signatureLocations != null)
                {

                    pdfOutStream = Sign(file.OpenReadStream(), pks, chain, signatureLocations, signatureImageData);
                }
                else
                {
                    return BadRequest("No signature found");
                }

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

        private MemoryStream Sign(Stream fileStream, IExternalSignature pks, X509Certificate[] chain, SignatureLocation[] signatureLocations,
            ImageData signatureImageData)
        {
            PdfReader reader = new PdfReader(fileStream);
            MemoryStream pdfOutStream = new MemoryStream();
            PdfSigner signer = new PdfSigner(reader, pdfOutStream, new StampingProperties().UseAppendMode());
            PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
            PdfDocument pdf = signer.GetDocument();
            SignatureUtil signatureUtil = new SignatureUtil(pdf);
            int existingSignatureCount = signatureUtil.GetSignatureNames().Count;

            for (int i = signatureLocations.Length - 1; i >= 0; i--)
            {
                PdfPage page = pdf.GetPage(signatureLocations[i].Page);
                signatureLocations[i].Y = page.GetPageSize().GetHeight() - signatureLocations[i].Y - signatureLocations[i].Height;

                appearance
                    .SetSignatureGraphic(signatureImageData)
                    .SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION)
                    .SetLocation("Manila")
                    .SetReason("I approve of this document")
                    .SetPageRect(new Rectangle(signatureLocations[i].X, signatureLocations[i].Y,
                    signatureLocations[i].Width, signatureLocations[i].Height))
                    .SetPageNumber(signatureLocations[i].Page);

                if (i == 0)
                {
                    signer.SetFieldName("Signature" + existingSignatureCount + 1);

                    signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
                } else
                {
                    PdfCanvas pdfCanvas = new PdfCanvas(page);
                    Rectangle rect = new Rectangle(signatureLocations[i].X, signatureLocations[i].Y, signatureLocations[i].Width, signatureLocations[i].Height);
                    pdfCanvas.Rectangle(rect);

                    Rectangle sigRect = new Rectangle(signatureLocations[i].X, signatureLocations[i].Y, signatureLocations[i].Width / 2, signatureLocations[i].Height);
                    Canvas sigCanvas = new Canvas(pdfCanvas, sigRect);
                    Image sigImage = new Image(signatureImageData);
                    sigImage.SetAutoScale(true);
                    Div imageDiv = new Div();
                    imageDiv.SetHeight(sigRect.GetHeight());
                    imageDiv.SetWidth(sigRect.GetWidth());
                    imageDiv.SetVerticalAlignment(iText.Layout.Properties.VerticalAlignment.MIDDLE);
                    imageDiv.SetHorizontalAlignment(iText.Layout.Properties.HorizontalAlignment.CENTER);
                    imageDiv.Add(sigImage);
                    sigCanvas.Add(imageDiv);

                    Rectangle textRect = new Rectangle(signatureLocations[i].X + sigRect.GetWidth(), signatureLocations[i].Y, signatureLocations[i].Width / 2, signatureLocations[i].Height);
                    Canvas textCanvas = new Canvas(pdfCanvas, textRect);
                    PdfFont font = PdfFontFactory.CreateFont();
                    Paragraph paragraph = new Paragraph("Digitally signed by Nikko\nDate: mm/dd/yyyy\nReason: I do not approve of this document\nLocation: At Home")
                        .SetFont(font).SetMargin(0).SetMultipliedLeading(0.9f).SetFontSize(10);
                    Div textDiv = new Div();
                    textDiv.SetHeight(textRect.GetHeight());
                    textDiv.SetWidth(textRect.GetWidth());
                    textDiv.SetVerticalAlignment(iText.Layout.Properties.VerticalAlignment.MIDDLE);
                    textDiv.SetHorizontalAlignment(iText.Layout.Properties.HorizontalAlignment.CENTER);
                    textDiv.Add(paragraph);
                    textCanvas.Add(textDiv);
                }
            }

            return pdfOutStream;
        }
    }
}