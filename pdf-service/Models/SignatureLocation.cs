namespace pdf_service.Models
{
    public class SignatureLocation
    {
        public float X { get; set; }
        public float Y { get; set; }
        public float Width { get; set; }
        public float Height { get; set; }
        public int Page { get; set; }

        public string SignatureName { get; set; }

    }
}
