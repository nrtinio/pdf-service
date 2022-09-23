using System.Collections;

namespace pdf_service.Models
{
    public class SignatureComparer : IComparer
    {
        public int Compare(object x, object y)
        {
            return (new CaseInsensitiveComparer()).Compare((x as SignatureLocation).Page, (y as SignatureLocation).Page);
        }
    }
}
