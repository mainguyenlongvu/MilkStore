namespace MilkStore.ModelViews
{
    public class PaymentRequest
    {
        public string InvoiceCode { get; set; }
        public double TotalAmount { get; set; }
        public string OrderType { get; set; }
    }
}